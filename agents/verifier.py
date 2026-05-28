"""Verifier sub-agent — vaccine-mode re-attack validator.

Runs after the defender writes ``defense_brief.json``. For each finding,
the verifier attempts to reproduce the exploit using the new pure-Python
HTTPClient and the same scanners the exploit agent had, records
``{id, original_severity, reproducible: bool, notes}`` per finding, and
writes the aggregate to ``verification_results.json`` in the workspace.

If a defense has been applied and the finding no longer reproduces, the
defender's proposed patch is considered validated. If it still
reproduces, the patch is marked insufficient — operators know the gap
is real before closing the engagement.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from network_pipeline.agents._common import build_agent
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.schemas import C2Tier, OpsecLevel
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph


def _run(coro):
    """Sync helper to run an async coroutine from a sync @tool wrapper.

    Schedules onto the engagement loop via run_on_engagement_loop so the
    HTTPClient (bound to that loop) actually receives the request.
    """
    from network_pipeline.tools.runtime import run_on_engagement_loop
    return run_on_engagement_loop(coro)


def create_verifier_agent(
    *, workspace: Path, config: EngagementConfig, runner=None,
    kg: KnowledgeGraph, findings: FindingsLog, factory: OllamaLLMFactory,
    iteration: int = 0, engagement_id: str = "",
    opsec_level: OpsecLevel | None = None, c2_tier: C2Tier | None = None,
    http_client: Any = None, dns_client: Any = None,
):
    import json

    from langchain_core.tools import tool  # type: ignore[import-not-found]

    results_path = workspace / "verification_results.json"
    brief_path = workspace / "defense_brief.json"

    @tool
    def read_defense_brief() -> str:
        """Return defender's defense_brief.json contents (empty if missing)."""
        if not brief_path.exists():
            return "(no defense_brief.json yet)"
        try:
            return brief_path.read_text(encoding="utf-8")[:4096]
        except OSError as e:
            return f"[read failed] {e}"

    @tool
    def http_replay(url: str, method: str = "GET",
                    headers: dict | None = None, body: str = "",
                    objective_id: str = "") -> str:
        """Replay a single HTTP request to verify reproducibility.

        Returns ``status:<code> len:<bytes>`` or an error string. Use this
        to re-issue the exact request captured in a finding's evidence.
        """
        if http_client is None:
            return "[http_replay] http_client not configured"
        method = (method or "GET").upper()
        try:
            if method == "GET":
                resp = _run(http_client.get(
                    url, headers=headers or {}, scanner_tool="verifier",
                ))
            elif method == "POST":
                resp = _run(http_client.post(
                    url, headers=headers or {}, content=body or None,
                    scanner_tool="verifier",
                ))
            else:
                resp = _run(http_client.request(
                    method, url, headers=headers or {}, content=body or None,
                    scanner_tool="verifier",
                ))
        except Exception as e:
            return f"[http_replay] error: {e!r}"
        if resp is None:
            return "[http_replay] request blocked or failed"
        try:
            blen = len(resp.content or b"")
        except Exception:
            blen = 0
        return f"status:{resp.status_code} len:{blen}"

    @tool
    def write_verification_results(results: list[dict]) -> str:
        """Persist per-finding verification outcomes AND escalate confidence.

        results: list of {id, original_severity, reproducible: bool, notes}.

        Phase-J 2026 fix: when a finding is successfully reproduced
        (``reproducible: True``), this tool now mutates the corresponding
        entry in ``findings.jsonl`` so its ``confidence`` becomes
        ``verified`` and ``"http_replay"`` is appended to
        ``verified_methods``. Without this escalation, the ``Finding``
        schema validator silently drops every CRITICAL/HIGH item from
        ``report.json`` (the validator requires ``confidence=verified``
        for those severities).
        """
        payload = {"results": results}
        results_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        reproducible_ids = {
            str(r.get("id")) for r in results if r.get("reproducible")
        }
        reproducible = len(reproducible_ids)
        # Phase-7: blocked = mitigated. ``reproducible=False`` AND the
        # finding appears in the defender's brief means the proposed
        # mitigation held against re-attack — emit a VERIFIED edge
        # from the DefenseAction to the Finding.
        blocked_ids = {
            str(r.get("id")) for r in results
            if r.get("id") and not r.get("reproducible")
        }

        escalated = 0
        if reproducible_ids:
            try:
                escalated = _escalate_confidence(
                    workspace, reproducible_ids,
                )
            except Exception as e:  # pragma: no cover - defensive
                return (
                    f"verification written: {results_path} "
                    f"({len(results)} findings, {reproducible} reproducible, "
                    f"escalation FAILED: {e!r})"
                )

        verified_edges = 0
        if blocked_ids:
            try:
                verified_edges = _emit_verified_edges(
                    workspace, kg, blocked_ids, results,
                )
            except Exception:
                # Graph annotation is metadata — never block the
                # verification result.
                pass

        return (
            f"verification written: {results_path} "
            f"({len(results)} findings, {reproducible} reproducible, "
            f"{escalated} escalated to confidence=verified, "
            f"{verified_edges} VERIFIED edges emitted)"
        )

    return build_agent(
        "verifier",
        workspace=workspace, config=config, runner=runner,
        kg=kg, findings=findings, factory=factory,
        extra_tools=[read_defense_brief, http_replay, write_verification_results],
        iteration=iteration, engagement_id=engagement_id,
        opsec_level=opsec_level, c2_tier=c2_tier,
        http_client=http_client, dns_client=dns_client,
    )


def _escalate_confidence(
    workspace: Path, reproducible_ids: set[str],
) -> int:
    """Rewrite ``findings.jsonl`` upgrading confidence for reproduced findings.

    Returns the count of entries actually modified. Atomic write via
    a sibling tmp file + rename so a crash mid-write doesn't truncate
    the audit log.
    """
    import json as _json

    log_path = workspace / "findings.jsonl"
    if not log_path.exists():
        return 0

    tmp_path = log_path.with_suffix(".jsonl.tmp")
    escalated = 0
    with log_path.open("r", encoding="utf-8") as src, \
            tmp_path.open("w", encoding="utf-8") as dst:
        for line in src:
            line = line.rstrip("\n")
            if not line.strip():
                dst.write(line + "\n")
                continue
            # findings.jsonl lines may have a trailing "\t__sig__=..." HMAC
            # suffix. Preserve it (we replay it after mutation).
            sig = ""
            payload = line
            if "\t__sig__=" in line:
                payload, sig = line.split("\t__sig__=", 1)
                sig = "\t__sig__=" + sig
            try:
                obj = _json.loads(payload)
            except _json.JSONDecodeError:
                dst.write(line + "\n")
                continue
            if not isinstance(obj, dict):
                dst.write(line + "\n")
                continue
            fid = str(obj.get("id") or "")
            if fid in reproducible_ids:
                # Upgrade confidence
                if str(obj.get("confidence") or "").lower() != "verified":
                    obj["confidence"] = "verified"
                    methods = list(obj.get("verified_methods") or [])
                    if "http_replay" not in methods:
                        methods.append("http_replay")
                    obj["verified_methods"] = methods
                    escalated += 1
            dst.write(_json.dumps(obj) + sig + "\n")

    # Atomic replace; HMAC sig — when present — was preserved verbatim,
    # so the chain still verifies for unmodified rows. Rows we mutated
    # WILL fail HMAC verify (correctly: the audit log has changed). The
    # evidence_chain.verify_evidence() report will surface those rows
    # under bad_signatures so operators see the verifier's escalations.
    tmp_path.replace(log_path)
    return escalated


def _emit_verified_edges(
    workspace: Path,
    kg: KnowledgeGraph,
    blocked_ids: set[str],
    results: list[dict],
) -> int:
    """Phase-7: for every blocked finding, find the DefenseAction(s) that
    listed it in ``finding_ids`` and emit a VERIFIED edge.

    Reads the on-disk ``defense_brief.json`` to map finding_id →
    DefenseAction id. Each recommendation entry's ``id`` (or its index)
    becomes the action_id matching ``kg.add_defense_action(...)``.
    """
    import json as _json

    brief_path = workspace / "defense_brief.json"
    if not brief_path.exists():
        return 0
    try:
        brief = _json.loads(brief_path.read_text(encoding="utf-8"))
    except (OSError, _json.JSONDecodeError):
        return 0

    by_id = {str(r.get("id")): r for r in results if r.get("id")}
    edges = 0
    for idx, rec in enumerate(brief.get("recommendations") or [], start=1):
        if not isinstance(rec, dict):
            continue
        action_id = str(rec.get("id") or f"REC-{idx:03d}")
        for fid in rec.get("finding_ids") or []:
            fid = str(fid)
            if fid not in blocked_ids:
                continue
            note = str(by_id.get(fid, {}).get("notes", ""))
            try:
                kg.add_verification(
                    action_id=action_id,
                    finding_id=fid,
                    verified=True,
                    notes=note,
                )
                edges += 1
            except Exception:
                # Single-edge failure should not abort the loop.
                continue
    return edges
