"""Async engagement runner for the FastAPI server.

Spawns ``EngagementLoop.run`` on a background asyncio task per
engagement and tracks state in-process. Per-target folder structure
+ engagement.meta.json reuse the existing ``core.auto`` helpers — the
HTTP layer is just a thin wrapper around the same lifecycle the
``cli auto`` subcommand drives.

Concurrency cap: at most ``MAX_PARALLEL_ENGAGEMENTS`` engagements may
run simultaneously. Excess requests are rejected with HTTP 429 — the
shared local Ollama doesn't usefully scale past 2-3 concurrent runs
even with the inference lock.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from network_pipeline.core.auto import (
    finalise_meta, make_engagement_dir, slugify_target, update_stage,
    write_initial_meta,
)
from network_pipeline.core.logging import get_logger

log = get_logger("api.runner")


# Hard cap — protects the shared Ollama instance from VRAM thrash.
MAX_PARALLEL_ENGAGEMENTS = 2


# Module-level registry: engagement_id → state dict.
# Each state dict mirrors what ``engagement.meta.json`` holds, plus a
# ``status`` field that can be: pending | running | complete | failed.
_ENGAGEMENTS: dict[str, dict[str, Any]] = {}
# Futures returned by run_coroutine_threadsafe — concurrent.futures.Future,
# NOT asyncio.Future. add_done_callback signature is the same.
_TASKS: dict[str, "concurrent.futures.Future[Any]"] = {}
# Created lazily on first submit on the main loop. Bug-fix:
# ``asyncio.Semaphore`` constructed at module import time binds to
# whatever loop happens to be current, which under FastAPI's
# threadpool routes is None — raising at acquire time.
_RUN_LOCK: asyncio.Semaphore | None = None
_MAIN_LOOP: asyncio.AbstractEventLoop | None = None


def bind_main_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Capture the FastAPI/uvicorn main loop so sync route handlers can
    submit coroutines safely from the threadpool.

    Called from ``server.py`` ``@app.on_event("startup")``.
    """
    global _MAIN_LOOP, _RUN_LOCK
    _MAIN_LOOP = loop
    # Build the semaphore on the bound loop so acquire works.
    _RUN_LOCK = asyncio.Semaphore(MAX_PARALLEL_ENGAGEMENTS)
    log.info("api.runner bound main loop %r", loop)


def list_engagements() -> list[dict[str, Any]]:
    """Snapshot of every engagement we've started this process lifetime."""
    return [
        {**v, "engagement_id": k}
        for k, v in sorted(
            _ENGAGEMENTS.items(),
            key=lambda kv: kv[1].get("started_at", ""),
            reverse=True,
        )
    ]


def get_engagement(engagement_id: str) -> dict[str, Any] | None:
    return _ENGAGEMENTS.get(engagement_id)


def make_engagement_id(target: str) -> str:
    """Stable ID = ``<target-slug>__<UTC-compact-timestamp>``."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    return f"{slugify_target(target)}__{stamp}"


def workspace_for(engagement_id: str, root: Path) -> Path:
    """Per-target/per-timestamp workspace under ``root``."""
    slug, _, stamp = engagement_id.partition("__")
    return root / slug / stamp


# ── Job spec ──────────────────────────────────────────────────────────


class EngagementJob:
    """Self-contained spec the runner executes asynchronously."""

    def __init__(
        self,
        *,
        engagement_id: str,
        target: str,
        in_scope: list[str],
        out_of_scope: list[str],
        engagement_name: str,
        ollama_base_url: str,
        profile: str,
        max_iterations: int,
        iteration_timeout: int,
        playbook: str,
        c2_profile: str,
        auth_cookie: str,
        rate_caps: dict[str, float],
        seed: int | None,
        token_budget: int | None,
        wall_budget: int | None,
        hmac_engagement_id: str,
        report_root: Path,
        rag_index: str = "",
        allowed_scanners: list[str] | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.target = target
        self.in_scope = in_scope
        self.out_of_scope = out_of_scope
        self.engagement_name = engagement_name
        self.ollama_base_url = ollama_base_url
        self.profile = profile
        self.max_iterations = max_iterations
        self.iteration_timeout = iteration_timeout
        self.playbook = playbook
        self.c2_profile = c2_profile
        self.auth_cookie = auth_cookie
        self.rate_caps = rate_caps
        self.seed = seed
        self.token_budget = token_budget
        self.wall_budget = wall_budget
        self.hmac_engagement_id = hmac_engagement_id
        self.report_root = report_root
        self.rag_index = rag_index
        self.allowed_scanners = list(allowed_scanners or [])


def submit_job(job: EngagementJob) -> dict[str, Any]:
    """Register + spawn an engagement task.

    Returns the registry entry. Caller checks ``status`` to know
    whether the job is queued, running, or already failed at submit.

    Bug-fix: this is called from FastAPI sync route handlers running
    in anyio's threadpool, where there is no current asyncio loop.
    We capture the main loop on app startup via ``bind_main_loop``
    and submit via ``asyncio.run_coroutine_threadsafe`` which is
    thread-safe.
    """
    if _MAIN_LOOP is None or not _MAIN_LOOP.is_running():
        return {
            "engagement_id": job.engagement_id,
            "status": "rejected",
            "reason": "server main loop not bound (call bind_main_loop on startup)",
            "started_at": "",
        }
    if len(_TASKS) >= MAX_PARALLEL_ENGAGEMENTS:
        return {
            "engagement_id": job.engagement_id,
            "status": "rejected",
            "reason": (
                f"max parallel engagements ({MAX_PARALLEL_ENGAGEMENTS}) "
                "already running"
            ),
            "started_at": "",
        }
    workspace = workspace_for(job.engagement_id, job.report_root)
    workspace.mkdir(parents=True, exist_ok=True)
    entry: dict[str, Any] = {
        "engagement_id": job.engagement_id,
        "target": job.target,
        "workspace": str(workspace),
        "status": "pending",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "ended_at": "",
        "summary": {},
    }
    _ENGAGEMENTS[job.engagement_id] = entry

    # Schedule on the captured main loop. ``run_coroutine_threadsafe``
    # returns a concurrent.futures.Future — different from asyncio.Future
    # but compatible enough for our add_done_callback usage.
    future = asyncio.run_coroutine_threadsafe(
        _run_engagement(job, workspace), _MAIN_LOOP,
    )
    _TASKS[job.engagement_id] = future
    future.add_done_callback(
        lambda _f, eid=job.engagement_id: _TASKS.pop(eid, None)
    )
    return entry


# ── Background task ──────────────────────────────────────────────────


async def _run_engagement(job: EngagementJob, workspace: Path) -> None:
    entry = _ENGAGEMENTS[job.engagement_id]
    # Defensive: if bind_main_loop wasn't called (shouldn't happen in
    # serve mode), build a per-engagement semaphore so we still
    # serialise this single run cleanly.
    sem = _RUN_LOCK if _RUN_LOCK is not None else asyncio.Semaphore(1)
    async with sem:
        try:
            entry["status"] = "running"
            await _do_run(job, workspace, entry)
            entry["status"] = "complete"
        except Exception as e:
            log.exception("engagement %s failed", job.engagement_id)
            entry["status"] = "failed"
            entry["error"] = repr(e)
        finally:
            entry["ended_at"] = datetime.now(timezone.utc).isoformat()


async def _do_run(
    job: EngagementJob, workspace: Path, entry: dict[str, Any],
) -> None:
    """The actual lifecycle — mirrors ``cli auto``."""
    from network_pipeline.agents.orchestrator import load_opplan, save_opplan
    from network_pipeline.core.engagement import EngagementConfig
    from network_pipeline.core.engagement_loop import EngagementLoop
    from network_pipeline.core.schemas import (
        BudgetState, RoE, ScopeEntry, SeedState,
    )
    from network_pipeline.core.seed import seed_all

    # 1. Initial metadata
    flags = {
        "max_iterations": job.max_iterations,
        "iteration_timeout": job.iteration_timeout,
        "playbook": job.playbook,
        "c2_profile": job.c2_profile,
        "auth_cookie_present": bool(job.auth_cookie),
        "rate_caps": job.rate_caps,
        "seed": job.seed,
        "token_budget": job.token_budget,
        "wall_budget": job.wall_budget,
        "hmac_engagement_id": job.hmac_engagement_id,
    }
    write_initial_meta(
        workspace=workspace, target=job.target,
        in_scope=job.in_scope, out_of_scope=job.out_of_scope,
        engagement_name=job.engagement_name,
        ollama_base_url=job.ollama_base_url,
        profile=job.profile, flags=flags,
    )

    # 2. PLAN — write RoE + seeded OPPLAN + markers
    update_stage(workspace, "plan", "running")
    try:
        scope_entries = [_scope_from_target(job.target)]
        for s in job.in_scope:
            if ":" in s:
                kind, value = s.split(":", 1)
                scope_entries.append(ScopeEntry(target=value, type=kind))
        out_entries = []
        for s in job.out_of_scope:
            if ":" in s:
                kind, value = s.split(":", 1)
                out_entries.append(ScopeEntry(target=value, type=kind))
        roe = RoE(
            engagement_name=job.engagement_name or job.engagement_id,
            in_scope=scope_entries,
            out_of_scope=out_entries,
        )
        (workspace / "plan").mkdir(parents=True, exist_ok=True)
        (workspace / "plan" / "roe.json").write_text(
            roe.model_dump_json(indent=2), encoding="utf-8",
        )
        # Seed OPPLAN via the existing CLI helper (lazy import to avoid
        # importing click at module-load time).
        from network_pipeline.cli import _seed_opplan
        _seed_opplan(workspace, job.target)

        # Markers
        plan_dir = workspace / "plan"
        if job.playbook:
            from network_pipeline.core.playbook import load_playbook
            load_playbook(job.playbook)
            (plan_dir / "playbook.txt").write_text(
                job.playbook + "\n", encoding="utf-8",
            )
        if job.c2_profile:
            from network_pipeline.core.c2_profile import load_callback_profile
            load_callback_profile(job.c2_profile)
            (plan_dir / "c2_profile.txt").write_text(
                job.c2_profile + "\n", encoding="utf-8",
            )
        if job.hmac_engagement_id:
            (plan_dir / "hmac_key.txt").write_text(
                job.hmac_engagement_id + "\n", encoding="utf-8",
            )
        if job.rag_index:
            # Phase-4 cross-engagement RAG. The engagement loop reads
            # this marker, builds CrossEngagementRAG against the path,
            # and at COMPLETE absorbs every finding + KG summary so
            # later engagements against similar targets get prior-
            # context recall via the orchestrator's rag_recall tool.
            (plan_dir / "rag_index.txt").write_text(
                job.rag_index + "\n", encoding="utf-8",
            )
        # Per-target scanner allowlist (e.g. scanme.nmap.org → passive +
        # nmap-style only). When set, scanners not on the list are
        # OPSEC-blocked at the agent capability gate.
        if job.allowed_scanners:
            (plan_dir / "scanner_allowlist.txt").write_text(
                "\n".join(job.allowed_scanners) + "\n", encoding="utf-8",
            )
        # Phase-3 defaults from the API: critic ON, no ToT, no adaptive.
        (plan_dir / "tot.flag").write_text("", encoding="utf-8")
        (plan_dir / "nocritic.flag").write_text("", encoding="utf-8")
        (plan_dir / "adaptive.flag").write_text("", encoding="utf-8")
        (plan_dir / "parallel.txt").write_text("1\n", encoding="utf-8")

        # Auth cookie
        if job.auth_cookie:
            from network_pipeline.tools.web.auth_replay import AuthStore
            AuthStore(workspace).update_from_cookie_header(
                job.target, job.auth_cookie,
            )
        update_stage(workspace, "plan", "ok")
    except Exception as e:
        update_stage(workspace, "plan", "failed", error=repr(e))
        raise

    # 3. Seed budgets / rate caps
    if job.seed is not None:
        seed_all(job.seed)
    if job.rate_caps:
        from network_pipeline.core.rate_limit import GLOBAL_RATE_LIMITS
        for binary, rps in job.rate_caps.items():
            GLOBAL_RATE_LIMITS.set_rate(binary, float(rps))
    # Treat 0 / None as "unlimited" for token_budget and wall_budget so
    # the Swagger-default body ({"token_budget": 0, "wall_budget": 0})
    # doesn't accidentally cap the engagement to zero. Real caps must
    # be > 0.
    token_cap = (
        int(job.token_budget) if job.token_budget and job.token_budget > 0 else None
    )
    wall_cap = (
        int(job.wall_budget) if job.wall_budget and job.wall_budget > 0 else None
    )
    if job.seed is not None or token_cap is not None or wall_cap is not None:
        opplan = load_opplan(workspace)
        if opplan is not None:
            if job.seed is not None:
                opplan.seed = SeedState(seed=int(job.seed), seeded=True)
            opplan.budget = BudgetState(
                total_tokens=token_cap,
                total_seconds=wall_cap,
            )
            save_opplan(workspace, opplan)

    # 4. RUN
    update_stage(workspace, "run", "running")
    try:
        config = EngagementConfig(
            target=job.target, workspace=workspace,
            max_iterations=job.max_iterations,
            iteration_max_seconds=job.iteration_timeout,
            ollama_base_url=job.ollama_base_url,
            profile=job.profile,
        )
        state = await EngagementLoop(config).run()
        entry["summary"] = state.summary
        update_stage(workspace, "run", "ok", summary=state.summary)
    except Exception as e:
        update_stage(workspace, "run", "failed", error=repr(e))
        raise

    # 5. VERIFY (only when HMAC was set)
    verify_report: dict[str, Any] | None = None
    if job.hmac_engagement_id:
        update_stage(workspace, "verify", "running")
        try:
            from network_pipeline.core.evidence_chain import (
                default_key_path, load_or_create_key, verify_evidence,
            )
            key_path = default_key_path(job.hmac_engagement_id)
            key = load_or_create_key(key_path) if key_path.exists() else None
            rep = verify_evidence(workspace, key)
            verify_report = {
                "ok": rep.ok,
                "expected_root": rep.expected_root,
                "actual_root": rep.actual_root,
                "leaf_count": rep.leaf_count,
                "unsigned_findings": rep.unsigned_findings,
                "bad_signatures": rep.bad_signatures,
                "missing_sidecars": rep.missing_sidecars,
                "bad_sidecar_hashes": rep.bad_sidecar_hashes,
                "notes": rep.notes,
            }
            update_stage(
                workspace, "verify", "ok" if rep.ok else "mismatch",
                **verify_report,
            )
        except Exception as e:
            update_stage(workspace, "verify", "failed", error=repr(e))
    else:
        update_stage(workspace, "verify", "skipped")

    # 6. REPORT
    update_stage(workspace, "report", "running")
    report_paths: dict[str, str] = {}
    try:
        from network_pipeline.tools.kg import FindingsLog
        from network_pipeline.tools.report import (
            enrich_with_epss,
            write_cyclonedx_vex,
            write_json_report,
            write_sarif_report,
        )
        all_findings = FindingsLog(workspace / "findings.jsonl").all()
        # 2026: EPSS prioritisation. Annotates findings in-place with
        # exploit-in-the-wild probability before they hit the report.
        try:
            enrich_with_epss(all_findings, workspace=workspace)
        except Exception as e:  # noqa: BLE001
            log.debug("epss enrichment skipped: %r", e)
        # Pipeline-wide dedup: scanners can independently flag the same vuln
        # (e.g. http_probe + web_audit both raising missing-hsts on `/`).
        # Collapse by (vuln_class, normalized_endpoint, param) and keep the
        # highest-severity / verified-confidence representative; merge
        # evidence_paths so no audit data is lost.
        findings = _dedup_findings(all_findings)
        if len(findings) != len(all_findings):
            log.info(
                "report dedup: %d → %d findings (%d duplicates merged)",
                len(all_findings), len(findings),
                len(all_findings) - len(findings),
            )
        for fmt, fn in (
            ("json", write_json_report),
            ("sarif", write_sarif_report),
            ("cdx.json", write_cyclonedx_vex),  # CycloneDX-VEX 1.5
        ):
            out_path = workspace / f"report.{fmt}"
            fn(findings, out_path, workspace=workspace)
            report_paths[fmt] = str(out_path)
        update_stage(workspace, "report", "ok",
                     formats=list(report_paths.keys()),
                     finding_count=len(findings),
                     duplicates_merged=len(all_findings) - len(findings))
    except Exception as e:
        update_stage(workspace, "report", "failed", error=repr(e))

    # 7. Finalise meta
    finalise_meta(
        workspace=workspace,
        state_summary=entry.get("summary", {}),
        verify_report=verify_report,
        report_paths=report_paths,
    )


_SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
_CONF_ORDER = ["unverified", "tentative", "probable", "verified"]


def _dedup_findings(findings: list) -> list:
    """Pipeline-wide finding dedup.

    Multiple scanners can independently raise the same vuln on the same
    endpoint — for instance ``http_probe`` and ``web_audit`` both flag
    ``missing-hsts`` on ``/``. Collapse those into a single representative
    with the highest severity + confidence, merging evidence so no audit
    data is lost. Key: ``(title-class, normalized_endpoint, component)``.

    Falls back to identity (no dedup) on any per-finding exception so a
    single malformed item can't sink the whole report stage.
    """
    from network_pipeline.scanners._common import normalize_endpoint

    by_key: dict[tuple, Any] = {}
    order: list[tuple] = []
    for f in findings:
        try:
            target = getattr(f, "affected_target", "") or ""
            component = getattr(f, "affected_component", "") or ""
            title = (getattr(f, "title", "") or "").strip().lower()
            # Use the first 4 tokens of the title as a coarse vuln-class
            # signature — scanners write titles like "Missing HSTS on /…"
            # or "SQL injection in id parameter".
            class_sig = " ".join(title.split()[:4])
            key = (class_sig, normalize_endpoint(target), component)
        except Exception:
            order.append(("__bad__", id(f), 0))
            by_key[("__bad__", id(f), 0)] = f
            continue
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = f
            order.append(key)
            continue
        # Choose the better representative
        winner = _better(existing, f)
        loser = f if winner is existing else existing
        # Merge evidence onto winner
        try:
            existing_ev = list(getattr(winner, "evidence", []) or [])
            loser_ev = list(getattr(loser, "evidence", []) or [])
            for ev in loser_ev:
                if ev not in existing_ev:
                    existing_ev.append(ev)
            try:
                winner.evidence = existing_ev  # pydantic mutate
            except Exception:
                pass
            # Carry MITRE / CWE union forward
            for attr in ("cwe", "mitre", "verified_methods"):
                a = list(getattr(winner, attr, []) or [])
                b = list(getattr(loser, attr, []) or [])
                merged = list(dict.fromkeys(a + b))
                try:
                    setattr(winner, attr, merged)
                except Exception:
                    pass
        except Exception:
            pass
        by_key[key] = winner
    return [by_key[k] for k in order]


def _better(a, b):
    """Pick the higher-severity / higher-confidence finding of two."""
    def _sev(x) -> int:
        v = getattr(getattr(x, "severity", None), "value", None) or getattr(x, "severity", "")
        return _SEV_ORDER.index(str(v).lower()) if str(v).lower() in _SEV_ORDER else -1
    def _conf(x) -> int:
        v = getattr(getattr(x, "confidence", None), "value", None) or getattr(x, "confidence", "")
        return _CONF_ORDER.index(str(v).lower()) if str(v).lower() in _CONF_ORDER else -1
    if _sev(a) != _sev(b):
        return a if _sev(a) > _sev(b) else b
    if _conf(a) != _conf(b):
        return a if _conf(a) > _conf(b) else b
    return a  # arbitrary tie-break, stable


def _scope_from_target(target: str):
    from network_pipeline.core.schemas import ScopeEntry
    import ipaddress

    try:
        ipaddress.ip_network(target, strict=False)
        return ScopeEntry(target=target, type="cidr")
    except ValueError:
        pass
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return ScopeEntry(target=host, type="domain")


__all__ = [
    "EngagementJob",
    "MAX_PARALLEL_ENGAGEMENTS",
    "bind_main_loop",
    "get_engagement",
    "list_engagements",
    "make_engagement_id",
    "submit_job",
    "workspace_for",
]
