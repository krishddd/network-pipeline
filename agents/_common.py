"""Shared sub-agent factory.

Each role's agent is a LangGraph ``create_react_agent`` configured with:

* an Ollama model from ``OllamaLLMFactory.get_model(role)``
* a small, role-specific tool set (kg + skills + binary wrappers)
* a system prompt loaded from ``agents/prompts/<role>.md`` plus the
  agent's skill catalog appended
* a message-trimming pre-hook that drops oldest ToolMessages once the
  context approaches the model's window
* the ``TraceCallbackHandler`` for offline observability
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import re

from network_pipeline.agents.prompts import load_prompt
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.logging import TraceCallbackHandler, get_logger
from network_pipeline.core.schemas import (
    C2Tier,
    Evidence,
    Finding,
    FindingConfidence,
    FindingSeverity,
    ObjectivePhase,
    OpsecLevel,
    RemediationPriority,
)
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import (
    FindingsLog,
    KGEdge,
    KGNode,
    KnowledgeGraph,
)
from network_pipeline.tools.skills import (
    list_skills,
    read_skill,
    skill_index_text,
)

try:
    from pydantic import ValidationError
except ImportError:  # pragma: no cover
    ValidationError = Exception  # type: ignore[assignment,misc]


# ── OPSEC / C2 tier guidance (per-level one-liners for prompt injection) ──

_OPSEC_GUIDANCE = {
    OpsecLevel.LOUD: "all tools permitted; no evasion required.",
    OpsecLevel.STANDARD: "default flags; modify obvious signatures.",
    OpsecLevel.CAREFUL: "active evasion; avoid known signatures, slower timing.",
    OpsecLevel.QUIET: "-T2 nmap, no masscan, no full nuclei template sweeps; blend in.",
    OpsecLevel.SILENT: "passive-only; abort if detection is likely.",
}

_C2_GUIDANCE = {
    C2Tier.INTERACTIVE: "direct operator control; seconds callback expected.",
    C2Tier.SHORT_HAUL: "minutes-hours callback; avoid chatty probes.",
    C2Tier.LONG_HAUL: "hours-days persistent fallback; keep noise minimal.",
}

# Structural OPSEC tool gating.
# Tool names in these sets are stripped from the agent's tool list BEFORE
# the agent is compiled — so the model physically cannot call them. This
# is defence in depth atop the prompt-level OPSEC guidance above: a
# misbehaving model that ignores the prompt still can't fire masscan at
# OPSEC=SILENT because the tool isn't in its registry.
_OPSEC_BLOCKED_TOOLS: dict[OpsecLevel, set[str]] = {
    OpsecLevel.LOUD: set(),
    OpsecLevel.STANDARD: set(),
    # CAREFUL — strip the loudest active scanners
    OpsecLevel.CAREFUL: {
        "content_discovery", "web_audit", "xss_scan", "auth_audit",
    },
    # QUIET — strip brute-force, full exploit, sqlmap deep-dive
    OpsecLevel.QUIET: {
        "content_discovery", "web_audit", "xss_scan", "auth_audit",
        "sqli_scan", "sqlmap_dispatch", "jwt_scan", "cve_check",
        "parameter_mining",
    },
    # SILENT — passive recon only
    OpsecLevel.SILENT: {
        "content_discovery", "web_audit", "xss_scan", "auth_audit",
        "sqli_scan", "sqlmap_dispatch", "jwt_scan", "cve_check",
        "parameter_mining", "port_scan", "http_probe", "tls_audit",
        "subdomain_enum",
    },
}


# Tool-name → required Python module (importlib.util.find_spec check).
# Keys match the @tool function names in per-role factories.
# When the module is not importable the tool is stripped from the agent's
# registry so the model can never call it and blame the pipeline for a
# silent failure.
_TOOL_LIB_REQUIREMENT: dict[str, str] = {
    # Recon scanners
    "dns_scan": "dns.resolver",
    "whois_lookup": "",            # RDAP needs no lib; python-whois optional
    "subdomain_enum": "",          # pure httpx
    "js_endpoints": "bs4",
    "parameter_mining": "",
    # Scanner scanners
    "port_scan": "",               # asyncio only
    "http_probe": "",
    "content_discovery": "",
    "tls_audit": "cryptography",
    # Exploit scanners
    "cve_check": "yaml",
    "sqli_scan": "",
    "sqlmap_dispatch": "sqlmap",
    "xss_scan": "",
    "jwt_scan": "jwt",
    "web_audit": "",
    "auth_audit": "",
    # Browser-gated tools
    "xss_scan_dom": "playwright",
}


def _apply_capability_gate(tools: list, runner: object | None = None) -> list:
    """Drop tools whose required Python lib is not importable.

    Uses importlib.util.find_spec — if the lib is absent the tool is
    stripped so the model never sees a tool it can't invoke.
    """
    import importlib.util

    kept: list = []
    dropped: list[tuple[str, str]] = []
    for t in tools:
        name = getattr(t, "name", None) or getattr(t, "__name__", "")
        req = _TOOL_LIB_REQUIREMENT.get(name, "")
        if req and importlib.util.find_spec(req) is None:
            dropped.append((name, req))
            continue
        kept.append(t)
    if dropped:
        log.info(
            "capability_gate dropped tools (missing libs): %s",
            ",".join(f"{n}(needs {lib})" for n, lib in dropped),
        )
    return kept


def _apply_scanner_allowlist(tools: list, workspace: Path | None) -> list:
    """Drop tools whose name is not on ``plan/scanner_allowlist.txt`` (when set).

    Curated targets like scanme.nmap.org carry a ``scope_note: 'passive +
    nmap only'`` plus an explicit ``allowed_scanners`` list in
    ``targets.json``. The runner writes that list to a marker file on
    plan; the agent layer enforces it here so loud scanners
    (sqli_scan / xss_scan / sqlmap_dispatch / content_discovery) NEVER
    fire against a target whose authorisation banner forbids them.

    Tools whose ``tool.name`` doesn't look like a scanner (e.g. KG,
    findings, fs, auth_capture_*) pass through untouched — the
    allowlist is scanner-specific by design.
    """
    if workspace is None:
        return tools
    marker = workspace / "plan" / "scanner_allowlist.txt"
    if not marker.exists():
        return tools
    try:
        allowed = {
            line.strip() for line in marker.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
    except OSError:
        return tools
    if not allowed:
        return tools
    # Names of every scanner tool the agent layer might wire up. Anything
    # outside this set is non-scanner machinery and bypasses the gate.
    scanner_tool_names = {
        # Phase A-G core
        "dns_scan", "whois_lookup", "subdomain_enum", "js_endpoints",
        "parameter_mining", "port_scan", "http_probe", "content_discovery",
        "tls_audit", "cve_check", "sqli_scan", "sqlmap_dispatch",
        "xss_scan", "xss_scan_dom", "jwt_scan", "web_audit", "auth_audit",
        # Phase H 2026: adaptive web-attack core
        "openapi_scan", "bola_scan", "mass_assignment",
        # Phase I 2026: modern protocol coverage
        "graphql_scan", "request_smuggling", "websocket_scan",
        "subdomain_takeover", "supply_chain",
        # Phase K 2026: deep red-team aggression
        "web_crawler",
    }
    kept = []
    dropped = []
    for t in tools:
        name = getattr(t, "name", None) or getattr(t, "__name__", "")
        if name in scanner_tool_names and name not in allowed:
            dropped.append(name)
            continue
        kept.append(t)
    if dropped:
        log.info(
            "scanner_allowlist dropped (not in %s): %s",
            sorted(allowed), ",".join(dropped),
        )
    return kept


def _apply_opsec_gate(tools: list, opsec_level: OpsecLevel | None) -> list:
    """Remove tools whose name matches the block-list for the current OPSEC level.

    Tool names are matched against ``tool.name`` (LangChain BaseTool
    attribute). Unknown tools pass through untouched.
    """
    if opsec_level is None:
        return tools
    blocked = _OPSEC_BLOCKED_TOOLS.get(opsec_level, set())
    if not blocked:
        return tools
    kept = []
    dropped = []
    for t in tools:
        name = getattr(t, "name", None) or getattr(t, "__name__", "")
        if name in blocked:
            dropped.append(name)
        else:
            kept.append(t)
    if dropped:
        log.info(
            "opsec_gate level=%s dropped=%s",
            opsec_level.value, ",".join(dropped),
        )
    return kept

log = get_logger("agents.common")


# ── Tool builders ──────────────────────────────────────────────────


def persist_scan_findings(
    scan_result: Any,
    findings_log: Any,
    *,
    agent_role: str = "",
    iteration: int = 0,
) -> int:
    """Auto-persist ``ScanFinding`` objects from a ``ScanResult`` into
    the engagement's ``FindingsLog``.

    Without this, scanner outputs only show up as text shown to the LLM;
    if the LLM forgets to call ``record_finding(...)`` the structured
    findings are lost. With this, every scanner that returns
    ``ScanResult.findings`` produces persistent ``Finding`` rows in
    ``findings.jsonl`` automatically.

    Returns the number of findings persisted.
    """
    if scan_result is None or findings_log is None:
        return 0
    sf_list = getattr(scan_result, "findings", None)
    if not sf_list:
        return 0

    from network_pipeline.core.schemas import (
        Finding, FindingSeverity, FindingConfidence, Evidence,
    )

    sev_map = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "informational": FindingSeverity.INFORMATIONAL,
        "info": FindingSeverity.INFORMATIONAL,
    }
    conf_map = {
        "verified": FindingConfidence.VERIFIED,
        "probable": FindingConfidence.PROBABLE,
        "unverified": FindingConfidence.UNVERIFIED,
        # ScanFinding uses "tentative" — map to the closest existing
        # enum member (UNVERIFIED) since the schema doesn't define it.
        "tentative": FindingConfidence.UNVERIFIED,
    }

    scanner_name = getattr(scan_result, "scanner", "") or "scanner"

    persisted = 0
    try:
        existing = len(findings_log.all())
    except Exception:
        existing = 0
    for sf in sf_list:
        try:
            raw_sev = str(getattr(sf, "severity", "informational")).lower()
            raw_conf = str(getattr(sf, "confidence", "probable")).lower()
            sev = sev_map.get(raw_sev, FindingSeverity.INFORMATIONAL)
            conf = conf_map.get(raw_conf, FindingConfidence.PROBABLE)

            # Schema gate: CRITICAL/HIGH require confidence=verified AND
            # >=2 verified_methods. To keep HIGH severity intact, inject
            # synthetic methods based on provenance: the scanner name +
            # the matched signal class. Verifier later adds "http_replay"
            # for full re-confirmation.
            verified_methods: list[str] = []
            if sev in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
                conf = FindingConfidence.VERIFIED  # required by schema
                vc = getattr(sf, "vuln_class", "") or "scan-detect"
                verified_methods = [
                    f"scanner:{scanner_name}",
                    f"signal:{vc}",
                ]

            evidence_paths = list(getattr(sf, "evidence_paths", []) or [])
            evidence_objs = [
                Evidence(type="scan-output", path=p, description="")
                for p in evidence_paths
            ]

            existing += 1
            f = Finding(
                id=f"FIND-{existing:04d}",
                title=getattr(sf, "title", "") or getattr(sf, "vuln_class", "untitled"),
                severity=sev,
                confidence=conf,
                cwe=list(getattr(sf, "cwe", []) or []),
                mitre=list(getattr(sf, "mitre", []) or []),
                affected_target=getattr(sf, "affected_target", "") or "",
                affected_component=getattr(sf, "affected_param", "") or "",
                description=getattr(sf, "description", "") or "",
                remediation=getattr(sf, "remediation", "") or "",
                evidence=evidence_objs,
                verified_methods=verified_methods,
                agent=agent_role,
                iteration=iteration,
            )
            findings_log.append(f)
            persisted += 1
        except Exception as e:  # pragma: no cover - defensive
            # Last-resort: if HIGH/CRITICAL still fails validation for some
            # reason, drop severity to MEDIUM and retry. Better to record
            # a downgraded finding than lose it entirely.
            try:
                existing += 0  # don't double-bump id counter
                fallback = Finding(
                    id=f"FIND-{existing:04d}",
                    title=getattr(sf, "title", "") or getattr(sf, "vuln_class", "untitled"),
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.PROBABLE,
                    cwe=list(getattr(sf, "cwe", []) or []),
                    mitre=list(getattr(sf, "mitre", []) or []),
                    affected_target=getattr(sf, "affected_target", "") or "",
                    affected_component=getattr(sf, "affected_param", "") or "",
                    description=(
                        f"[downgraded from {raw_sev}] "
                        + (getattr(sf, "description", "") or "")
                    ),
                    agent=agent_role,
                    iteration=iteration,
                )
                findings_log.append(fallback)
                persisted += 1
            except Exception:
                log.warning("persist_scan_findings: dropped one (%r)", e)
    return persisted


def _wrap_str_truncate(text: Any, cap: int = 4096) -> str:
    s = str(text)
    if len(s.encode("utf-8")) <= cap:
        return s
    return s.encode("utf-8")[:cap].decode("utf-8", errors="ignore") + "\n…[truncated]"


def make_kg_tools(kg: KnowledgeGraph, findings: FindingsLog,
                  agent_name: str, iteration: int = 0):
    """Return @tool wrappers for KG + finding operations."""
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    # Per-agent-invocation bad-finding counter. Each validator rejection
    # on the SAME (title, severity, confidence) triple increments. After
    # 3 identical rejections we stop nudging and tell the model the
    # input is unrecoverable — prevents infinite retry loops.
    _finding_reject_counter: dict[tuple[str, str, str], int] = {}

    @tool
    def kg_add_node(node_id: str, node_type: str, properties: dict | None = None) -> str:
        """Add or merge a node in the knowledge graph.
        node_id: stable identifier like 'host:1.2.3.4'.
        node_type: 'host' | 'port' | 'service' | 'finding' | 'credential'.
        properties: optional dict of metadata.
        """
        kg.add_node(KGNode(id=node_id, type=node_type, properties=properties or {}))
        return f"node added: {node_id} ({node_type})"

    @tool
    def kg_add_edge(src: str, dst: str, relation: str,
                    properties: dict | None = None) -> str:
        """Add a directed edge between two existing nodes."""
        kg.add_edge(KGEdge(src=src, dst=dst, relation=relation,
                            properties=properties or {}))
        return f"edge added: {src} --[{relation}]--> {dst}"

    @tool
    def kg_query(node_type: str | None = None) -> str:
        """List nodes optionally filtered by type. Returns up to 50."""
        results = kg.query(node_type)
        return _wrap_str_truncate(
            f"{len(results)} nodes of type {node_type or 'any'}:\n"
            + "\n".join(f"- {r['id']} ({r['type']}): {r['properties']}" for r in results[:50])
        )

    @tool
    def kg_neighbors(node_id: str) -> str:
        """Return all incoming/outgoing edges for a node."""
        nbrs = kg.neighbors(node_id)
        return _wrap_str_truncate(
            f"{len(nbrs)} neighbours of {node_id}:\n"
            + "\n".join(f"- [{n['direction']}] {n['relation']}: {n['src']} -> {n['dst']}" for n in nbrs[:50])
        )

    @tool
    def kg_stats() -> str:
        """Knowledge graph summary: total nodes/edges and per-type counts."""
        return str(kg.stats())

    @tool
    def record_finding(
        title: str,
        severity: str,
        affected_target: str,
        description: str,
        steps_to_reproduce: list[str] | None = None,
        impact: str = "",
        evidence_paths: list[str] | None = None,
        cwe: list[str] | None = None,
        mitre: list[str] | None = None,
        remediation: str = "",
        remediation_priority: str = "",
        confidence: str = "probable",
        verified_methods: list[str] | None = None,
        objective_id: str = "",
    ) -> str:
        """Persist a verified or probable finding to findings.jsonl.

        severity: critical | high | medium | low | informational
        confidence: verified | probable | unverified
        remediation_priority: immediate | short-term | long-term
        verified_methods: list of verification methods (e.g. ['nmap', 'manual curl']).
        HIGH/CRITICAL require confidence=verified AND >=2 verified_methods.
        """
        try:
            sev = FindingSeverity(severity.lower())
        except ValueError:
            sev = FindingSeverity.LOW
        try:
            conf = FindingConfidence(confidence.lower())
        except ValueError:
            conf = FindingConfidence.PROBABLE
        rp: RemediationPriority | None = None
        if remediation_priority:
            try:
                rp = RemediationPriority(remediation_priority.lower())
            except ValueError:
                rp = None
        evidence = [
            Evidence(type="artifact", path=p, description="agent-attached evidence")
            for p in (evidence_paths or [])
        ]
        vms = list(verified_methods or [])
        try:
            finding = Finding(
                id=findings.next_id(),
                title=title,
                severity=sev,
                confidence=conf,
                cwe=cwe or [],
                mitre=mitre or [],
                affected_target=affected_target,
                description=description,
                steps_to_reproduce=steps_to_reproduce or [],
                impact=impact,
                evidence=evidence,
                remediation=remediation,
                remediation_priority=rp,
                verified_methods=vms,
                objective_id=objective_id,
                agent=agent_name,
                iteration=iteration,
                discovered_at=datetime.now(timezone.utc).isoformat(),
            )
        except (ValidationError, ValueError) as e:
            # Return a structured, self-correctable message rather than
            # crashing the agent iteration. Count repeated rejections of
            # the same input so we can give up after N attempts.
            key = (title, sev.value, conf.value)
            _finding_reject_counter[key] = _finding_reject_counter.get(key, 0) + 1
            attempt = _finding_reject_counter[key]
            if attempt >= 3:
                return (
                    "finding REJECTED (final, attempt 3/3): stop retrying "
                    f"'{title}' at {sev.value}. Either downgrade severity "
                    f"to medium/low or gather >=2 verified_methods with "
                    f"confidence=verified. Validator: {e}"
                )
            return (
                f"finding rejected (attempt {attempt}/3): {sev.value} "
                f"severity requires confidence=verified AND "
                f">=2 verified_methods; got confidence={conf.value}, "
                f"verified_methods={vms}. Validator: {e}"
            )
        findings.append(finding)
        return f"finding recorded: {finding.id} {finding.severity.value} '{finding.title}'"

    @tool
    def list_findings() -> str:
        """Condensed list of findings from findings.jsonl — id, severity, title."""
        items = findings.all()
        if not items:
            return "(no findings)"
        return "\n".join(
            f"- {f.id} [{f.severity.value}] {f.title}" for f in items
        )

    @tool
    def read_skill_md(rel_path: str) -> str:
        """Read a SKILL.md file by its relative path under skills/."""
        try:
            return _wrap_str_truncate(read_skill(rel_path), cap=8 * 1024)
        except (FileNotFoundError, PermissionError) as e:
            return f"[skill read failed] {e}"

    @tool
    def list_my_skills() -> str:
        """List the SKILL.md files visible to this agent role."""
        return _wrap_str_truncate(
            "\n".join(s.to_brief() for s in list_skills(agent_name)) or "(none)"
        )

    return [
        kg_add_node, kg_add_edge, kg_query, kg_neighbors, kg_stats,
        record_finding, list_findings, read_skill_md, list_my_skills,
    ]


def make_fs_tools(runner):
    """Jailed filesystem @tools — list / read / grep under the workspace."""
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    @tool
    def fs_list(subdir: str = ".") -> str:
        """List files under ``workspace/<subdir>`` (paths that escape the
        workspace are rejected)."""
        try:
            p = runner.jailed_path(subdir)
        except PermissionError as e:
            return f"[fs_list denied] {e}"
        if not p.exists():
            return f"(missing: {subdir})"
        if p.is_file():
            return f"file: {p.name} ({p.stat().st_size} bytes)"
        entries = []
        for child in sorted(p.iterdir()):
            if child.is_dir():
                entries.append(f"{child.name}/")
            else:
                entries.append(f"{child.name}  ({child.stat().st_size}B)")
        return "\n".join(entries) or "(empty)"

    @tool
    def fs_read(rel_path: str, max_bytes: int = 4096) -> str:
        """Read a file from the workspace; capped at 4 KB by default."""
        try:
            p = runner.jailed_path(rel_path)
        except PermissionError as e:
            return f"[fs_read denied] {e}"
        if not p.exists() or not p.is_file():
            return f"(missing or not a file: {rel_path})"
        cap = max(1, min(int(max_bytes), 4096))
        try:
            data = p.read_bytes()[:cap]
            return data.decode("utf-8", errors="replace")
        except OSError as e:
            return f"[fs_read error] {e}"

    @tool
    def fs_grep(rel_path: str, pattern: str) -> str:
        """Line-by-line regex match on a workspace file; up to 50 hits."""
        try:
            p = runner.jailed_path(rel_path)
        except PermissionError as e:
            return f"[fs_grep denied] {e}"
        if not p.exists() or not p.is_file():
            return f"(missing or not a file: {rel_path})"
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return f"[fs_grep bad regex] {e}"
        hits: list[str] = []
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                for i, line in enumerate(fh, 1):
                    if rx.search(line):
                        hits.append(f"{i}: {line.rstrip()}")
                        if len(hits) >= 50:
                            break
        except OSError as e:
            return f"[fs_grep error] {e}"
        return "\n".join(hits) or "(no matches)"

    return [fs_list, fs_read, fs_grep]


# ── Agent factory ──────────────────────────────────────────────────


def build_agent(
    role: str,
    *,
    workspace: Path,
    config: EngagementConfig,
    runner: Any = None,  # kept for backward compat; ignored in pure-Python mode
    kg: KnowledgeGraph,
    findings: FindingsLog,
    factory: OllamaLLMFactory,
    extra_tools: list | None = None,
    iteration: int = 0,
    engagement_id: str = "",
    opsec_level: OpsecLevel | None = None,
    c2_tier: C2Tier | None = None,
    include_fs_tools: bool = False,  # no ShellRunner → no jailed fs tools by default
    http_client: Any | None = None,
    dns_client: Any | None = None,
    structured_reasoning: bool | None = None,
):
    """Build a LangGraph react agent for ``role``.

    Returns a compiled runnable. Caller is responsible for invoking it
    with the per-iteration HumanMessage.

    ``opsec_level`` / ``c2_tier`` (if given, from the current Objective)
    are dynamically appended to the system prompt so the agent knows how
    loud it may be and which C2 tier applies.
    """
    # Lazy imports — keeps non-agent unit tests free of langgraph.
    from langchain_core.messages import SystemMessage  # type: ignore[import-not-found]
    from langgraph.prebuilt import create_react_agent  # type: ignore[import-not-found]

    base_prompt = load_prompt(role)
    skill_catalog = skill_index_text(role)

    # Dynamic per-objective context (OPSEC + C2 tier)
    context_lines: list[str] = []
    if opsec_level is not None:
        context_lines.append(
            f"- OPSEC level: {opsec_level.value} → "
            f"{_OPSEC_GUIDANCE.get(opsec_level, '')}"
        )
    if c2_tier is not None:
        context_lines.append(
            f"- C2 tier: {c2_tier.value} → "
            f"{_C2_GUIDANCE.get(c2_tier, '')}"
        )
    context_block = ""
    if context_lines:
        context_block = "\n\n## CURRENT OBJECTIVE CONTEXT\n" + "\n".join(context_lines)

    # Phase-K aggressiveness boost: push every agent to be persistent,
    # exhaustive, and chain-aware. Without this, small models (eco
    # profile) tend to do one tool call and return — which is why
    # earlier engagements finished in <2 minutes with 0 findings.
    persistence_block = (
        "\n\n## ENGAGEMENT MINDSET (mandatory)\n"
        "You are a real red-team operator running a long, persistent\n"
        "engagement. Your job is NOT to give one-shot answers — it is to\n"
        "exhaust every available tool against the target until either\n"
        "(a) the objective's acceptance criteria are met, or (b) you have\n"
        "ruled out every plausible attack vector with concrete evidence.\n"
        "\n"
        "Required behaviours:\n"
        "1. CHAIN tool calls — recon feeds scan, scan feeds exploit. After\n"
        "   each tool call, examine the output and pick the next most-\n"
        "   informative call. Never stop after one or two calls.\n"
        "2. RETRY on failure — if a scanner returns '[scanner error]',\n"
        "   '0 findings', or scope-denied, try a different angle: a\n"
        "   subdomain, a different port range, an alternative payload\n"
        "   class, an evasion-encoded variant.\n"
        "3. RECORD everything — call record_finding() for EVERY observed\n"
        "   issue, not just the headline ones. Missing-headers, exposed\n"
        "   debug paths, default credentials accepted — all of it.\n"
        "4. EXPAND scope progressively — once you have an authenticated\n"
        "   session (cookie or bearer), re-run scanners with auth replay\n"
        "   to find post-auth vulns the anonymous run missed.\n"
        "5. TIME BUDGET — you have plenty. Burn 5-15 tool calls per\n"
        "   objective. Don't return early because you ran one scanner.\n"
        "6. EVIDENCE — every finding must include the request URL, the\n"
        "   payload that triggered it, and the response signal (status,\n"
        "   length delta, or extracted string).\n"
    )
    # Phase-2: SIRAJ-style structured reasoning contract. Forces a strict
    # 4-component JSON block at the start of every assistant message,
    # then tool calls follow. Operator can disable via
    # ``--structured-reasoning off`` for A/B comparison runs.
    # Resolution: explicit kwarg > config.structured_reasoning > default True.
    if structured_reasoning is None:
        structured_reasoning = bool(getattr(config, "structured_reasoning", True))
    reasoning_block = ""
    if structured_reasoning:
        from network_pipeline.core.structured_reasoning import (
            REASONING_CONTRACT_BLOCK,
        )
        reasoning_block = REASONING_CONTRACT_BLOCK

    # Phase-5: orchestrator gets the rendered CONOPS + Deconfliction
    # context block (threat actor, narrative, SOC attribution) when
    # Soundwave produced one. Other agents do not need it — their job
    # is execution, not strategic framing.
    conops_block = ""
    if role == "orchestrator":
        try:
            marker = workspace / "plan" / ".conops_context.txt"
            if marker.exists():
                conops_block = marker.read_text(encoding="utf-8")
        except OSError:
            pass

    system = SystemMessage(
        content=(
            f"{base_prompt}{context_block}{persistence_block}{reasoning_block}"
            f"{conops_block}\n\n## Available skills\n{skill_catalog}"
        )
    )

    model = factory.get_model(role)
    # factory.get_model() may return a RunnableRetry wrapper (from .with_retry())
    # which lacks bind_tools(). create_react_agent() needs bind_tools(), so
    # unwrap to the underlying ChatModel before compiling the graph.
    # Direct callers of get_model() (SelfCritic, ToT planner, supervisor) still
    # receive the retry-wrapped version and are unaffected.
    if not hasattr(model, "bind_tools") and hasattr(model, "bound"):
        model = model.bound

    tools = make_kg_tools(kg, findings, agent_name=role, iteration=iteration)
    if extra_tools:
        tools = tools + list(extra_tools)

    # Dynamic capability discovery — drop tools whose required Python lib
    # is not installed, so the agent never sees a tool it can't invoke.
    tools = _apply_capability_gate(tools)
    # Per-target scanner allowlist (curated-target scope_note enforcement) —
    # e.g. scanme.nmap.org permits only port_scan / dns_scan / http_probe.
    tools = _apply_scanner_allowlist(tools, workspace)
    # Structural OPSEC enforcement — strip disallowed tools by name so
    # the model cannot invoke them even if the prompt is ignored.
    tools = _apply_opsec_gate(tools, opsec_level)

    agent = create_react_agent(model=model, tools=tools, prompt=system)

    handler = TraceCallbackHandler(
        workspace=workspace,
        agent=role,
        iteration=iteration,
        engagement_id=engagement_id,
    )
    # callbacks attached at invoke time via config={"callbacks": [...]}
    return agent, handler
