"""Scanner sub-agent — port + HTTP probing (pure Python)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from network_pipeline.agents._common import build_agent, _wrap_str_truncate
from network_pipeline.core.logging import get_logger

log = get_logger("agents.scanner")
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.schemas import C2Tier, ObjectivePhase, OpsecLevel
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph

# ── Plugin registry opt-in ──────────────────────────────────────────
AGENT_ROLE = "scanner"
SUPPORTED_PHASES = (ObjectivePhase.SCAN,)


def create_scanner_agent(
    *,
    workspace: Path,
    config: EngagementConfig,
    runner: Any = None,
    kg: KnowledgeGraph,
    findings: FindingsLog,
    factory: OllamaLLMFactory,
    iteration: int = 0,
    engagement_id: str = "",
    opsec_level: OpsecLevel | None = None,
    c2_tier: C2Tier | None = None,
    http_client: Any | None = None,
    dns_client: Any | None = None,
):
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    from network_pipeline.scanners.port_scan import PortScanner
    from network_pipeline.scanners.http_probe import HTTPProbeScanner
    from network_pipeline.scanners.content_discovery import ContentScanner
    from network_pipeline.scanners.tls_audit import TLSAuditScanner

    # Bug-fix: PortScanner() with no scope used to deny EVERY target
    # because TCPConnectProbe defaults to ScopeGuard() with domains=().
    # Pull the scope from the engagement's HTTPClient (which was built
    # from RoE in_scope) so port scans see the same allowlist as HTTP.
    _scope_for_tcp = None
    if http_client is not None:
        _scope_for_tcp = getattr(http_client, "_scope", None)
    port_scanner = PortScanner(scope=_scope_for_tcp)
    http_probe = HTTPProbeScanner(http_client) if http_client else None
    content_scanner = ContentScanner(http_client) if http_client else None
    tls_scanner = TLSAuditScanner(http_client) if http_client else None

    def _run(coro: Any) -> str:
        from network_pipeline.tools.runtime import run_on_engagement_loop
        from network_pipeline.agents._common import persist_scan_findings
        try:
            result = run_on_engagement_loop(coro)
            try:
                n = persist_scan_findings(
                    result, findings, agent_role="scanner", iteration=iteration,
                )
                if n:
                    log.info("scanner: auto-persisted %d findings", n)
            except Exception as e:
                log.debug("scanner: persist failed: %r", e)
            return _wrap_str_truncate(
                result.to_agent_text()
                if hasattr(result, "to_agent_text") else str(result)
            )
        except Exception as e:
            return f"[scanner error] {e!r}"

    @tool
    def port_scan(target: str, ports: str = "common") -> str:
        """TCP connect-scan on a target. ports: 'common', '1-1024', or '80,443,8080'."""
        return _run(port_scanner.scan(target, ports=ports))

    @tool
    def http_probe(urls: list[str]) -> str:
        """Probe a list of URLs for status, title, tech stack, and missing security headers."""
        if http_probe is None:
            return "[http_probe] http_client not configured"
        return _run(http_probe.probe(urls))

    @tool
    def content_discovery(target_url: str, wordlist: str = "common") -> str:
        """Discover content/directories. wordlist: 'common', 'raft-small', 'dirbuster-medium'."""
        if content_scanner is None:
            return "[content_discovery] http_client not configured"
        return _run(content_scanner.discover(target_url, wordlist=wordlist))

    @tool
    def tls_audit(target: str) -> str:
        """TLS handshake + certificate audit (protocol version, expiry, key strength, SANs)."""
        if tls_scanner is None:
            return "[tls_audit] http_client not configured"
        return _run(tls_scanner.audit(target))

    return build_agent(
        "scanner",
        workspace=workspace, config=config, runner=runner,
        kg=kg, findings=findings, factory=factory,
        extra_tools=[port_scan, http_probe, content_discovery, tls_audit],
        iteration=iteration, engagement_id=engagement_id,
        opsec_level=opsec_level, c2_tier=c2_tier,
        http_client=http_client, dns_client=dns_client,
    )
