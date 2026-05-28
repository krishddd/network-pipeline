"""Recon sub-agent — passive + active reconnaissance (pure Python)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from network_pipeline.agents._common import build_agent, _wrap_str_truncate
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import C2Tier, ObjectivePhase, OpsecLevel
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph

log = get_logger("agents.recon")

# ── Plugin registry opt-in ──────────────────────────────────────────
AGENT_ROLE = "recon"
SUPPORTED_PHASES = (ObjectivePhase.RECON,)


def create_recon_agent(
    *,
    workspace: Path,
    config: EngagementConfig,
    runner: Any = None,  # kept for backward compat; not used
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

    from network_pipeline.scanners.dns_scan import DNSScanner
    from network_pipeline.scanners.whois_lookup import WhoisScanner
    from network_pipeline.scanners.subdomains import SubdomainScanner
    from network_pipeline.scanners.js_endpoints import JSEndpointScanner
    from network_pipeline.scanners.parameter_mining import ParamScanner
    from network_pipeline.scanners.web_crawler import WebCrawlerScanner

    opsec_str = opsec_level.value if opsec_level else "standard"

    dns_scanner = DNSScanner(dns_client) if dns_client else None
    whois_scanner = WhoisScanner(http_client) if http_client else None
    sub_scanner = SubdomainScanner(http_client, dns_client) if (http_client and dns_client) else None
    js_scanner = JSEndpointScanner(http_client) if http_client else None
    param_scanner = ParamScanner(http_client, opsec_level=opsec_str) if http_client else None
    crawler = WebCrawlerScanner(http_client) if http_client else None

    def _run(coro: Any) -> str:
        from network_pipeline.tools.runtime import run_on_engagement_loop
        from network_pipeline.agents._common import persist_scan_findings
        try:
            result = run_on_engagement_loop(coro)
            # Auto-persist structured ScanFinding -> Finding so we don't
            # depend on the LLM remembering to call record_finding.
            try:
                n = persist_scan_findings(
                    result, findings, agent_role="recon", iteration=iteration,
                )
                if n:
                    log.info("recon: auto-persisted %d findings", n)
            except Exception as e:
                log.debug("recon: persist failed: %r", e)
            return _wrap_str_truncate(
                result.to_agent_text()
                if hasattr(result, "to_agent_text") else str(result)
            )
        except Exception as e:
            return f"[scanner error] {e!r}"

    @tool
    def dns_scan(domain: str, record_types: str = "A,AAAA,TXT,MX,NS") -> str:
        """Resolve DNS records for a domain. record_types: comma-separated list."""
        if dns_scanner is None:
            return "[dns_scan] dns_client not configured"
        types = tuple(t.strip().upper() for t in record_types.split(","))
        return _run(dns_scanner.resolve(domain, types=types))

    @tool
    def whois_lookup(domain: str) -> str:
        """WHOIS/RDAP lookup for a domain."""
        if whois_scanner is None:
            return "[whois_lookup] http_client not configured"
        return _run(whois_scanner.lookup(domain))

    @tool
    def subdomain_enum(domain: str) -> str:
        """Enumerate subdomains via CT logs, HackerTarget, AlienVault OTX, VirusTotal."""
        if sub_scanner is None:
            return "[subdomain_enum] http_client/dns_client not configured"
        return _run(sub_scanner.enumerate(domain))

    @tool
    def js_endpoints(url: str) -> str:
        """Extract JS-embedded endpoint paths from a target URL (requires bs4)."""
        if js_scanner is None:
            return "[js_endpoints] http_client not configured"
        return _run(js_scanner.extract(url))

    @tool
    def parameter_mining(target_url: str) -> str:
        """Mine URL parameters from Wayback Machine (passive) + live brute at LOUD/STANDARD OPSEC."""
        if param_scanner is None:
            return "[parameter_mining] http_client not configured"
        return _run(param_scanner.mine(target_url))

    @tool
    def web_crawler(seed_url: str, max_depth: int = 4, max_pages: int = 200) -> str:
        """BFS-crawl the target up to ``max_depth`` levels deep, harvesting
        every link, form action, and JS-extracted URL into the KG. Use
        early in recon to populate the attack surface before parameter
        mining + sqli/xss probes."""
        if crawler is None:
            return "[web_crawler] http_client not configured"
        return _run(crawler.crawl(
            seed_url, max_depth=max_depth, max_pages=max_pages,
        ))

    # Bumblebee-port: target-side supply-chain inventory scanner.
    # Fetches any exposed package.json / requirements.txt / Gemfile.lock /
    # go.mod / composer.lock and matches resolved (eco, pkg, version)
    # tuples against the bundled threat-intel catalogs.
    from network_pipeline.scanners.supply_chain_inventory import (
        SupplyChainInventoryScanner,
    )
    supply_scanner = SupplyChainInventoryScanner(http_client) if http_client else None

    @tool
    def supply_chain_inventory(target_url: str) -> str:
        """Fetch exposed dependency manifests and check against threat-intel
        catalogs (Shai-Hulud, typosquats, credential stealers, etc.).

        Use early in recon — exposed manifests are a high-signal find
        and the catalog match auto-verifies CRITICAL/HIGH findings.
        """
        if supply_scanner is None:
            return "[supply_chain_inventory] http_client not configured"
        return _run(supply_scanner.run(target_url))

    return build_agent(
        "recon",
        workspace=workspace, config=config, runner=runner,
        kg=kg, findings=findings, factory=factory,
        extra_tools=[
            dns_scan, whois_lookup, subdomain_enum,
            js_endpoints, parameter_mining, web_crawler,
            supply_chain_inventory,
        ],
        iteration=iteration, engagement_id=engagement_id,
        opsec_level=opsec_level, c2_tier=c2_tier,
        http_client=http_client, dns_client=dns_client,
    )
