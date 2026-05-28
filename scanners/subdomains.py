"""Subdomain enumeration — replaces subfinder.

Queries four free passive sources:
  1. crt.sh (Certificate Transparency logs)
  2. HackerTarget host search API
  3. AlienVault OTX passive DNS
  4. VirusTotal (gated on VIRUSTOTAL_API_KEY env var)

No Go binary required.
"""

from __future__ import annotations

import asyncio
import os
import re
from typing import TYPE_CHECKING

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient, DNSClient

_SUBDOMAIN_RE = re.compile(r"[\w\-]+(?:\.[\w\-]+)+")


@register_scanner
class SubdomainScanner(Scanner):
    name = "subdomain_enum"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "passive"

    def __init__(
        self,
        http_client: "HTTPClient",
        dns_client: "DNSClient",
    ) -> None:
        self._http = http_client
        self._dns = dns_client

    async def enumerate(self, domain: str) -> ScanResult:
        """Enumerate subdomains via multiple passive sources."""
        found: set[str] = set()

        sources_used: list[str] = []
        results = await asyncio.gather(
            self._crt_sh(domain),
            self._hackertarget(domain),
            self._alienvault(domain),
            self._virustotal(domain),
            return_exceptions=True,
        )

        for i, (source_name, result) in enumerate(zip(
            ["crt.sh", "hackertarget", "alienvault", "virustotal"],
            results,
        )):
            if isinstance(result, Exception):
                continue
            if result:
                subs, used = result
                found.update(subs)
                if used:
                    sources_used.append(source_name)

        # Remove the apex domain itself
        found.discard(domain)
        # Filter to only valid subdomains of the target domain
        filtered = {s for s in found if s.endswith("." + domain) or s == domain}

        # Resolve A records to confirm liveness
        live: list[dict] = []
        resolve_tasks = [self._resolve_sub(sub) for sub in sorted(filtered)]
        resolve_results = await asyncio.gather(*resolve_tasks, return_exceptions=True)
        for sub, res in zip(sorted(filtered), resolve_results):
            if isinstance(res, Exception):
                continue
            ips = res if isinstance(res, list) else []
            live.append({"subdomain": sub, "ips": ips, "live": bool(ips)})

        return ScanResult(
            scanner=self.name,
            target=domain,
            success=True,
            data={
                "subdomains": live,
                "total_found": len(filtered),
                "live_count": sum(1 for s in live if s["live"]),
                "sources": sources_used,
            },
            raw_text=_format_subdomains(domain, live),
        )

    async def _resolve_sub(self, sub: str) -> list[str]:
        return await self._dns.resolve(sub, "A")

    # ── Sources ───────────────────────────────────────────────────────────────

    async def _crt_sh(self, domain: str) -> tuple[set[str], bool]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = await self._http.get(url, scanner_tool=self.name, check_scope=False)
        if resp is None or resp.status_code != 200:
            return set(), False
        try:
            data = resp.json()
            subs: set[str] = set()
            for entry in data:
                for raw in [entry.get("name_value", ""), entry.get("common_name", "")]:
                    for name in raw.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain):
                            subs.add(name.lower())
            return subs, True
        except Exception:
            return set(), False

    async def _hackertarget(self, domain: str) -> tuple[set[str], bool]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = await self._http.get(url, scanner_tool=self.name, check_scope=False)
        if resp is None or resp.status_code != 200:
            return set(), False
        subs: set[str] = set()
        for line in resp.text.splitlines():
            parts = line.split(",")
            if parts:
                host = parts[0].strip().lower()
                if host.endswith(domain):
                    subs.add(host)
        return subs, bool(subs)

    async def _alienvault(self, domain: str) -> tuple[set[str], bool]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp = await self._http.get(url, scanner_tool=self.name, check_scope=False)
        if resp is None or resp.status_code != 200:
            return set(), False
        try:
            data = resp.json()
            subs: set[str] = set()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").lower()
                if hostname.endswith(domain):
                    subs.add(hostname)
            return subs, True
        except Exception:
            return set(), False

    async def _virustotal(self, domain: str) -> tuple[set[str], bool]:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            return set(), False
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        resp = await self._http.get(
            url,
            headers={"x-apikey": api_key},
            scanner_tool=self.name,
            check_scope=False,
        )
        if resp is None or resp.status_code != 200:
            return set(), False
        try:
            data = resp.json()
            subs: set[str] = set()
            for item in data.get("data", []):
                host = item.get("id", "").lower()
                if host.endswith(domain):
                    subs.add(host)
            return subs, True
        except Exception:
            return set(), False


def _format_subdomains(domain: str, live: list[dict]) -> str:
    lines = [f"Subdomains of {domain} ({len(live)} found):"]
    for s in live[:100]:
        status = "LIVE" if s["live"] else "unresolved"
        ips = ", ".join(s["ips"][:3]) if s["ips"] else ""
        lines.append(f"  {s['subdomain']} [{status}] {ips}")
    if len(live) > 100:
        lines.append(f"  ... and {len(live) - 100} more")
    return "\n".join(lines)
