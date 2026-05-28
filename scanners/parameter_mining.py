"""Parameter miner — replaces paramspider + arjun.

Two modes:
  Passive (always): Wayback Machine CDX API extracts historic URL parameters.
  Active (OPSEC-gated, LOUD/STANDARD only): concurrent GET brute-force against
  a bundled 1000-param wordlist with reflection detection.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding, load_params_wordlist

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

_WAYBACK_CDX = (
    "http://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=5000"
)

# Canary used to detect reflection in brute-force mode
_CANARY = "pMine7x3"
_BRUTE_CONCURRENCY = 20
_BRUTE_MAX_PARAMS = 1000


@register_scanner
class ParamScanner(Scanner):
    name = "parameter_mining"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient", opsec_level: str = "standard") -> None:
        self._http = http_client
        self._opsec_level = opsec_level.lower()

    async def mine(self, target_url: str) -> ScanResult:
        """Mine parameters from Wayback and optionally brute-force live."""
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(":")[0]

        params: dict[str, set[str]] = {}
        sources: list[str] = []

        # Passive: Wayback CDX
        wayback_params = await self._wayback_params(domain)
        if wayback_params:
            for p in wayback_params:
                params.setdefault(p, set()).add("wayback")
            sources.append("wayback")

        # Active brute-force (LOUD or STANDARD opsec only)
        if self._opsec_level in ("loud", "standard"):
            brute_params = await self._brute_force(target_url)
            for p in brute_params:
                params.setdefault(p, set()).add("brute")
            if brute_params:
                sources.append("brute")

        all_params = sorted(params.keys())
        findings: list[ScanFinding] = []
        if all_params:
            findings.append(ScanFinding(
                vuln_class="parameters-discovered",
                title=f"Discovered {len(all_params)} parameters on {target_url}",
                severity="informational",
                affected_target=target_url,
                description="Parameter list for further injection testing.",
                confidence="probable",
                extra={"params": all_params[:200], "sources": sources},
            ))

        return ScanResult(
            scanner=self.name,
            target=target_url,
            success=True,
            data={"params": all_params, "count": len(all_params), "sources": sources},
            findings=findings,
            raw_text=_format_params(target_url, all_params, sources),
        )

    async def _wayback_params(self, domain: str) -> list[str]:
        """Extract parameter names from Wayback CDX archived URLs."""
        url = _WAYBACK_CDX.format(domain=domain)
        resp = await self._http.get(url, scanner_tool=self.name, check_scope=False)
        if resp is None or resp.status_code != 200:
            return []
        try:
            data = resp.json()
            # First row is headers
            params: set[str] = set()
            for row in data[1:]:
                if not row:
                    continue
                orig = row[0] if isinstance(row, list) else str(row)
                qs = urlparse(orig).query
                if qs:
                    for k in parse_qs(qs).keys():
                        if k and 1 < len(k) < 64:
                            params.add(k)
            return sorted(params)
        except Exception:
            return []

    async def _brute_force(self, target_url: str) -> list[str]:
        """Concurrent brute-force: send each param with canary, detect reflection."""
        wordlist = load_params_wordlist()[:_BRUTE_MAX_PARAMS]
        if not wordlist:
            return []

        baseline_resp = await self._http.get(target_url, scanner_tool=self.name)
        if baseline_resp is None:
            return []
        baseline_len = len(baseline_resp.content)

        sem = asyncio.Semaphore(_BRUTE_CONCURRENCY)
        tasks = [self._probe_param(target_url, param, baseline_len, sem) for param in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, str)]

    async def _probe_param(
        self,
        url: str,
        param: str,
        baseline_len: int,
        sem: asyncio.Semaphore,
    ) -> str | None:
        async with sem:
            probe_url = _append_param(url, param, _CANARY)
            resp = await self._http.get(probe_url, scanner_tool=self.name)
            if resp is None:
                return None
            # Reflection: canary appears in response body
            if _CANARY in resp.text:
                return param
            # Length difference > 10% with same status → param processed
            if resp.status_code == baseline_len and len(resp.content) > baseline_len * 1.1:
                return param
            return None


def _append_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    existing[key] = [value]
    new_qs = urlencode(existing, doseq=True)
    return urlunparse(parsed._replace(query=new_qs))


def _format_params(url: str, params: list[str], sources: list[str]) -> str:
    lines = [f"Parameters on {url} (sources: {', '.join(sources)}):"]
    for p in params[:50]:
        lines.append(f"  ?{p}=")
    if len(params) > 50:
        lines.append(f"  ... and {len(params) - 50} more")
    return "\n".join(lines)
