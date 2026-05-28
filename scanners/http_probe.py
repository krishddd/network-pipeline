"""HTTP probe scanner — replaces ProjectDiscovery httpx binary.

Probes a list of URLs: status, title, content-type, server header,
tech-detection via header + favicon hash + meta-generator.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

# Minimal wappalyzer-ish rules: (header_name, pattern, tech_name, category)
_HEADER_RULES: list[tuple[str, re.Pattern[str], str]] = [
    ("server", re.compile(r"nginx", re.I), "Nginx"),
    ("server", re.compile(r"apache", re.I), "Apache"),
    ("server", re.compile(r"iis", re.I), "IIS"),
    ("server", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("x-powered-by", re.compile(r"php", re.I), "PHP"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("x-powered-by", re.compile(r"express", re.I), "Express"),
    ("x-generator", re.compile(r"wordpress", re.I), "WordPress"),
    ("x-generator", re.compile(r"drupal", re.I), "Drupal"),
]

_META_GENERATOR_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"wordpress", re.I), "WordPress"),
    (re.compile(r"joomla", re.I), "Joomla"),
    (re.compile(r"drupal", re.I), "Drupal"),
    (re.compile(r"ghost", re.I), "Ghost"),
]

_TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.I)
_META_GEN_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

# Security headers that should be present
_REQUIRED_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


@register_scanner
class HTTPProbeScanner(Scanner):
    name = "http_probe"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "low"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def probe(self, urls: list[str]) -> ScanResult:
        """Probe a list of URLs and return tech-detection results."""
        tasks = [self._probe_one(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        probed: list[dict[str, Any]] = []
        findings: list[ScanFinding] = []

        for url, res in zip(urls, results):
            if isinstance(res, Exception) or res is None:
                probed.append({"url": url, "error": str(res)})
                continue
            probed.append(res)
            findings.extend(_make_findings(url, res))

        return ScanResult(
            scanner=self.name,
            target="|".join(urls[:3]),
            success=True,
            data={"probed": probed, "count": len(probed)},
            findings=findings,
            raw_text=_format_results(probed),
        )

    async def _probe_one(self, url: str) -> dict[str, Any] | None:
        resp = await self._http.get(url, scanner_tool=self.name)
        if resp is None:
            return None

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:65536]

        title = ""
        m = _TITLE_RE.search(body)
        if m:
            title = m.group(1).strip()[:200]

        # Tech detection
        techs: list[str] = []
        for hdr_name, pattern, tech_name in _HEADER_RULES:
            val = headers.get(hdr_name, "")
            if val and pattern.search(val):
                techs.append(tech_name)

        gen_m = _META_GEN_RE.search(body)
        if gen_m:
            gen_val = gen_m.group(1)
            for pat, tech_name in _META_GENERATOR_RULES:
                if pat.search(gen_val):
                    techs.append(tech_name)

        # Favicon hash for fingerprinting
        favicon_hash = await self._favicon_hash(url)

        # Security headers present/absent
        present_sec = [h for h in _REQUIRED_SECURITY_HEADERS if h in headers]
        missing_sec = [h for h in _REQUIRED_SECURITY_HEADERS if h not in headers]

        return {
            "url": url,
            "status": resp.status_code,
            "title": title,
            "content_type": headers.get("content-type", ""),
            "server": headers.get("server", ""),
            "content_length": len(resp.content),
            "technologies": list(set(techs)),
            "favicon_hash": favicon_hash,
            "missing_security_headers": missing_sec,
            "present_security_headers": present_sec,
            "redirect_url": str(resp.url) if str(resp.url) != url else "",
        }

    async def _favicon_hash(self, base_url: str) -> str:
        favicon_url = urljoin(base_url, "/favicon.ico")
        resp = await self._http.get(favicon_url, scanner_tool=self.name, check_scope=False)
        if resp and resp.status_code == 200 and resp.content:
            return hashlib.md5(resp.content).hexdigest()
        return ""


def _make_findings(url: str, result: dict) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    missing = result.get("missing_security_headers", [])
    if missing:
        findings.append(ScanFinding(
            vuln_class="missing-security-headers",
            title=f"Missing security headers on {url}",
            severity="low",
            affected_target=url,
            description=f"Missing headers: {', '.join(missing)}",
            cwe=["CWE-693"],
            mitre=["T1190"],
            remediation="Add missing HTTP security headers in web server config.",
            confidence="verified",
        ))
    return findings


def _format_results(probed: list[dict]) -> str:
    lines = ["HTTP probe results:"]
    for p in probed:
        url = p.get("url", "")
        if "error" in p:
            lines.append(f"  {url} — ERROR: {p['error']}")
        else:
            techs = ", ".join(p.get("technologies", [])) or "unknown"
            lines.append(
                f"  {p.get('status')} {url} [{techs}] "
                f"title={p.get('title', '')[:60]!r}"
            )
    return "\n".join(lines)
