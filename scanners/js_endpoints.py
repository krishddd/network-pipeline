"""JavaScript endpoint extractor — replaces getJS + LinkFinder.

Fetches a page, extracts all <script src="..."> tags via BeautifulSoup,
fetches each script, then applies the LinkFinder regex set to extract
endpoint patterns from JS source.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

# LinkFinder regex — ported from GerbenJavado/LinkFinder
_ENDPOINT_PATTERN = re.compile(
    r"""(?:"|')                     # start with " or '
    (                               # capture group
        (?:
            [a-zA-Z]{1,10}://       # protocol
            |                       # or
            //                      # protocol-relative
        )
        [^"'\s]{1,250}              # url chars
        |                           # or
        /?[a-zA-Z0-9_\-/]{1,250}   # relative path
        (?:
            \.[a-zA-Z]{1,4}        # extension
            |/                     # or trailing slash
        )
    )
    (?:"|')""",
    re.VERBOSE,
)

# Extensions to skip (binary, media, fonts)
_SKIP_EXTS = frozenset(
    ".png .jpg .jpeg .gif .svg .ico .woff .woff2 .ttf .eot .otf "
    ".mp4 .mp3 .avi .pdf .zip .tar .gz .css".split()
)

MAX_SCRIPT_SIZE = 2 * 1024 * 1024  # 2 MB


@register_scanner
class JSEndpointScanner(Scanner):
    name = "js_endpoints"
    requires_libs = ("bs4",)
    opsec_min = "loud"
    loud_level = "low"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def extract(self, url: str) -> ScanResult:
        """Extract endpoints from all JS files linked from url."""
        from bs4 import BeautifulSoup

        # Fetch the page
        resp = await self._http.get(url, scanner_tool=self.name)
        if resp is None:
            return ScanResult(
                scanner=self.name, target=url, success=False,
                error="could not fetch page",
            )

        soup = BeautifulSoup(resp.text, "html.parser")
        base = _base_url(url)

        # Collect script URLs
        script_urls: list[str] = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            abs_url = urljoin(base, src)
            if _is_same_origin(abs_url, base) or abs_url.startswith("//"):
                script_urls.append(abs_url)

        all_endpoints: set[str] = set()
        inline_endpoints = _extract_from_js(resp.text)
        all_endpoints.update(inline_endpoints)

        # Fetch and parse each script
        for js_url in script_urls[:30]:  # cap at 30 files
            js_resp = await self._http.get(js_url, scanner_tool=self.name, check_scope=False)
            if js_resp is None:
                continue
            if len(js_resp.content) > MAX_SCRIPT_SIZE:
                continue
            endpoints = _extract_from_js(js_resp.text)
            all_endpoints.update(endpoints)

        # Filter and categorise
        api_endpoints = [e for e in all_endpoints if _looks_like_api(e)]
        other_endpoints = [e for e in all_endpoints if not _looks_like_api(e)]

        findings: list[ScanFinding] = []
        if api_endpoints:
            findings.append(ScanFinding(
                vuln_class="js-endpoints-discovered",
                title=f"JS endpoint enumeration: {len(api_endpoints)} API paths",
                severity="informational",
                affected_target=url,
                description=f"Discovered {len(api_endpoints)} potential API endpoints in JS.",
                confidence="probable",
                extra={"endpoints": api_endpoints[:50]},
            ))

        return ScanResult(
            scanner=self.name,
            target=url,
            success=True,
            data={
                "scripts_fetched": len(script_urls),
                "api_endpoints": api_endpoints[:200],
                "other_endpoints": other_endpoints[:100],
                "total": len(all_endpoints),
            },
            findings=findings,
            raw_text=_format_endpoints(url, api_endpoints, other_endpoints),
        )


def _extract_from_js(text: str) -> set[str]:
    endpoints: set[str] = set()
    for m in _ENDPOINT_PATTERN.finditer(text):
        endpoint = m.group(1).strip()
        ext = "." + endpoint.rsplit(".", 1)[-1].lower() if "." in endpoint else ""
        if ext in _SKIP_EXTS:
            continue
        if len(endpoint) < 3 or len(endpoint) > 250:
            continue
        endpoints.add(endpoint)
    return endpoints


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _is_same_origin(url: str, base: str) -> bool:
    return url.startswith(base)


def _looks_like_api(endpoint: str) -> bool:
    api_keywords = ("/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/",
                    "/service/", "/endpoint", ".json", ".xml")
    return any(kw in endpoint.lower() for kw in api_keywords)


def _format_endpoints(url: str, api: list[str], other: list[str]) -> str:
    lines = [f"JS endpoints from {url}:", f"  API-like ({len(api)}):"]
    for e in api[:20]:
        lines.append(f"    {e}")
    lines.append(f"  Other ({len(other)}):")
    for e in other[:10]:
        lines.append(f"    {e}")
    return "\n".join(lines)
