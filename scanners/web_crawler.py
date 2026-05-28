"""Aggressive recursive web crawler.

Discovers URLs, forms, parameters, and JS endpoints by walking the
site graph BFS-style up to a configurable depth. Output is intended
to feed parameter_mining, sqli_scan, xss_scan, bola_scan with the
fattest possible attack surface.

Why a dedicated crawler vs. relying on http_probe + js_endpoints:
- http_probe only fingerprints what's at known seed paths
- js_endpoints only finds URLs referenced FROM JS bundles
- web_crawler walks the actual page graph: <a href>, <form action>,
  <iframe src>, <link href>, redirects, plus JS regex-extracted URLs

Pure stdlib + httpx + BeautifulSoup (already in pipeline).
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse, urlunparse, urldefrag

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanFinding, ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


# Regex from the LinkFinder paper — finds URL-like substrings in JS.
_JS_URL_RE = re.compile(
    r"""(?:["'])
    (
      (?:[a-z]+:\/\/|\/\/|\.\.?\/|\/)
      [^"'\s<>]+\.[a-zA-Z]{1,4}(?:\?[^"'\s<>]*)?
      |
      \/[^"'\s<>]+(?:\?[^"'\s<>]*)?
    )
    (?:["'])""",
    re.VERBOSE | re.IGNORECASE,
)

# Common static-asset extensions we don't recurse into (waste of budget).
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp4", ".mp3", ".webm", ".ogg", ".m4a",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".css",  # we DO record but don't recurse into linked stylesheets
})

# Sensitive paths the crawler especially flags.
_SENSITIVE_PATH_TOKENS = (
    "admin", "login", "logout", "register", "signup", "password",
    "config", "backup", "private", "internal", "debug",
    "api", "graphql", "swagger", "openapi",
    ".git", ".env", ".svn", ".bak",
)


@register_scanner
class WebCrawlerScanner(Scanner):
    name = "web_crawler"
    requires_libs = ("bs4",)
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def crawl(
        self,
        seed_url: str,
        *,
        max_depth: int = 4,
        max_pages: int = 200,
        max_concurrency: int = 6,
    ) -> ScanResult:
        """BFS crawl from ``seed_url`` up to ``max_depth`` levels deep.

        Records every URL, form, and parameter found into the ScanResult's
        ``data`` dict. Emits findings only for sensitive-path discoveries
        and exposed dev/secret-looking paths.
        """
        try:
            from bs4 import BeautifulSoup  # type: ignore[import-untyped]
        except ImportError:
            return ScanResult(
                scanner=self.name, target=seed_url, success=False,
                error="bs4 not installed",
            )

        result = ScanResult(scanner=self.name, target=seed_url)
        seed_host = urlparse(seed_url).netloc

        visited: set[str] = set()
        endpoints: set[str] = set()
        forms: list[dict[str, Any]] = []
        params_seen: set[tuple[str, str]] = set()  # (endpoint, param)

        queue: deque[tuple[str, int]] = deque()
        queue.append((seed_url, 0))
        sem = asyncio.Semaphore(max_concurrency)

        while queue and len(visited) < max_pages:
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < max_concurrency:
                url, depth = queue.popleft()
                norm = _normalise(url)
                if norm in visited or norm is None:
                    continue
                if urlparse(norm).netloc != seed_host:
                    continue
                if _has_skip_ext(norm):
                    continue
                visited.add(norm)
                batch.append((norm, depth))

            if not batch:
                break

            tasks = [self._fetch(url, sem) for url, _ in batch]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for (url, depth), resp in zip(batch, responses):
                if isinstance(resp, Exception) or resp is None:
                    continue
                endpoints.add(url)
                ctype = (resp.headers.get("content-type") or "").lower()
                text = resp.text or ""

                # Sensitive-path finding (any depth)
                if _is_sensitive_path(url):
                    result.findings.append(ScanFinding(
                        vuln_class="sensitive-path-discovered",
                        title=f"Sensitive path reachable: {urlparse(url).path}",
                        severity="low",
                        affected_target=url,
                        description=(
                            f"Crawler hit {url} (HTTP {resp.status_code}). "
                            "Path token suggests admin/config/internal exposure."
                        ),
                        cwe=["CWE-538"],
                        confidence="verified",
                        extra={"status": resp.status_code, "depth": depth},
                    ))

                # Stop recursing past max_depth
                if depth >= max_depth:
                    continue
                # Only parse HTML/JS for further links
                if "html" in ctype or "javascript" in ctype or url.endswith(".js"):
                    new_links = _extract_links(text, url, ctype)
                    for link in new_links:
                        norm = _normalise(link)
                        if norm and norm not in visited:
                            queue.append((norm, depth + 1))

                    # Extract forms (HTML only)
                    if "html" in ctype:
                        try:
                            soup = BeautifulSoup(text, "html.parser")
                            for f in soup.find_all("form"):
                                form_action = urljoin(url, f.get("action") or "")
                                method = (f.get("method") or "GET").upper()
                                inputs = []
                                for inp in f.find_all(["input", "select", "textarea"]):
                                    name = inp.get("name")
                                    if name:
                                        inputs.append(name)
                                        params_seen.add((form_action, name))
                                forms.append({
                                    "action": form_action,
                                    "method": method,
                                    "inputs": inputs,
                                })
                        except Exception:
                            pass

                # Track URL-level query params
                qs = urlparse(url).query
                if qs:
                    for pair in qs.split("&"):
                        if "=" in pair:
                            k = pair.split("=", 1)[0]
                            params_seen.add((url.split("?", 1)[0], k))

        result.data["endpoints_found"] = len(endpoints)
        result.data["forms_found"] = len(forms)
        result.data["unique_params"] = len(params_seen)
        result.data["pages_visited"] = len(visited)
        # Surface the discovered surface for downstream scanners
        result.data["endpoints"] = sorted(endpoints)[:200]
        result.data["forms"] = forms[:50]
        result.data["params"] = sorted({f"{k[0]}::{k[1]}" for k in params_seen})[:200]

        # Emit a summary finding
        if endpoints:
            result.findings.append(ScanFinding(
                vuln_class="attack-surface-mapped",
                title=(
                    f"Web crawl mapped {len(endpoints)} endpoints, "
                    f"{len(forms)} forms, {len(params_seen)} parameters"
                ),
                severity="informational",
                affected_target=seed_url,
                description=(
                    f"BFS crawl from {seed_url} (depth={max_depth}, "
                    f"pages={len(visited)}). Surface fed to parameter_mining, "
                    "sqli_scan, xss_scan, bola_scan."
                ),
                confidence="verified",
                extra={
                    "depth": max_depth,
                    "pages_visited": len(visited),
                    "endpoints_found": len(endpoints),
                    "forms_found": len(forms),
                    "params_found": len(params_seen),
                },
            ))

        return result

    async def _fetch(self, url: str, sem: asyncio.Semaphore):
        async with sem:
            try:
                return await self._http.get(url, scanner_tool=self.name)
            except Exception:
                return None


# ── Helpers ──────────────────────────────────────────────────────────

def _normalise(url: str) -> str | None:
    """Strip fragment, lowercase scheme/host, drop trailing slash."""
    try:
        u, _ = urldefrag(url)
        parsed = urlparse(u)
        if parsed.scheme not in ("http", "https"):
            return None
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        path = parsed.path or "/"
        # Don't strip trailing slash on root; otherwise normalise
        if len(path) > 1:
            path = path.rstrip("/")
        return urlunparse((
            parsed.scheme.lower(), host + port, path, "",
            parsed.query, "",
        ))
    except Exception:
        return None


def _has_skip_ext(url: str) -> bool:
    path = urlparse(url).path.lower()
    for ext in _SKIP_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


def _is_sensitive_path(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(token in path for token in _SENSITIVE_PATH_TOKENS)


def _extract_links(text: str, base: str, content_type: str) -> list[str]:
    """Extract URLs from HTML or JS content."""
    links: list[str] = []

    if "html" in content_type:
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, "html.parser")
            for tag, attr in (
                ("a", "href"), ("link", "href"), ("script", "src"),
                ("iframe", "src"), ("form", "action"), ("img", "src"),
                ("source", "src"), ("video", "src"),
            ):
                for el in soup.find_all(tag):
                    v = el.get(attr)
                    if v:
                        links.append(urljoin(base, v))
        except Exception:
            pass

    # JS regex extraction (works on inline <script> and standalone .js)
    for m in _JS_URL_RE.finditer(text):
        v = m.group(1)
        if v:
            links.append(urljoin(base, v))

    return links
