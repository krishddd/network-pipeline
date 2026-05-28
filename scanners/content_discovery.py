"""Content/directory discovery — replaces ffuf + feroxbuster.

Concurrent httpx requests against wordlist; auto-calibrates against a
random-baseline response to filter false-positives.
"""

from __future__ import annotations

import asyncio
import random
import string
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import (
    ScanResult,
    ScanFinding,
    load_wordlist,
)

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

# Status codes we keep (standard content-discovery filter)
_KEEP_STATUS = frozenset({200, 204, 301, 302, 307, 401, 403})

# Interesting status codes — worth flagging as findings
_FINDING_STATUS = frozenset({200, 204, 401, 403})

_CONCURRENCY = 30
_MAX_WORDS = 10_000  # cap per run to avoid wall-time explosion


@register_scanner
class ContentScanner(Scanner):
    name = "content_discovery"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "high"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def discover(
        self,
        target_url: str,
        wordlist: str = "common",
        recurse: bool = False,
        max_recurse_depth: int = 2,
        max_recurse_dirs: int = 8,
    ) -> ScanResult:
        """Discover content under target_url using a bundled wordlist.

        When ``recurse=True``, every 200/3xx hit whose URL ends in `/`
        OR whose path looks directory-like (no file extension) is
        re-probed with the same wordlist up to ``max_recurse_depth``
        levels. Capped at ``max_recurse_dirs`` per level to keep
        wall-time bounded.
        """
        target_url = target_url.rstrip("/")
        words = load_wordlist(wordlist)[:_MAX_WORDS]

        if not words:
            return ScanResult(
                scanner=self.name, target=target_url, success=False,
                error=f"wordlist '{wordlist}' is empty or missing",
            )

        all_hits: list[dict] = []
        roots_to_visit: list[tuple[str, int]] = [(target_url, 0)]
        visited_roots: set[str] = set()

        while roots_to_visit:
            base, depth = roots_to_visit.pop(0)
            if base in visited_roots:
                continue
            visited_roots.add(base)

            baseline = await self._calibrate(base)
            sem = asyncio.Semaphore(_CONCURRENCY)
            tasks = [self._probe(base, word, baseline, sem) for word in words]
            raw = await asyncio.gather(*tasks, return_exceptions=True)
            level_hits = [r for r in raw if isinstance(r, dict)]
            all_hits.extend(level_hits)

            if not recurse or depth >= max_recurse_depth:
                continue

            # Pick directory-like 200/3xx hits to recurse into
            dir_candidates = [
                h for h in level_hits
                if h["status"] in (200, 301, 302, 307, 401, 403)
                and _looks_like_dir(h["path"])
            ]
            for hit in dir_candidates[:max_recurse_dirs]:
                next_root = (base + hit["path"]).rstrip("/")
                roots_to_visit.append((next_root, depth + 1))

        all_hits.sort(key=lambda h: (h["status"], h["path"]))
        findings = _make_findings(target_url, all_hits)

        return ScanResult(
            scanner=self.name,
            target=target_url,
            success=True,
            data={
                "hits": all_hits[:500],
                "total_hits": len(all_hits),
                "words_tried": len(words),
                "wordlist": wordlist,
                "recursive": recurse,
                "depth": max_recurse_depth if recurse else 0,
                "directories_recursed": len(visited_roots) - 1,
            },
            findings=findings,
            raw_text=_format_hits(target_url, all_hits),
        )

    async def _calibrate(self, base: str) -> dict:
        """Fetch two random non-existent paths to learn the 404 signature."""
        results = {"status_codes": set(), "avg_length": 0}
        lengths: list[int] = []
        for _ in range(2):
            random_path = "".join(random.choices(string.ascii_lowercase, k=12))
            url = f"{base}/{random_path}"
            resp = await self._http.get(url, scanner_tool=self.name)
            if resp is not None:
                results["status_codes"].add(resp.status_code)
                lengths.append(len(resp.content))
        results["avg_length"] = int(sum(lengths) / len(lengths)) if lengths else 0
        return results

    async def _probe(
        self,
        base: str,
        word: str,
        baseline: dict,
        sem: asyncio.Semaphore,
    ) -> dict | None:
        async with sem:
            url = f"{base}/{word}"
            resp = await self._http.get(url, scanner_tool=self.name)
            if resp is None:
                return None
            status = resp.status_code
            if status not in _KEEP_STATUS:
                return None
            # Filter out calibrated 404-equivalent codes
            if status in baseline.get("status_codes", set()):
                # Check body length — large divergence = real response
                body_len = len(resp.content)
                avg = baseline.get("avg_length", 0)
                if avg > 0 and abs(body_len - avg) < avg * 0.1:
                    return None
            return {
                "path": f"/{word}",
                "url": url,
                "status": status,
                "content_length": len(resp.content),
                "content_type": resp.headers.get("content-type", "")[:60],
            }


def _make_findings(target: str, hits: list[dict]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    # Sensitive paths
    sensitive_keywords = (
        ".git", ".env", "admin", "backup", "config", "phpinfo",
        ".htaccess", "web.config", "swagger", "api-docs", "actuator",
    )
    for hit in hits:
        path = hit["path"].lower()
        for kw in sensitive_keywords:
            if kw in path and hit["status"] in _FINDING_STATUS:
                findings.append(ScanFinding(
                    vuln_class=f"sensitive-path-{kw.replace('.', '').replace('-', '_')}",
                    title=f"Sensitive path exposed: {hit['url']}",
                    severity="high" if kw in (".git", ".env", "backup") else "medium",
                    affected_target=hit["url"],
                    description=f"HTTP {hit['status']} at {hit['url']} — may expose sensitive data.",
                    cwe=["CWE-538"] if kw == ".git" else ["CWE-200"],
                    mitre=["T1083"],
                    remediation=f"Restrict access to {hit['path']}.",
                    confidence="verified",
                ))
                break
    return findings


def _format_hits(target: str, hits: list[dict]) -> str:
    lines = [f"Content discovery on {target} — {len(hits)} hits:"]
    for h in hits[:50]:
        lines.append(f"  {h['status']} {h['path']} ({h['content_length']}B)")
    if len(hits) > 50:
        lines.append(f"  ... and {len(hits) - 50} more")
    return "\n".join(lines)


def _looks_like_dir(path: str) -> bool:
    """Heuristic: path is directory-like if it has no file extension OR
    ends in `/`. Used by recursive content discovery."""
    p = (path or "").rstrip("/")
    if not p:
        return False
    last = p.rsplit("/", 1)[-1]
    if "." not in last:
        return True
    # Treat known extension-less common dirs as dirs anyway
    return last.lower() in {"admin", "api", "backup", "config", "files",
                            "uploads", "private"}
