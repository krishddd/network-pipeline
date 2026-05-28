"""Broken Object-Level Authorisation (BOLA / IDOR) scanner.

Walks a list of authenticated endpoints with object-id path or query
params and probes neighbouring IDs (±1, ±10, JWT-sub guess). Compares
status + body length + body entropy against a baseline.

Heuristic:
- Baseline = original (presumed authorised) request.
- For each probe, fetch the same endpoint with a different ID.
- Flag BOLA if probe returns 2xx AND body differs substantially from
  baseline (length delta > 5% OR entropy delta > 0.3 OR shared-prefix
  ratio < 0.5).

The scanner does NOT mint cookies — it relies on AuthStore replay being
already wired into HTTPClient. Run AFTER auth_audit captures a session.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import (
    ScanFinding,
    ScanResult,
    normalize_endpoint,
)

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


_INT_PATH_RE = re.compile(r"/(\d+)(?=/|$|\?)")
_UUID_PATH_RE = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.I,
)


@register_scanner
class BOLAScanner(Scanner):
    name = "bola_scan"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def scan(
        self,
        endpoints: list[str],
        *,
        max_probes_per_endpoint: int = 6,
    ) -> ScanResult:
        result = ScanResult(scanner=self.name, target=",".join(endpoints[:3]))
        if not endpoints:
            result.success = False
            result.error = "no endpoints supplied"
            return result

        for url in endpoints:
            try:
                hits = await self._probe_endpoint(url, max_probes_per_endpoint)
                result.findings.extend(hits)
            except Exception as e:  # noqa: BLE001
                result.data.setdefault("errors", []).append(f"{url}: {e!r}")

        result.data["endpoints_probed"] = len(endpoints)
        result.data["bola_findings"] = sum(
            1 for f in result.findings if f.vuln_class == "idor-bola"
        )
        return result

    async def _probe_endpoint(
        self, url: str, max_probes: int,
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        baseline = await self._http.get(url, scanner_tool=self.name)
        if baseline is None or baseline.status_code >= 400:
            return findings  # baseline unauthorised — no signal
        base_body = baseline.text or ""
        base_len = len(base_body)
        if base_len < 8:
            return findings  # too small, signal unreliable
        base_entropy = _entropy(base_body[:8192])

        candidates = list(_neighbouring_ids(url, k=max_probes))
        for probe_url in candidates:
            r = await self._http.get(probe_url, scanner_tool=self.name)
            if r is None:
                continue
            if not (200 <= r.status_code < 300):
                continue
            probe_body = r.text or ""
            if len(probe_body) < 8:
                continue
            len_delta = abs(len(probe_body) - base_len) / max(base_len, 1)
            ent_delta = abs(_entropy(probe_body[:8192]) - base_entropy)
            shared = _shared_prefix_ratio(base_body, probe_body)
            # BOLA signal: substantively different body returned 200
            if len_delta > 0.05 or ent_delta > 0.3 or shared < 0.5:
                findings.append(ScanFinding(
                    vuln_class="idor-bola",
                    title=f"BOLA candidate — neighbour ID returned distinct 2xx body",
                    severity="high",
                    affected_target=normalize_endpoint(probe_url),
                    description=(
                        f"Original {url} returned {baseline.status_code}/"
                        f"{base_len}b; probe {probe_url} returned "
                        f"{r.status_code}/{len(probe_body)}b "
                        f"(len_delta={len_delta:.2f} ent_delta={ent_delta:.2f} "
                        f"shared_prefix={shared:.2f}). The endpoint did not "
                        "perform per-object authorisation."
                    ),
                    cwe=["CWE-639", "CWE-284"],
                    mitre=["T1190"],
                    confidence="probable",
                    extra={
                        "baseline_url": url,
                        "probe_url": probe_url,
                        "len_delta": round(len_delta, 3),
                        "ent_delta": round(ent_delta, 3),
                        "shared_prefix_ratio": round(shared, 3),
                    },
                ))
        return findings


# ── Helpers ──────────────────────────────────────────────────────────

def _neighbouring_ids(url: str, *, k: int = 6) -> Any:
    """Yield up to ``k`` neighbouring URLs by mutating an int/uuid id segment."""
    # Path int: /users/123/...
    m = _INT_PATH_RE.search(urlparse(url).path)
    if m:
        original = int(m.group(1))
        for delta in (1, -1, 2, -2, 10, -10):
            if len(list(_done := [])) >= k:  # noqa: SIM105
                return
            new_id = original + delta
            if new_id < 0:
                continue
            yield _replace_path_int(url, original, new_id)
            k -= 1
            if k <= 0:
                return
    # Path UUID: /orders/<uuid>/...
    m = _UUID_PATH_RE.search(urlparse(url).path)
    if m:
        original = m.group(1)
        for swap in _uuid_neighbours(original)[:k]:
            yield url.replace(original, swap)
        return
    # Query string id=...
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    for key in list(qs.keys()):
        if key.lower() not in {"id", "uid", "user", "user_id", "uuid"}:
            continue
        try:
            original = int(qs[key][0])
        except (ValueError, IndexError):
            continue
        for delta in (1, -1, 10, -10):
            new_id = original + delta
            if new_id < 0:
                continue
            new_qs = {**qs, key: [str(new_id)]}
            new_url = urlunparse(parsed._replace(
                query=urlencode(new_qs, doseq=True),
            ))
            yield new_url
            k -= 1
            if k <= 0:
                return


def _replace_path_int(url: str, original: int, new: int) -> str:
    parsed = urlparse(url)
    new_path = re.sub(
        rf"/{re.escape(str(original))}(?=/|$)",
        f"/{new}",
        parsed.path, count=1,
    )
    return urlunparse(parsed._replace(path=new_path))


def _uuid_neighbours(uuid_str: str) -> list[str]:
    """Trivial UUID neighbours by flipping the last hex char."""
    out = []
    if not uuid_str or len(uuid_str) < 36:
        return out
    last = uuid_str[-1]
    for c in "0123456789abcdef":
        if c == last.lower():
            continue
        out.append(uuid_str[:-1] + c)
        if len(out) >= 6:
            break
    return out


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _shared_prefix_ratio(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    n = min(len(a), len(b), 4096)
    shared = 0
    for i in range(n):
        if a[i] == b[i]:
            shared += 1
        else:
            break
    return shared / max(len(a), len(b), 1)
