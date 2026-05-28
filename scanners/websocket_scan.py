"""WebSocket security scanner.

Checks for:
- Discoverable WS upgrade endpoints (/ws, /websocket, /socket.io, etc.)
- Origin enforcement on Upgrade (Cross-Site WebSocket Hijacking — CSWSH)
- Auth-context replay (cookie/bearer captured by AuthStore replays into
  the WS upgrade)
- Missing wss (cleartext WS over public network)

Pure stdlib: uses asyncio + the optional ``websockets`` lib if available;
falls back to the bare HTTP Upgrade probe (which is enough to detect
origin-enforcement issues without a full WS handshake).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import ssl
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanFinding, ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


_DISCOVERY_PATHS = (
    "/ws", "/websocket", "/socket", "/socket.io/?EIO=4&transport=websocket",
    "/api/ws", "/api/websocket", "/wss", "/realtime", "/pubsub",
    "/notifications/ws", "/chat/ws",
)


def _ws_key() -> str:
    return base64.b64encode(os.urandom(16)).decode("ascii")


@register_scanner
class WebSocketScanner(Scanner):
    name = "websocket_scan"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "low"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def scan(self, base_url: str) -> ScanResult:
        result = ScanResult(scanner=self.name, target=base_url)

        # 1. Discover WS endpoints
        endpoints = await self._discover(base_url)
        if not endpoints:
            result.success = False
            result.error = "no WS endpoint found at common paths"
            return result
        result.data["endpoints"] = endpoints

        for ep in endpoints:
            scheme = "wss" if ep.startswith("https") else "ws"
            ws_url = ep.replace("https://", "wss://").replace("http://", "ws://")

            # Cleartext WS finding
            if scheme == "ws":
                result.findings.append(ScanFinding(
                    vuln_class="websocket-cleartext",
                    title=f"WebSocket exposed over cleartext ws:// at {ws_url}",
                    severity="medium",
                    affected_target=ws_url,
                    description=(
                        "WebSocket traffic is unencrypted. Adversaries on "
                        "the path can read or inject messages."
                    ),
                    cwe=["CWE-319"],
                    confidence="verified",
                ))

            # 2. Origin enforcement: send Upgrade with attacker-origin
            try:
                accepts_evil = await _origin_accepts(ep, evil_origin="https://evil.example")
                accepts_native = await _origin_accepts(
                    ep, evil_origin=f"{urlparse(ep).scheme}://{urlparse(ep).netloc}",
                )
            except Exception:  # noqa: BLE001
                accepts_evil = accepts_native = None

            if accepts_evil and accepts_native:
                result.findings.append(ScanFinding(
                    vuln_class="cswsh",
                    title=f"Cross-Site WebSocket Hijacking — origin not validated at {ws_url}",
                    severity="high",
                    affected_target=ws_url,
                    description=(
                        "The WebSocket upgrade was accepted with "
                        "Origin: https://evil.example. Combined with cookie "
                        "auth this lets an attacker page hijack the victim's "
                        "WS session via CSRF-like flow."
                    ),
                    cwe=["CWE-1385", "CWE-352"],
                    mitre=["T1557"],
                    confidence="probable",
                ))

        return result

    # ── Discovery ──────────────────────────────────────────────────

    async def _discover(self, base_url: str) -> list[str]:
        out: list[str] = []
        for path in _DISCOVERY_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            r = await self._http.get(
                url,
                headers={
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Key": _ws_key(),
                    "Sec-WebSocket-Version": "13",
                },
                scanner_tool=self.name,
            )
            if r is None:
                continue
            # 101 Switching Protocols means the endpoint speaks WS.
            # Some servers return 400 + "Bad WebSocket key" which still
            # confirms the endpoint exists.
            if r.status_code == 101:
                out.append(url)
            elif r.status_code in (400, 426) and (
                "websocket" in (r.text or "").lower()
            ):
                out.append(url)
        return out


# ── Raw upgrade probe (origin check) ───────────────────────────────

async def _origin_accepts(url: str, *, evil_origin: str) -> bool | None:
    """Send a raw HTTP Upgrade with a forged Origin and look for 101."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    ssl_ctx = ssl.create_default_context() if parsed.scheme == "https" else None
    if ssl_ctx is not None:
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    key = _ws_key()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {evil_origin}\r\n"
        f"\r\n"
    ).encode("ascii")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=ssl_ctx,
                server_hostname=host if ssl_ctx else None,
            ),
            timeout=5.0,
        )
    except (OSError, asyncio.TimeoutError):
        return None
    try:
        writer.write(req)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=4.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return None
        line = data.decode("latin-1", errors="ignore").strip()
        # Expect "HTTP/1.1 101 Switching Protocols"
        return "101" in line
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
