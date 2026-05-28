"""Pure-Python runtime primitives replacing the subprocess ShellRunner.

Three shared primitives used by all scanners:
  HTTPClient  — async httpx wrapper with scope, rate-limit, evidence, proxy
  DNSClient   — dnspython resolver with evidence capture
  TCPConnectProbe — asyncio TCP connect-scan with banner-grab

Plus a thin factory:
  get_browser_session() — lazy-imports BrowserSession from browser/playwright_session.py

One HTTPClient instance is created per engagement by EngagementLoop and injected
into every scanner via the agent factory's extra_tools plumbing. Used as an
async context manager so the underlying httpx.AsyncClient closes on teardown.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from network_pipeline.core.logging import get_logger
from network_pipeline.core.rate_limit import GLOBAL_RATE_LIMITS, RateLimitRegistry

if TYPE_CHECKING:
    from network_pipeline.core.c2_profile import CallbackProfile
    from network_pipeline.core.evidence_chain import EvidenceChain
    from network_pipeline.core.schemas import RoE

log = get_logger("tools.runtime")

# ── Scope guard (moved here from tools/shell.py) ──────────────────────────────


@dataclass
class ScopeGuard:
    """RoE-derived in-scope set. Every HTTP/DNS/TCP call validates against this."""

    domains: tuple[str, ...] = ()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    raw_targets: tuple[str, ...] = ()

    def allows(self, target: str) -> bool:
        target = target.strip().rstrip("/")
        if target in self.raw_targets:
            return True
        # Bug-fix: previous string-split parser failed on URLs without
        # a path (e.g. "http://host?id=foo") because no `/` was present
        # to split on, so the query string contaminated the host token.
        # Use urllib.parse.urlparse for a robust extraction that handles
        # any URL form: with/without path, with/without query, with port.
        from urllib.parse import urlparse
        try:
            url_for_parse = target if "://" in target else "http://" + target
            parsed = urlparse(url_for_parse)
            host = (parsed.hostname or "").lower()
        except Exception:
            # Fallback: also strip query and fragment in case urlparse failed
            host = (
                target.split("://", 1)[-1]
                .split("/", 1)[0]
                .split("?", 1)[0]
                .split("#", 1)[0]
                .split(":", 1)[0]
                .lower()
            )
        if not host:
            return False
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        try:
            ip = ipaddress.ip_address(host)
            for net in self.networks:
                if ip in net:
                    return True
        except ValueError:
            pass
        return False

    @classmethod
    def from_in_scope(cls, in_scope: list) -> "ScopeGuard":
        domains: list[str] = []
        networks: list = []
        raw: list[str] = []
        for entry in in_scope:
            t = entry.target.strip().rstrip("/")
            kind = entry.type.lower()
            if kind in ("cidr", "ip-range", "ip"):
                try:
                    networks.append(ipaddress.ip_network(t, strict=False))
                except ValueError:
                    log.warning("invalid CIDR in RoE: %s", t)
            elif kind == "domain":
                domains.append(t)
            else:
                raw.append(t)
            try:
                networks.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                pass
        return cls(
            domains=tuple(domains),
            networks=tuple(networks),
            raw_targets=tuple(raw),
        )


# ── Wayback-specific backoff registry ─────────────────────────────────────────

_WAYBACK_HOSTS = frozenset({"web.archive.org", "archive.org"})
_MAX_WAYBACK_BACKOFF = 60.0


class _HostBackoff:
    """Exponential backoff tracker for specific hosts (Wayback Machine)."""

    def __init__(self) -> None:
        self._delays: dict[str, float] = {}

    def record_failure(self, host: str) -> None:
        cur = self._delays.get(host, 1.0)
        self._delays[host] = min(cur * 2.0, _MAX_WAYBACK_BACKOFF)

    def record_success(self, host: str) -> None:
        self._delays.pop(host, None)

    async def wait_if_needed(self, host: str) -> None:
        delay = self._delays.get(host, 0.0)
        if delay > 0:
            jitter = random.uniform(0, delay * 0.2)
            await asyncio.sleep(delay + jitter)


# ── HTTPClient ─────────────────────────────────────────────────────────────────


DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)

_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


class HTTPClient:
    """One-per-engagement async HTTP client.

    Wraps httpx.AsyncClient with:
    - scope-allows-target check
    - request_guard RoE prohibition check
    - per-(scanner_tool, host) rate-limit acquire
    - callback_profile pacing
    - evidence capture: request+response bytes → disk + SHA-256 sidecar + Merkle leaf
    - proxy support (kwarg or HTTP_PROXY/HTTPS_PROXY env vars)
    - Wayback-specific exponential backoff
    """

    def __init__(
        self,
        scope: ScopeGuard | None = None,
        roe: "RoE | None" = None,
        rate_limits: RateLimitRegistry | None = None,
        callback_profile: "CallbackProfile | None" = None,
        evidence_chain: "EvidenceChain | None" = None,
        workspace: Path | None = None,
        *,
        proxy: str | None = None,
        dns_nameservers: list[str] | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        user_agents: list[str] | None = None,
    ) -> None:
        self._scope = scope or ScopeGuard()
        self._roe = roe
        self._rate_limits = rate_limits if rate_limits is not None else GLOBAL_RATE_LIMITS
        self._callback_profile = callback_profile
        self._evidence_chain = evidence_chain
        self._workspace = workspace
        self._timeout = timeout
        self._user_agents = user_agents or [_DEFAULT_UA]
        self._wayback = _HostBackoff()

        # Build proxy URL from kwarg or env. httpx >=0.28 removed the
        # ``proxies={"http://": ..., "https://": ...}`` kwarg in favour
        # of a single ``proxy=`` URL applied to every scheme. Detect
        # the installed httpx version and pass the right kwarg.
        import os
        proxy_url = proxy or os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")

        client_kwargs: dict[str, Any] = {
            "timeout": self._timeout,
            "follow_redirects": True,
            "http2": False,
        }
        if proxy_url:
            try:
                httpx_major, httpx_minor = (int(x) for x in httpx.__version__.split(".")[:2])
            except (ValueError, AttributeError):
                httpx_major, httpx_minor = 0, 28  # assume modern
            if (httpx_major, httpx_minor) >= (0, 28):
                client_kwargs["proxy"] = proxy_url
            else:
                client_kwargs["proxies"] = {
                    "http://": proxy_url, "https://": proxy_url,
                }
        self._client: httpx.AsyncClient = httpx.AsyncClient(**client_kwargs)
        if workspace:
            (workspace / "tool_io").mkdir(parents=True, exist_ok=True)

    async def __aenter__(self) -> "HTTPClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    def snapshot_cookies(self) -> dict[str, str]:
        """Return a snapshot of the current cookie jar (by domain)."""
        jar = self._client.cookies
        return {k: v for k, v in jar.items()}

    def restore_cookies(self, snapshot: dict[str, str]) -> None:
        """Restore cookie jar from a snapshot."""
        for k, v in snapshot.items():
            self._client.cookies.set(k, v)

    # ── public request interface ───────────────────────────────────────────────

    async def request(
        self,
        method: str,
        url: str,
        *,
        scanner_tool: str = "http_client",
        agent: str = "unknown",
        objective_id: str = "",
        check_scope: bool = True,
        **kwargs: Any,
    ) -> httpx.Response | None:
        """Issue an HTTP request with all safety/evidence wrappers.

        Returns the response or None if refused (scope/RoE) or on error.
        """
        parsed = urlparse(url)
        host = parsed.hostname or ""

        # 1. Scope check
        if check_scope and not self._scope.allows(url):
            log.warning("http_client: scope denied %s", url)
            return None

        # 2. RoE request-guard check
        from network_pipeline.tools.request_guard import check_request
        refusal = check_request(method, url, kwargs.get("content") or kwargs.get("data"), self._roe)
        if refusal:
            log.warning("http_client: request_guard denied %s %s: %s", method, url, refusal)
            return None

        # 3. Rate limit (async — keeps the event loop alive while
        #    waiting for tokens; previously used sync time.sleep which
        #    froze the entire asyncio loop and made parallel scanners
        #    serialise + overshoot their asyncio.wait_for timeouts).
        await self._rate_limits.acquire_async(scanner_tool, host)

        # 4. Callback profile pacing (async — sync sleep here would
        #    freeze the asyncio loop for sleep_s±jitter every request,
        #    serialising concurrent scanners and starving wait_for
        #    timeouts. With c2_profile=balanced (5s) and 9 parallel
        #    scanners that meant a 45s loop freeze per cycle.)
        if self._callback_profile is not None:
            if hasattr(self._callback_profile, "apply_pacing_async"):
                await self._callback_profile.apply_pacing_async()
            else:
                self._callback_profile.apply_pacing()  # legacy fallback

        # 5. Wayback backoff
        if host in _WAYBACK_HOSTS:
            await self._wayback.wait_if_needed(host)

        # 6. Pick UA
        ua = random.choice(self._user_agents)
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("User-Agent", ua)

        t0 = time.monotonic()
        try:
            resp = await self._client.request(method, url, headers=headers, **kwargs)
            duration = time.monotonic() - t0

            if host in _WAYBACK_HOSTS:
                if resp.status_code == 429:
                    self._wayback.record_failure(host)
                else:
                    self._wayback.record_success(host)

            # 7. Evidence capture
            self._capture_evidence(method, url, resp, agent, objective_id, scanner_tool, t0)
            return resp

        except (httpx.TimeoutException, httpx.ConnectError) as e:
            duration = time.monotonic() - t0
            if host in _WAYBACK_HOSTS:
                self._wayback.record_failure(host)
            # Bumped from debug to warning: silently swallowing network
            # errors made it impossible to tell why scanners produced 0
            # findings (timeout? connection refused? DNS? firewall?).
            log.warning(
                "http_client: %s %s FAILED (%.1fs): %s: %s",
                method, url, duration, type(e).__name__, e,
            )
            return None
        except Exception as e:
            log.warning(
                "http_client: %s %s UNEXPECTED ERROR: %s: %s",
                method, url, type(e).__name__, e,
            )
            return None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)

    # ── evidence capture ───────────────────────────────────────────────────────

    def _capture_evidence(
        self,
        method: str,
        url: str,
        resp: httpx.Response,
        agent: str,
        objective_id: str,
        scanner_tool: str,
        t0: float,
    ) -> None:
        if not self._workspace:
            return
        try:
            out_dir = self._workspace / "tool_io" / agent
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            stem = f"{ts}_{objective_id or 'noobj'}_{scanner_tool}"

            req_bytes = (
                f"{method} {url}\n"
                f"headers: {dict(resp.request.headers)}\n"
            ).encode("utf-8", errors="replace")

            resp_bytes = (
                f"HTTP {resp.status_code}\n"
                f"headers: {dict(resp.headers)}\n\n"
                + resp.text[:65536]
            ).encode("utf-8", errors="replace")

            req_path = out_dir / f"{stem}.req"
            resp_path = out_dir / f"{stem}.resp"
            req_path.write_bytes(req_bytes)
            resp_path.write_bytes(resp_bytes)

            # SHA-256 sidecar
            try:
                from network_pipeline.tools.integrity import write_sidecar, sha256_file
                sidecar = write_sidecar(
                    source_path=resp_path,
                    workspace=self._workspace,
                    argv_path=req_path,
                    kind="http-response",
                )
                if sidecar is not None and self._evidence_chain is not None:
                    payload = sha256_file(resp_path)
                    if payload:
                        self._evidence_chain.add_sidecar_leaf(
                            sidecar_path=sidecar,
                            content_sha256=payload,
                            ts=datetime.now(timezone.utc).isoformat(),
                            kind="http-response",
                        )
            except Exception as e:
                log.debug("evidence sidecar failed: %s", e)

        except Exception as e:
            log.debug("evidence capture failed: %s", e)


# ── DNSClient ──────────────────────────────────────────────────────────────────


class DNSClient:
    """dnspython-based resolver with evidence capture.

    Default nameservers: 8.8.8.8 + 1.1.1.1 to bypass corporate split-horizon DNS.
    Operator can override via nameservers kwarg.
    """

    def __init__(
        self,
        scope: ScopeGuard | None = None,
        evidence_chain: "EvidenceChain | None" = None,
        *,
        nameservers: list[str] | None = None,
        workspace: Path | None = None,
    ) -> None:
        self._scope = scope or ScopeGuard()
        self._evidence_chain = evidence_chain
        self._workspace = workspace
        self._nameservers = nameservers or ["8.8.8.8", "1.1.1.1"]
        self._resolver = self._build_resolver()

    def _build_resolver(self) -> Any:
        try:
            import dns.resolver
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = self._nameservers
            r.timeout = 5.0
            r.lifetime = 10.0
            return r
        except ImportError:
            log.warning("dnspython not installed — DNS resolution will be limited")
            return None

    async def resolve(
        self,
        domain: str,
        rdtype: str = "A",
    ) -> list[str]:
        """Resolve a DNS record type; returns list of string values."""
        if not self._scope.allows(domain):
            return []
        if self._resolver is None:
            return await self._fallback_resolve(domain)
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None, lambda: self._resolver.resolve(domain, rdtype)
            )
            answers = [r.to_text() for r in result]
            self._capture_dns(domain, rdtype, answers)
            return answers
        except Exception as e:
            log.debug("DNS resolve %s %s: %s", rdtype, domain, e)
            return []

    async def _fallback_resolve(self, domain: str) -> list[str]:
        """Socket-based A record fallback when dnspython not available."""
        import socket
        loop = asyncio.get_event_loop()
        try:
            info = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
            return list({i[4][0] for i in info})
        except Exception:
            return []

    def _capture_dns(self, domain: str, rdtype: str, answers: list[str]) -> None:
        if not self._workspace:
            return
        try:
            out_dir = self._workspace / "tool_io" / "dns"
            out_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            rec = f"{ts} {rdtype} {domain}: {', '.join(answers)}\n"
            log_path = out_dir / "dns_queries.log"
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write(rec)
        except Exception:
            pass


# ── TCPConnectProbe ────────────────────────────────────────────────────────────


@dataclass
class PortResult:
    host: str
    port: int
    open: bool
    banner: str = ""
    duration_ms: float = 0.0


class TCPConnectProbe:
    """Pure-Python TCP connect-scan with banner-grab.

    This is the *runtime primitive* — not the public-facing PortScanner class
    (scanners/port_scan.py). PortScanner composes TCPConnectProbe.
    """

    def __init__(
        self,
        scope: ScopeGuard | None = None,
        callback_profile: "CallbackProfile | None" = None,
        *,
        concurrency: int = 200,
        timeout: float = 2.0,
        banner_timeout: float = 1.0,
    ) -> None:
        self._scope = scope or ScopeGuard()
        self._callback_profile = callback_profile
        self._concurrency = concurrency
        self._timeout = timeout
        self._banner_timeout = banner_timeout

    async def scan_ports(
        self,
        host: str,
        ports: list[int],
    ) -> list[PortResult]:
        """Scan a list of ports; return only open ones with banners."""
        if not self._scope.allows(host):
            log.warning("TCPConnectProbe: scope denied %s", host)
            return []

        sem = asyncio.Semaphore(self._concurrency)
        tasks = [self._probe_one(host, p, sem) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, PortResult) and r.open]

    async def _probe_one(
        self,
        host: str,
        port: int,
        sem: asyncio.Semaphore,
    ) -> PortResult:
        async with sem:
            t0 = time.monotonic()
            try:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self._timeout,
                )
                banner = ""
                try:
                    data = await asyncio.wait_for(r.read(256), timeout=self._banner_timeout)
                    banner = data.decode("utf-8", errors="replace").strip()[:200]
                except asyncio.TimeoutError:
                    pass
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return PortResult(
                    host=host,
                    port=port,
                    open=True,
                    banner=banner,
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return PortResult(host=host, port=port, open=False,
                                  duration_ms=(time.monotonic() - t0) * 1000)


# ── Browser session factory ────────────────────────────────────────────────────


def get_browser_session() -> Any:
    """Lazy-import and return a BrowserSession from browser/playwright_session.py.

    This is the only definition of get_browser_session — all code imports from here.
    Raises BrowserUnavailable if playwright is not installed.
    """
    from network_pipeline.browser.playwright_session import BrowserSession
    return BrowserSession()


def is_browser_available() -> bool:
    """Return True if playwright is importable."""
    import importlib.util
    return importlib.util.find_spec("playwright") is not None


# ── Engagement-loop registration (sync@tool to async scanner bridge) ─
#
# LangGraph runs sync @tool functions in a worker thread via
# asyncio.to_thread. From inside that thread we have NO running loop
# but the HTTPClient/DNSClient/OASTClient are all bound to the engagement
# loop on the main thread. Calling loop.run_until_complete on a fresh
# loop in the worker thread leaves the original coroutine un-awaited
# (the symptom: "RuntimeWarning: coroutine X was never awaited" and
# zero findings).
#
# Fix: EngagementLoop.run() registers its loop here at startup.
# Every sync @tool wraps its scanner coroutine with
# run_on_engagement_loop(coro) which uses
# asyncio.run_coroutine_threadsafe — the canonical, deadlock-free way to
# schedule a coroutine on an event loop running in another thread and
# block until the result is available.

_ENGAGEMENT_LOOP: "asyncio.AbstractEventLoop | None" = None


def set_engagement_loop(loop: "asyncio.AbstractEventLoop | None") -> None:
    """Called by EngagementLoop.run() to publish its loop."""
    global _ENGAGEMENT_LOOP
    _ENGAGEMENT_LOOP = loop


def get_engagement_loop() -> "asyncio.AbstractEventLoop | None":
    return _ENGAGEMENT_LOOP


def run_on_engagement_loop(coro: Any, *, timeout: float = 300.0) -> Any:
    """Run an async coroutine from a sync @tool and return its result.

    - If an engagement loop is registered AND running on another thread,
      schedule via run_coroutine_threadsafe and block.
    - Otherwise fall back to a fresh loop on this thread (CLI/test).
    - On TimeoutError, cancels the future and re-raises.
    """
    main_loop = _ENGAGEMENT_LOOP
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None

    if main_loop is not None and main_loop.is_running() and main_loop is not running:
        import concurrent.futures as _cf
        fut = asyncio.run_coroutine_threadsafe(coro, main_loop)
        try:
            return fut.result(timeout=timeout)
        except _cf.TimeoutError:
            fut.cancel()
            raise TimeoutError(
                f"scanner coroutine timed out after {timeout:.0f}s",
            )

    new_loop = asyncio.new_event_loop()
    try:
        return new_loop.run_until_complete(coro)
    finally:
        try:
            new_loop.close()
        except Exception:  # noqa: BLE001
            pass
