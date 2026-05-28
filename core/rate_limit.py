"""Per-(binary, target-host) rate limiter (Plan B.4.1).

The shell runner enforces a per-call timeout but no aggregate request
rate. A misbehaving model can fire 100 nmap scans in 10 s and trip the
target's WAF / IDS even when each individual call is "small". This
module is the back-pressure: a token bucket per ``(binary, target)``
keyed in memory.

Buckets are configured via ``RateLimitRegistry.set_rate(binary, rps,
burst)``. The CLI accepts a ``--rate <binary>:<rps>`` flag which the
engagement bootstrap forwards to the registry. Defaults below
preserve current behaviour (effectively unlimited) so the addition is
backward-compatible.

The acquire path is *blocking* — it sleeps for the time required for a
token to materialise. We intentionally do NOT abort the call: the agent
already has callback-profile sleeps for stealth, and a refusal here
would surface as a confusing error rather than the natural pacing it
was meant to be.
"""

from __future__ import annotations

import threading
import time
import urllib.parse
from dataclasses import dataclass

from network_pipeline.core.logging import get_logger

log = get_logger("core.rate_limit")


# Default: very permissive. Real values are pushed in via CLI.
_DEFAULT_RATE_RPS = 50.0
_DEFAULT_BURST = 50


def host_of(target: str) -> str:
    """Extract the host portion of a target string for keying buckets.

    Accepts URLs, host:port, bare hostnames, and CIDRs. Returns the
    canonical lowercase host. CIDRs are returned as-is so all calls
    against ``10.0.0.0/8`` share one bucket.
    """
    t = (target or "").strip().rstrip("/")
    if not t:
        return "_empty"
    if "://" in t:
        try:
            parsed = urllib.parse.urlparse(t)
            host = parsed.hostname or t
        except ValueError:
            host = t
    else:
        host = t.split("/")[0].split(":", 1)[0]
    return host.lower()


@dataclass
class _Bucket:
    """Token-bucket rate limiter for one (binary, host) pair."""

    rate_rps: float
    burst: int
    tokens: float = 0.0
    last_refill: float = 0.0

    def __post_init__(self) -> None:
        self.tokens = float(self.burst)
        self.last_refill = time.monotonic()

    def reserve(self, cost: float = 1.0) -> float:
        """Reserve ``cost`` tokens; return seconds the caller must wait.

        Pure book-keeping — does NOT sleep. The caller is responsible
        for sleeping ``wait_s`` seconds (sync or async, their choice)
        BEFORE issuing the rate-limited request. This split exists so
        the sleep can happen OUTSIDE any lock / event-loop critical
        section (the old in-bucket ``time.sleep`` blocked the asyncio
        loop and starved every concurrent request).
        """
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate_rps)
        self.last_refill = now
        if self.tokens >= cost:
            self.tokens -= cost
            return 0.0
        deficit = cost - self.tokens
        wait_s = deficit / self.rate_rps if self.rate_rps > 0 else 0.0
        # Clamp at 60 s — never wait longer than a minute on a single
        # acquire; if the cap is that low the operator should raise it.
        wait_s = min(60.0, max(0.0, wait_s))
        # Pre-debit: the next request will refill from `last_refill`,
        # so we record that we've consumed our quota now.
        self.tokens = 0.0
        self.last_refill = now + wait_s  # account for the upcoming wait
        return wait_s

    # Backward-compat alias kept for existing sync callers.
    def acquire(self, cost: float = 1.0) -> float:
        wait_s = self.reserve(cost)
        if wait_s > 0:
            time.sleep(wait_s)
        return wait_s


class RateLimitRegistry:
    """Cross-runner registry of token-buckets keyed by (binary, host)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        # Global per-binary defaults (rate, burst) — used when no
        # specific (binary, host) bucket has been created yet.
        self._defaults: dict[str, tuple[float, int]] = {}

    def set_rate(self, binary: str, rps: float, burst: int | None = None) -> None:
        """Configure the default token rate for a binary.

        Existing buckets for this binary are reset so the new rate
        takes effect immediately. Pass ``rps <= 0`` to remove the cap.
        """
        if rps <= 0:
            self._defaults.pop(binary, None)
            with self._lock:
                for key in list(self._buckets):
                    if key[0] == binary:
                        self._buckets.pop(key, None)
            return
        b = burst if burst is not None else max(1, int(rps))
        self._defaults[binary] = (float(rps), int(b))
        with self._lock:
            for key, bucket in list(self._buckets.items()):
                if key[0] == binary:
                    bucket.rate_rps = float(rps)
                    bucket.burst = int(b)
                    bucket.tokens = min(bucket.tokens, float(b))
        log.info("rate cap set: %s = %.1f rps (burst %d)", binary, rps, b)

    def configure(self, mapping: dict[str, float]) -> None:
        """Bulk-configure: ``{"nmap": 1.0, "nuclei": 0.5}``."""
        for binary, rps in mapping.items():
            self.set_rate(binary, rps)

    def acquire(self, binary: str, target: str) -> float:
        """Sync acquire — blocks via time.sleep. Use ONLY from sync code.

        Async callers must use ``acquire_async`` instead, which awaits
        ``asyncio.sleep`` outside the registry lock so the event loop
        keeps running and ``asyncio.wait_for`` timeouts can fire.
        """
        if binary not in self._defaults:
            return 0.0
        wait_s = self._reserve(binary, target)
        if wait_s > 0:
            time.sleep(wait_s)
            log.debug("rate limited (sync): %s slept %.2fs", binary, wait_s)
        return wait_s

    async def acquire_async(self, binary: str, target: str) -> float:
        """Async acquire — non-blocking; the event loop continues.

        Critical fix: the previous implementation called ``time.sleep``
        inside ``HTTPClient._request``, freezing the entire asyncio loop
        whenever ANY scanner needed to wait for a rate-limit token.
        That made ``asyncio.wait_for`` timeouts overshoot by 3-5x and
        serialised every "parallel" scanner.
        """
        if binary not in self._defaults:
            return 0.0
        wait_s = self._reserve(binary, target)
        if wait_s > 0:
            import asyncio
            await asyncio.sleep(wait_s)
            log.debug("rate limited (async): %s slept %.2fs", binary, wait_s)
        return wait_s

    def _reserve(self, binary: str, target: str) -> float:
        """Compute wait time under lock, but DO NOT sleep here.

        Releasing the lock before sleeping is what unblocks concurrent
        scanners on different (binary, host) pairs.
        """
        host = host_of(target)
        key = (binary, host)
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                rate_rps, burst = self._defaults[binary]
                bucket = _Bucket(rate_rps=rate_rps, burst=burst)
                self._buckets[key] = bucket
            return bucket.reserve()

    def reset(self) -> None:
        """Forget all buckets and configured rates. For tests."""
        with self._lock:
            self._buckets.clear()
        self._defaults.clear()


# Module-level shared registry. Engagements create their own
# ``ShellRunner`` per workspace, but rate limits are process-wide so a
# resumed engagement keeps the same caps.
GLOBAL_RATE_LIMITS = RateLimitRegistry()


def parse_rate_flag(value: str) -> tuple[str, float]:
    """Parse a CLI ``--rate <binary>:<rps>`` value into a tuple.

    Raises ``ValueError`` on malformed input — Click surfaces that
    cleanly to the user.
    """
    if ":" not in value:
        raise ValueError(f"--rate expects 'binary:rps', got {value!r}")
    binary, _, rps = value.partition(":")
    binary = binary.strip()
    if not binary:
        raise ValueError(f"--rate binary name empty in {value!r}")
    try:
        rps_f = float(rps)
    except ValueError as e:
        raise ValueError(f"--rate rps not a number in {value!r}") from e
    if rps_f < 0:
        raise ValueError(f"--rate rps must be >= 0 in {value!r}")
    return binary, rps_f
