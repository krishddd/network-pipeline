"""Per-provider exponential backoff with jitter for cloud LLMs.

Wraps `ainvoke` calls so the Phase-3 CoP Dual-Judge and Phase-4 HRL
trajectory loops don't trip 429/529/503 rate limits. Ollama does not
need this — it has the process-local `_INFERENCE_LOCK` instead.

If `tenacity` is not installed (lightweight installs may skip it), the
wrapper degrades to a hand-rolled retry loop with the same semantics.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any, Awaitable, Callable, TypeVar

from network_pipeline.core.logging import get_logger
from network_pipeline.llm.profiles import Provider

log = get_logger("llm.ratelimit")

T = TypeVar("T")

# Tunable knobs (kept in-file rather than config so a runaway loop can't
# turn retries off remotely).
_MAX_ATTEMPTS = 5
_BASE_SECONDS = 2.0
_MAX_SECONDS = 60.0


def _is_retryable(exc: BaseException) -> bool:
    """True for 429/529/503 and transient network errors."""
    # We avoid importing provider SDKs here. Match by class name and any
    # `status_code` attribute.
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if status in (408, 425, 429, 500, 502, 503, 504, 529):
        return True
    name = type(exc).__name__.lower()
    retryable_names = (
        "ratelimit", "overload", "timeout", "apitimeout", "apiconnection",
        "serviceunavailable", "internalserver",
    )
    return any(token in name for token in retryable_names)


def _backoff_seconds(attempt: int) -> float:
    """Full-jitter exponential backoff: random(0, min(MAX, BASE * 2^attempt))."""
    cap = min(_MAX_SECONDS, _BASE_SECONDS * (2 ** attempt))
    return random.uniform(0, cap)


async def with_retry(
    provider: Provider,
    fn: Callable[..., Awaitable[T]],
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run an async callable with exponential-backoff retry on rate limits.

    Ollama short-circuits (no retry — it has no rate limit, and a long
    Ollama call is more likely a model problem than a transient one).
    Cloud providers get up to `_MAX_ATTEMPTS` tries with full jitter.
    """
    if provider == "ollama":
        return await fn(*args, **kwargs)

    last_exc: BaseException | None = None
    for attempt in range(_MAX_ATTEMPTS):
        try:
            return await fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 — provider SDKs raise varied types
            last_exc = e
            if not _is_retryable(e) or attempt == _MAX_ATTEMPTS - 1:
                raise
            delay = _backoff_seconds(attempt)
            log.warning(
                "ratelimit/retry provider=%s attempt=%d/%d delay=%.1fs err=%s",
                provider, attempt + 1, _MAX_ATTEMPTS, delay, type(e).__name__,
            )
            await asyncio.sleep(delay)
    # Unreachable, but mypy-friendly.
    assert last_exc is not None
    raise last_exc
