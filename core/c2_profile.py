"""Mythic-style callback profiles (Plan B.3.1).

Real C2 frameworks defeat correlation by jittering the time between
callbacks, rotating User-Agent strings, and interleaving decoy traffic
to other in-scope targets. This module gives the engagement loop a way
to apply the same shaping to every subprocess invocation.

A ``CallbackProfile`` is loaded from one of three built-in YAMLs:

* ``stealth``  — sleep 30 s base / ±30 % jitter / UA pool of 10 / 3 decoys
* ``balanced`` — sleep 5 s / ±20 % / UA pool of 5 / 1 decoy
* ``loud``     — sleep 0 / ±0 % / no decoys (Phase-1 default behaviour)

The profile is consulted by ``ShellRunner.run`` before each spawn:

1. ``apply_pacing()`` sleeps ``sleep_s + uniform(-jitter, +jitter)``.
2. ``user_agent()`` returns a UA string sampled from the pool (with
   ``random.choice`` — ``core.seed.seed_all`` makes that deterministic).
3. ``decoy_targets`` is exposed so the engagement loop can fire
   no-op curl probes between real tool calls.

The profile is read-only at runtime — built once per engagement and
attached to the ShellRunner. Switching profiles mid-engagement
requires a CLI re-run.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from pathlib import Path

from network_pipeline.core.logging import get_logger

log = get_logger("core.c2_profile")


# Default UA pool — diverse browsers + a couple of bot UAs so a
# stealth profile against a permissive target still looks varied.
_DEFAULT_UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
)


@dataclass
class CallbackProfile:
    """One operational profile applied to every subprocess invocation."""

    name: str = "loud"
    sleep_s: float = 0.0
    jitter_pct: float = 0.0          # 0..1 fraction (0.30 = ±30 %)
    user_agents: tuple[str, ...] = ()
    decoy_targets: tuple[str, ...] = ()
    extra_headers: dict[str, str] = field(default_factory=dict)
    request_pacing: str = "burst"    # burst | steady | nightly

    # Tracks whether we've issued at least one request — pacing
    # applies BETWEEN requests, not before the first. Otherwise
    # ``stealth`` (30s sleep) deadlocks any scanner whose timeout
    # is also 30s — the very first request can never start.
    _has_paced: bool = field(default=False, repr=False, compare=False)

    # ── runtime helpers ────────────────────────────────────────────

    def _compute_pacing(self) -> float:
        """Pure: compute the next pacing duration. No sleep performed."""
        if self.sleep_s <= 0:
            return 0.0
        spread = self.sleep_s * max(0.0, min(1.0, self.jitter_pct))
        delta = random.uniform(-spread, spread) if spread > 0 else 0.0
        return max(0.0, self.sleep_s + delta)

    def apply_pacing(self) -> float:
        """Sync sleep for ``sleep_s ± jitter``. Returns seconds slept.

        First call returns 0 immediately (pacing applies BETWEEN
        requests, not before the first). Subsequent calls sleep.

        WARNING: this blocks the asyncio event loop. Async code must
        call ``apply_pacing_async`` instead.
        """
        if not self._has_paced:
            self._has_paced = True
            return 0.0
        wait = self._compute_pacing()
        if wait > 0:
            time.sleep(wait)
        return wait

    async def apply_pacing_async(self) -> float:
        """Async pacing — yields to the event loop while waiting.

        First call returns 0 immediately. This avoids a deadlock where
        ``stealth`` (sleep_s=30) starves any scanner with a 30s timeout
        — the first request can never even begin. Subsequent calls
        pace BETWEEN requests as intended.
        """
        if not self._has_paced:
            self._has_paced = True
            return 0.0
        wait = self._compute_pacing()
        if wait > 0:
            import asyncio
            await asyncio.sleep(wait)
        return wait

    def user_agent(self) -> str | None:
        """Pick a UA string for this call, or None when no UA rotation."""
        pool = self.user_agents or ()
        if not pool:
            return None
        return random.choice(pool)

    def header_args(self) -> list[str]:
        """Return curl-style ``-H header:value`` argv fragments.

        Combines ``extra_headers`` with a chosen User-Agent. Used by
        web wrappers that delegate to ``run_curl`` so the same headers
        flow through every authenticated probe.
        """
        out: list[str] = []
        ua = self.user_agent()
        if ua:
            out.extend(["-H", f"User-Agent: {ua}"])
        for k, v in self.extra_headers.items():
            out.extend(["-H", f"{k}: {v}"])
        return out

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"CallbackProfile(name={self.name!r}, sleep_s={self.sleep_s}, "
            f"jitter_pct={self.jitter_pct}, ua_pool={len(self.user_agents)}, "
            f"decoys={len(self.decoy_targets)})"
        )


# ── Loader ────────────────────────────────────────────────────────────


_BUILTIN_PROFILE_DIR = (
    Path(__file__).resolve().parent.parent / "skills" / "profiles"
)


# Hard-coded fallbacks so ``stealth`` / ``balanced`` / ``loud`` resolve
# even when PyYAML is missing or the YAML files are deleted.
_BUILTIN_FALLBACKS: dict[str, CallbackProfile] = {
    "loud": CallbackProfile(name="loud"),
    "balanced": CallbackProfile(
        name="balanced",
        sleep_s=5.0,
        jitter_pct=0.20,
        user_agents=tuple(_DEFAULT_UA_POOL),
    ),
    "stealth": CallbackProfile(
        name="stealth",
        sleep_s=30.0,
        jitter_pct=0.30,
        user_agents=tuple(_DEFAULT_UA_POOL),
        request_pacing="steady",
    ),
}


def builtin_profile_dir() -> Path:
    return _BUILTIN_PROFILE_DIR


def load_callback_profile(name_or_path: str | Path) -> CallbackProfile:
    """Resolve a profile by built-in name or YAML path.

    Built-in names (``stealth`` / ``balanced`` / ``loud``) are looked
    up in ``network_pipeline/skills/profiles``; if PyYAML or the file
    isn't available, we fall back to the hard-coded defaults above so
    the pipeline never crashes on a missing profile.
    """
    p = Path(name_or_path)
    if not p.is_absolute() and not p.exists():
        candidate = _BUILTIN_PROFILE_DIR / f"{p}.yaml"
        if candidate.exists():
            p = candidate
        else:
            candidate = _BUILTIN_PROFILE_DIR / p
            if candidate.exists():
                p = candidate
    if not p.exists():
        # Built-in fallback by name
        key = str(name_or_path).strip().lower()
        if key in _BUILTIN_FALLBACKS:
            log.info("c2_profile %r resolved from built-in fallback", key)
            return _BUILTIN_FALLBACKS[key]
        raise FileNotFoundError(f"callback profile not found: {name_or_path!r}")

    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        # PyYAML missing: fall back to hard-coded built-in if the name matches.
        key = p.stem.lower()
        if key in _BUILTIN_FALLBACKS:
            log.warning("PyYAML missing; using built-in fallback for %s", key)
            return _BUILTIN_FALLBACKS[key]
        raise RuntimeError(
            "PyYAML is required to load custom callback profiles. "
            "`pip install pyyaml` or pick a built-in name."
        )

    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{p}: callback profile root must be a mapping")
    return CallbackProfile(
        name=str(raw.get("name", p.stem)),
        sleep_s=float(raw.get("sleep_s", 0.0)),
        jitter_pct=float(raw.get("jitter_pct", 0.0)),
        user_agents=tuple(raw.get("user_agents", _DEFAULT_UA_POOL)),
        decoy_targets=tuple(raw.get("decoy_targets", ())),
        extra_headers=dict(raw.get("extra_headers", {})),
        request_pacing=str(raw.get("request_pacing", "burst")),
    )
