"""Reproducibility seed (Plan B.4.5).

Single entry point ``seed_all(seed)`` that:

* Seeds Python's ``random`` module so jitter / decoy choice / random
  retry-hint selection are deterministic.
* Sets ``PYTHONHASHSEED`` in the process environment so dict / set
  iteration order is stable across runs (matters for KG-delta
  comparisons in tests).
* Returns the seed for downstream consumers (CLI prints it; engagement
  state stamps it; ``OllamaLLMFactory`` forwards it via ``options.seed``
  to ChatOllama so the same prompts produce the same completions).

This is intentionally tiny — most reproducibility wiring happens at the
call sites (factory, shell, c2_profile). Centralising the seed_all
helper means a single audit point for "did we seed everything?".
"""

from __future__ import annotations

import os
import random

from network_pipeline.core.logging import get_logger

log = get_logger("core.seed")


# Module-level cache so consumers can ``current_seed()`` without
# threading the seed through every call. None ⇒ never seeded.
_CURRENT_SEED: int | None = None


def seed_all(seed: int | None) -> int | None:
    """Seed all known sources of randomness for this process.

    No-op when ``seed`` is None — preserves existing non-deterministic
    behaviour for users who don't pass ``--seed``.
    """
    global _CURRENT_SEED
    if seed is None:
        _CURRENT_SEED = None
        return None
    if not isinstance(seed, int):
        raise TypeError(f"seed must be int or None, got {type(seed).__name__}")
    random.seed(seed)
    # PYTHONHASHSEED only takes effect for child processes (subprocess /
    # spawned workers). The parent's hash randomisation is fixed at
    # interpreter startup; we set the env var so every spawned tool
    # subprocess inherits a stable hash seed.
    os.environ["PYTHONHASHSEED"] = str(seed)
    _CURRENT_SEED = seed
    log.info("seeded all RNGs with seed=%d", seed)
    return seed


def current_seed() -> int | None:
    """Return the active seed, or None if ``seed_all`` was never called."""
    return _CURRENT_SEED
