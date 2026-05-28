"""CoP principle library — loader + compatibility checks + sampling.

Loads ``skills/principles/library.yaml`` into typed `Principle` objects,
enforces ``compatible_with`` pairings so the composer can't accidentally
glue two personas together (a coherence breaker), and provides a
deterministic sampler so test runs are reproducible under
``--seed``.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from functools import lru_cache
from itertools import combinations
from pathlib import Path
from typing import Iterable, Literal

import yaml


PrincipleKind = Literal["persona", "pretext", "encoding", "format", "urgency"]
CollusionRisk = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class Principle:
    name: str
    kind: PrincipleKind
    description: str
    template: str
    compatible_with: frozenset[str]  # kinds, not names
    collusion_risk: CollusionRisk


# Default library path. Tests can pass a custom path to `load_library`.
_DEFAULT_LIBRARY = (
    Path(__file__).resolve().parent.parent / "skills" / "principles" / "library.yaml"
)


class PrinciplesError(RuntimeError):
    """Raised on malformed library or invalid composition request."""


@lru_cache(maxsize=4)
def load_library(path: str | None = None) -> tuple[Principle, ...]:
    """Parse the YAML library; cache by resolved path."""
    p = Path(path) if path else _DEFAULT_LIBRARY
    if not p.exists():
        raise PrinciplesError(f"principle library not found: {p}")

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PrinciplesError(f"YAML parse error in {p}: {e}") from e

    if not isinstance(raw, dict) or "principles" not in raw:
        raise PrinciplesError(f"{p} must contain a top-level `principles:` list")

    out: list[Principle] = []
    seen: set[str] = set()
    valid_kinds = {"persona", "pretext", "encoding", "format", "urgency"}
    valid_risk = {"low", "medium", "high"}

    for entry in raw["principles"]:
        for required in ("name", "kind", "description", "template", "compatible_with"):
            if required not in entry:
                raise PrinciplesError(f"principle missing `{required}`: {entry}")
        name = entry["name"]
        if name in seen:
            raise PrinciplesError(f"duplicate principle name: {name}")
        seen.add(name)
        if entry["kind"] not in valid_kinds:
            raise PrinciplesError(f"{name}: invalid kind {entry['kind']!r}")
        compat = frozenset(entry["compatible_with"])
        bad = compat - valid_kinds
        if bad:
            raise PrinciplesError(f"{name}: unknown kinds in compatible_with: {bad}")
        risk = entry.get("collusion_risk", "low")
        if risk not in valid_risk:
            raise PrinciplesError(f"{name}: invalid collusion_risk {risk!r}")
        out.append(Principle(
            name=name,
            kind=entry["kind"],
            description=entry["description"].strip(),
            template=entry["template"],
            compatible_with=compat,
            collusion_risk=risk,
        ))
    if not out:
        raise PrinciplesError(f"{p}: library is empty")
    return tuple(out)


def is_compatible(a: Principle, b: Principle) -> bool:
    """True if `a` allows kind-of-`b` and `b` allows kind-of-`a`."""
    return b.kind in a.compatible_with and a.kind in b.compatible_with


def is_compatible_set(principles: Iterable[Principle]) -> bool:
    """True if every pair in the set is mutually compatible AND no two
    share the same kind (no double-persona, no double-pretext, etc.)."""
    items = list(principles)
    kinds = [p.kind for p in items]
    if len(set(kinds)) != len(kinds):
        return False
    for a, b in combinations(items, 2):
        if not is_compatible(a, b):
            return False
    return True


def sample_compositions(
    *,
    size: int = 3,
    count: int = 5,
    library_path: str | None = None,
    seed: int | None = None,
    require_kinds: Iterable[PrincipleKind] | None = None,
    avoid_high_collusion: bool = False,
) -> list[tuple[Principle, ...]]:
    """Return up to `count` distinct compatible compositions of `size` principles.

    Args:
      size: principles per composition (the CoP paper used 2-3).
      count: how many compositions to return.
      library_path: override default library.
      seed: reproducibility — seeds the local Random instance.
      require_kinds: composition must include at least one principle of
        every named kind (e.g. ['persona', 'pretext']).
      avoid_high_collusion: skip principles tagged collusion_risk=high.
        Used by the judge when the composer + judge providers can't be
        properly diversified.

    Raises:
      PrinciplesError when `size` is impossible (e.g. size=3 but library
      has only 2 compatible kinds).
    """
    library = list(load_library(library_path))
    if avoid_high_collusion:
        library = [p for p in library if p.collusion_risk != "high"]

    required = set(require_kinds or [])
    if size < 1 or size > 5:
        raise PrinciplesError(f"size must be in [1, 5], got {size}")

    rng = random.Random(seed)
    pool = list(library)
    rng.shuffle(pool)

    valid: list[tuple[Principle, ...]] = []
    seen_sigs: set[tuple[str, ...]] = set()

    # Enumerate combinations deterministically given the shuffled pool;
    # break early once we have `count`.
    for combo in combinations(pool, size):
        if not is_compatible_set(combo):
            continue
        if required and not required.issubset({p.kind for p in combo}):
            continue
        sig = tuple(sorted(p.name for p in combo))
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)
        valid.append(combo)
        if len(valid) >= count:
            break

    if not valid:
        raise PrinciplesError(
            f"no compatible compositions of size {size} found "
            f"(require_kinds={required}, avoid_high_collusion={avoid_high_collusion})"
        )
    return valid


def compose_payload(
    principles: Iterable[Principle],
    *,
    intent: str,
    target: str = "",
    vuln_class: str = "",
    **extra: str,
) -> str:
    """Render principles' templates in declaration order, threading
    {intent} / {target} / {vuln_class} / **extra through each.

    Each template is rendered independently; the outputs are joined
    with two newlines. The composer relies on this deterministic
    behaviour for cache-friendly judging.
    """
    pieces: list[str] = []
    fmt = {"intent": intent, "target": target, "vuln_class": vuln_class, **extra}
    for p in principles:
        try:
            pieces.append(p.template.format(**fmt))
        except KeyError as e:
            # Missing variable — fall back to leaving the placeholder
            # literal so the operator can see what's unfilled.
            fallback = dict(fmt)
            for key in (str(e).strip("'"),):
                fallback[key] = "{" + key + "}"
            pieces.append(p.template.format(**fallback))
    return "\n\n".join(pieces)


__all__ = [
    "CollusionRisk",
    "Principle",
    "PrincipleKind",
    "PrinciplesError",
    "compose_payload",
    "is_compatible",
    "is_compatible_set",
    "load_library",
    "sample_compositions",
]
