"""Dynamic agent registry — auto-discovers sub-agent factories at import time.

Rather than hard-coding ``_AGENT_FACTORIES`` in ``engagement_loop.py``,
each sub-agent module in ``network_pipeline/agents/`` can declare:

* ``AGENT_ROLE: str`` — short role name (matches the prompt filename).
* ``SUPPORTED_PHASES: tuple[ObjectivePhase, ...]`` — phases routed here.
* ``create_<role>_agent(**kwargs)`` — the factory callable.

The registry scans the ``agents/`` directory once, imports each module,
and collects everything that satisfies that contract. Third parties can
drop ``agents/my_agent.py`` alongside the built-ins and it will be
picked up on the next run.

Modules without the declarations are ignored, so ``orchestrator``,
``verifier``, ``analyst``, and ``defender`` (which are not routed by
phase) remain invisible to the registry — they have their own
entry points via the engagement loop's vaccine phase and the ``task``
dispatcher.
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Callable

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import ObjectivePhase

log = get_logger("agents.registry")


# Keyed by ObjectivePhase → (role_name, factory_callable).
# Populated lazily on first call to ``discover()``.
_REGISTRY: dict[ObjectivePhase, tuple[str, Callable]] = {}
_DISCOVERED = False


def discover(force: bool = False) -> dict[ObjectivePhase, tuple[str, Callable]]:
    """Scan ``network_pipeline.agents.*`` for modules that opt in to routing.

    Returns a ``phase -> (role, factory)`` mapping. Safe to call multiple
    times — subsequent calls are no-ops unless ``force=True``.
    """
    global _DISCOVERED
    if _DISCOVERED and not force:
        return _REGISTRY
    _REGISTRY.clear()
    pkg_path = Path(__file__).parent
    pkg_name = "network_pipeline.agents"

    for mod_info in pkgutil.iter_modules([str(pkg_path)]):
        if mod_info.ispkg:
            continue
        # Skip private modules and the orchestrator (it has its own path).
        if mod_info.name.startswith("_"):
            continue
        if mod_info.name in ("orchestrator", "registry"):
            continue
        try:
            mod = importlib.import_module(f"{pkg_name}.{mod_info.name}")
        except ImportError as e:  # pragma: no cover - missing deps
            log.warning("registry: could not import %s: %r", mod_info.name, e)
            continue

        role = getattr(mod, "AGENT_ROLE", None)
        phases = getattr(mod, "SUPPORTED_PHASES", None)
        factory_name = f"create_{role}_agent" if role else None
        factory = getattr(mod, factory_name, None) if factory_name else None

        if not role or not phases or factory is None:
            # Module doesn't opt into phase-routing — that's fine, it
            # may still be used elsewhere (analyst/defender/verifier).
            continue

        for phase in phases:
            if phase in _REGISTRY:
                log.warning(
                    "registry: %s replaced by %s for phase %s",
                    _REGISTRY[phase][0], role, phase.value,
                )
            _REGISTRY[phase] = (role, factory)
            log.debug("registry: %s → %s", phase.value, role)

    _DISCOVERED = True
    return _REGISTRY


def get_factory(phase: ObjectivePhase) -> tuple[str, Callable] | None:
    """Return ``(role, factory)`` for a phase, or None if unmapped."""
    reg = discover()
    return reg.get(phase)
