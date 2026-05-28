"""Lazy schema migrations for engagement state files.

Pydantic ``model_config["extra"] = "ignore"`` already handles forward-
compatibility for unknown fields. What we DO need to handle is the
backward case: a v1 ``opplan.json`` from before the Phase-1 budget /
seed additions, loaded into a v2 schema where those new fields exist
with safe defaults.

Pydantic's defaulting mostly handles this for free. The wrinkle is when
a *required* field has been renamed or has changed semantics: there we
need an explicit migration step. This module is the one place those
go, called from the load paths in ``orchestrator.load_opplan`` and
``EngagementState.load``.

Today there are no breaking field changes — every Phase-1 addition is
defaulted. So this module is mostly a placeholder + an audit log: it
records the on-disk version it saw and bumps it to the current version
so future migrations can fan out from a single anchor.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from network_pipeline.core.logging import get_logger

log = get_logger("core.migrations")


# Bump when introducing a field that requires explicit migration (not
# just a default). Anchored on string for forward-compat with semver.
CURRENT_OPPLAN_VERSION = "1.1"
CURRENT_STATE_VERSION = "1.1"


def migrate_opplan_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Mutate an OPPLAN dict to the current shape, returning it.

    Idempotent: a v1.1 doc passes through unchanged.
    """
    if not isinstance(payload, dict):
        return payload
    version = str(payload.get("version", "1.0"))
    if version == CURRENT_OPPLAN_VERSION:
        return payload

    # ── v1.0 → v1.1 ────────────────────────────────────────────────
    # Adds: seed (SeedState), budget (BudgetState), Objective.retries,
    # Objective.max_retries, Objective.retry_hints, Objective.synthesized_from
    # ScopeEntry.mode (lives in roe.json, handled by migrate_roe_payload).
    # All defaults are safe — Pydantic supplies them on validation.
    if version in ("1.0",):
        payload.setdefault("seed", {"seed": 0, "seeded": False})
        payload.setdefault("budget", {})
        for obj in payload.get("objectives", []) or []:
            if not isinstance(obj, dict):
                continue
            obj.setdefault("retries", 0)
            obj.setdefault("max_retries", 3)
            obj.setdefault("retry_hints", [])
            obj.setdefault("synthesized_from", None)
        payload["version"] = CURRENT_OPPLAN_VERSION
        log.info("migrated opplan v%s → v%s", version, CURRENT_OPPLAN_VERSION)
    return payload


def migrate_roe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Add ``ScopeEntry.mode`` defaults to legacy RoE docs."""
    if not isinstance(payload, dict):
        return payload
    for entry in payload.get("in_scope", []) or []:
        if isinstance(entry, dict):
            entry.setdefault("mode", "normal")
    for entry in payload.get("out_of_scope", []) or []:
        if isinstance(entry, dict):
            entry.setdefault("mode", "normal")
    return payload


def migrate_state_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Engagement state migration. Reserved for future field changes."""
    if not isinstance(payload, dict):
        return payload
    version = str(payload.get("version", "1.0"))
    if version == CURRENT_STATE_VERSION:
        return payload
    payload["version"] = CURRENT_STATE_VERSION
    return payload


def load_json_with_migration(path: Path, kind: str) -> dict[str, Any] | None:
    """Read + migrate one JSON document. Returns None if missing/invalid.

    ``kind`` selects the migration: ``"opplan"`` | ``"roe"`` | ``"state"``.
    """
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.error("could not read %s (%s): %r", kind, path, e)
        return None
    if kind == "opplan":
        return migrate_opplan_payload(payload)
    if kind == "roe":
        return migrate_roe_payload(payload)
    if kind == "state":
        return migrate_state_payload(payload)
    return payload
