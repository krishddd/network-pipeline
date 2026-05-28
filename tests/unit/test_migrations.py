"""Tests for core.migrations — lazy v1→v2 schema upgrades."""

from __future__ import annotations

import json
from pathlib import Path


def test_migrate_opplan_v1_adds_seed_and_budget():
    from network_pipeline.core.migrations import (
        CURRENT_OPPLAN_VERSION, migrate_opplan_payload,
    )

    legacy = {
        "engagement_name": "old",
        "version": "1.0",
        "objectives": [
            {"id": "OBJ-1", "phase": "recon", "title": "x",
             "description": "y", "priority": 10},
        ],
    }
    out = migrate_opplan_payload(legacy)
    assert out["version"] == CURRENT_OPPLAN_VERSION
    assert "seed" in out
    assert "budget" in out
    obj = out["objectives"][0]
    assert obj["retries"] == 0
    assert obj["max_retries"] == 3
    assert obj["retry_hints"] == []
    assert obj["synthesized_from"] is None


def test_migrate_opplan_idempotent():
    from network_pipeline.core.migrations import (
        CURRENT_OPPLAN_VERSION, migrate_opplan_payload,
    )

    payload = {"version": CURRENT_OPPLAN_VERSION, "engagement_name": "x"}
    assert migrate_opplan_payload(payload) is payload


def test_migrate_roe_adds_mode_field():
    from network_pipeline.core.migrations import migrate_roe_payload

    legacy = {
        "engagement_name": "x",
        "in_scope": [{"target": "example.com", "type": "domain"}],
        "out_of_scope": [{"target": "off.example.com", "type": "domain"}],
    }
    out = migrate_roe_payload(legacy)
    assert out["in_scope"][0]["mode"] == "normal"
    assert out["out_of_scope"][0]["mode"] == "normal"


def test_load_json_with_migration_returns_none_for_missing(tmp_path: Path):
    from network_pipeline.core.migrations import load_json_with_migration

    assert load_json_with_migration(tmp_path / "nope.json", "opplan") is None


def test_migrated_opplan_validates_against_pydantic(tmp_path: Path):
    from network_pipeline.core.migrations import load_json_with_migration
    from network_pipeline.core.schemas import OPPLAN

    legacy = {
        "engagement_name": "old",
        "version": "1.0",
        "objectives": [
            {"id": "OBJ-1", "phase": "recon", "title": "x",
             "description": "y", "priority": 10},
        ],
    }
    p = tmp_path / "opplan.json"
    p.write_text(json.dumps(legacy))
    payload = load_json_with_migration(p, "opplan")
    assert payload is not None
    # Validates without raising — defaults filled in
    OPPLAN.model_validate(payload)
