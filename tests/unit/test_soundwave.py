"""Phase-5 tests: Soundwave interview + validate + review."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

import pytest

from network_pipeline.agents.soundwave import (
    ValidationReport,
    review_plan,
    run_interview,
    validate_plan,
)
from network_pipeline.core.schemas import (
    CONOPS,
    Deconfliction,
    Objective,
    ObjectivePhase,
    OPPLAN,
    RoE,
    SuccessOracle,
)


# ── schema round-trips ────────────────────────────────────────────────


def test_deconfliction_round_trip():
    decon = Deconfliction(
        engagement_name="acme-2026",
        source_ips=["10.1.0.0/24"],
        time_windows=["Mon-Fri 09:00-18:00 UTC"],
        shared_signature="network_pipeline-redteam/acme-2026",
    )
    blob = decon.model_dump_json()
    parsed = Deconfliction.model_validate_json(blob)
    assert parsed.shared_signature == decon.shared_signature
    assert parsed.source_ips == ["10.1.0.0/24"]


def test_roe_review_stamp_round_trip():
    roe = RoE(
        engagement_name="test",
        reviewed_by="alice",
        reviewed_at="2026-05-26T12:00:00+00:00",
        allow_destructive_writes=True,
        write_allowlist=["http://staging.example/upload"],
    )
    parsed = RoE.model_validate_json(roe.model_dump_json())
    assert parsed.reviewed_by == "alice"
    assert parsed.allow_destructive_writes is True
    assert parsed.write_allowlist == ["http://staging.example/upload"]


# ── interview (scripted prompt_fn) ────────────────────────────────────


def _scripted(answers: list[str]):
    """Return a PromptFn that pops each answer in order. Defaults on empty."""
    queue = list(answers)

    def fn(_: str) -> str:
        return queue.pop(0) if queue else ""
    return fn


def test_interview_produces_all_four_files(tmp_path: Path):
    ws = tmp_path / "eng"
    ws.mkdir()
    # Provide exactly the inputs the interview asks for. Order mirrors
    # the prompt sequence in run_interview.
    answers = [
        # RoE
        "smoke-engagement",      # engagement name
        "internal qa",           # client
        "example.com",           # primary target
        "",                      # additional in-scope (default: target only)
        "",                      # out-of-scope
        "24/7",                  # testing window
        "n",                     # allow_destructive_writes
        # CONOPS
        "APT-test",              # threat actor
        "medium",                # sophistication
        "data-exfil",            # motivation
        "T1190,T1059",           # ttps
        "Find a SQLi, escalate to RCE.",  # narrative
        "",                      # success criteria (use default)
        # Deconfliction
        "203.0.113.5",           # source IPs
        "Mon-Fri 09:00-18:00 UTC",
        "",                      # shared_signature (default)
        "",                      # SOC contact name (skip)
    ]
    result = run_interview(ws, target_hint="example.com",
                          prompt_fn=_scripted(answers))
    assert (ws / "plan" / "roe.json").exists()
    assert (ws / "plan" / "conops.json").exists()
    assert (ws / "plan" / "deconfliction.json").exists()
    assert (ws / "plan" / "opplan.json").exists()

    assert result.roe.engagement_name == "smoke-engagement"
    assert result.roe.allow_destructive_writes is False
    assert result.deconfliction.source_ips == ["203.0.113.5"]
    # Default signature derives from engagement name.
    assert result.deconfliction.shared_signature.startswith("network_pipeline-redteam/")


def test_interview_is_idempotent_on_resume(tmp_path: Path):
    ws = tmp_path / "eng"
    ws.mkdir()
    answers = [
        "eng1", "qa", "example.com", "", "", "24/7", "n",
        "APT", "medium", "exfil", "", "", "",
        "", "", "", "",
    ]
    first = run_interview(ws, target_hint="example.com", prompt_fn=_scripted(answers))

    # Re-run with empty answers → all hydrated from disk, no changes.
    second = run_interview(ws, target_hint="example.com",
                          prompt_fn=_scripted([""] * 30))
    assert second.roe.engagement_name == first.roe.engagement_name
    assert second.deconfliction.shared_signature == first.deconfliction.shared_signature


# ── validate ───────────────────────────────────────────────────────────


def _make_minimal_plan(ws: Path, *, with_review: bool = False) -> None:
    (ws / "plan").mkdir(parents=True, exist_ok=True)
    roe = RoE(
        engagement_name="t",
        in_scope=[{"target": "example.com", "type": "domain"}],  # type: ignore[list-item]
        reviewed_by="alice" if with_review else "",
    )
    (ws / "plan" / "roe.json").write_text(roe.model_dump_json(indent=2), encoding="utf-8")
    opplan = OPPLAN(
        engagement_name="t",
        objectives=[Objective(id="OBJ-1", phase=ObjectivePhase.RECON,
                              title="t", description="d")],
    )
    (ws / "plan" / "opplan.json").write_text(opplan.model_dump_json(indent=2), encoding="utf-8")


def test_validate_passes_minimal_plan(tmp_path: Path):
    _make_minimal_plan(tmp_path)
    report = validate_plan(tmp_path)
    assert report.ok is True
    # Missing review stamp is a warning, not an error.
    assert any("reviewed_by" in w for w in report.warnings)


def test_validate_fails_missing_roe(tmp_path: Path):
    (tmp_path / "plan").mkdir()
    report = validate_plan(tmp_path)
    assert report.ok is False
    assert any("roe.json" in e for e in report.errors)


def test_validate_fails_malformed_json(tmp_path: Path):
    plan = tmp_path / "plan"
    plan.mkdir()
    (plan / "roe.json").write_text("{not json", encoding="utf-8")
    (plan / "opplan.json").write_text("{}", encoding="utf-8")
    report = validate_plan(tmp_path)
    assert report.ok is False
    assert any("not valid JSON" in e for e in report.errors)


def test_validate_flags_writes_without_allowlist(tmp_path: Path):
    (tmp_path / "plan").mkdir()
    roe = RoE(
        engagement_name="t",
        in_scope=[{"target": "x.com", "type": "domain"}],  # type: ignore[list-item]
        allow_destructive_writes=True,
        write_allowlist=[],
    )
    (tmp_path / "plan" / "roe.json").write_text(roe.model_dump_json(), encoding="utf-8")
    opplan = OPPLAN(engagement_name="t", objectives=[
        Objective(id="OBJ-1", phase=ObjectivePhase.RECON, title="t", description="d")
    ])
    (tmp_path / "plan" / "opplan.json").write_text(opplan.model_dump_json(), encoding="utf-8")
    report = validate_plan(tmp_path)
    assert any("write_allowlist is empty" in e for e in report.errors)


def test_validate_warns_multi_turn_without_oracle(tmp_path: Path):
    (tmp_path / "plan").mkdir()
    roe = RoE(
        engagement_name="t",
        in_scope=[{"target": "x.com", "type": "domain"}],  # type: ignore[list-item]
    )
    (tmp_path / "plan" / "roe.json").write_text(roe.model_dump_json(), encoding="utf-8")
    opplan = OPPLAN(engagement_name="t", objectives=[
        Objective(id="OBJ-1", phase=ObjectivePhase.RECON, title="t", description="d",
                  multi_turn=True),
    ])
    (tmp_path / "plan" / "opplan.json").write_text(opplan.model_dump_json(), encoding="utf-8")
    report = validate_plan(tmp_path)
    assert any("success_oracle" in w for w in report.warnings)


# ── review ─────────────────────────────────────────────────────────────


def test_review_stamps_roe(tmp_path: Path, monkeypatch):
    _make_minimal_plan(tmp_path)
    # Don't open $EDITOR; just stamp.
    roe = review_plan(tmp_path, reviewer="bob", open_editor=False)
    assert roe.reviewed_by == "bob"
    assert roe.reviewed_at
    # Stamp is persisted.
    blob = json.loads((tmp_path / "plan" / "roe.json").read_text(encoding="utf-8"))
    assert blob["reviewed_by"] == "bob"


def test_review_picks_up_env_user(tmp_path: Path, monkeypatch):
    _make_minimal_plan(tmp_path)
    monkeypatch.setenv("USER", "envuser")
    monkeypatch.delenv("USERNAME", raising=False)
    roe = review_plan(tmp_path, open_editor=False)
    assert roe.reviewed_by == "envuser"


def test_review_is_idempotent(tmp_path: Path):
    _make_minimal_plan(tmp_path)
    a = review_plan(tmp_path, reviewer="alice", open_editor=False)
    b = review_plan(tmp_path, reviewer="alice", open_editor=False)
    assert a.reviewed_by == b.reviewed_by == "alice"
    # Second call refreshes the timestamp — that's intentional, not a bug.
    assert b.reviewed_at >= a.reviewed_at
