"""Tests for core.budget — token + wall-clock governor."""

from __future__ import annotations

import time


def test_budget_no_caps_never_aborts():
    from network_pipeline.core.budget import BudgetGovernor
    from network_pipeline.core.schemas import BudgetState

    g = BudgetGovernor(BudgetState())
    g.charge("recon", prompt_chars=10_000, response_chars=10_000)
    assert not g.should_abort().abort


def test_budget_total_token_cap_aborts():
    from network_pipeline.core.budget import BudgetGovernor
    from network_pipeline.core.schemas import BudgetState

    g = BudgetGovernor(BudgetState(total_tokens=100))
    g.charge("recon", prompt_chars=200, response_chars=200)  # ~115 tokens
    decision = g.should_abort()
    assert decision.abort
    assert "total token budget" in decision.reason


def test_budget_per_phase_cap_aborts_only_offending_phase():
    from network_pipeline.core.budget import BudgetGovernor
    from network_pipeline.core.schemas import BudgetState, ObjectivePhase

    g = BudgetGovernor(BudgetState(per_phase_tokens={"recon": 50}))
    g.charge("recon", prompt_chars=100, response_chars=100, phase=ObjectivePhase.RECON)
    assert g.should_abort().abort
    # Once latched, stays latched
    assert g.should_abort().abort


def test_budget_explicit_tokens_overrides_chars():
    from network_pipeline.core.budget import BudgetGovernor
    from network_pipeline.core.schemas import BudgetState

    g = BudgetGovernor(BudgetState(total_tokens=200))
    g.charge("scan", explicit_tokens=150)
    assert not g.should_abort().abort
    g.charge("scan", explicit_tokens=100)
    assert g.should_abort().abort


def test_budget_wall_clock_cap_aborts():
    from network_pipeline.core.budget import BudgetGovernor
    from network_pipeline.core.schemas import BudgetState

    g = BudgetGovernor(BudgetState(total_seconds=0))
    # state.seconds_used initialises 0 and total_seconds is 0 so it
    # should abort on the next tick
    time.sleep(0.001)
    assert g.should_abort().abort
