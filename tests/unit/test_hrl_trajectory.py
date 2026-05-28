"""Phase-4 tests: HRL trajectory primitives + multi-turn attacker."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from network_pipeline.agents.hrl_attacker import HRLAttacker, _parse_json_object
from network_pipeline.core.hrl_trajectory import (
    RewardWeights,
    StrategicAction,
    TrajectoryState,
    TurnObservation,
    compute_reward,
    valid_actions,
)
from network_pipeline.core.schemas import (
    Objective,
    ObjectivePhase,
    SuccessOracle,
)


# ── schema: multi_turn fields ─────────────────────────────────────────


def test_objective_default_is_single_turn():
    obj = Objective(
        id="OBJ-001", phase=ObjectivePhase.INITIAL_ACCESS,
        title="t", description="d",
    )
    assert obj.multi_turn is False
    assert obj.max_turns == 8
    assert obj.success_oracle is None


def test_objective_multi_turn_with_oracle():
    obj = Objective(
        id="OBJ-002", phase=ObjectivePhase.INITIAL_ACCESS,
        title="t", description="d",
        multi_turn=True, max_turns=5,
        success_oracle=SuccessOracle(
            pattern=r"is_admin=true", where="response_body",
        ),
    )
    assert obj.multi_turn is True
    assert obj.max_turns == 5
    assert obj.success_oracle.pattern == r"is_admin=true"


def test_objective_round_trips_json():
    obj = Objective(
        id="OBJ-003", phase=ObjectivePhase.INITIAL_ACCESS,
        title="t", description="d",
        multi_turn=True,
        success_oracle=SuccessOracle(pattern=r"AKIA[0-9A-Z]{16}"),
    )
    blob = obj.model_dump_json()
    parsed = Objective.model_validate_json(blob)
    assert parsed.multi_turn is True
    assert parsed.success_oracle.pattern == r"AKIA[0-9A-Z]{16}"


# ── TurnObservation ───────────────────────────────────────────────────


def test_fingerprint_ignores_whitespace_in_body():
    a = TurnObservation(response_status=200, response_body="ok\n  done")
    b = TurnObservation(response_status=200, response_body="ok done")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_distinguishes_status():
    a = TurnObservation(response_status=200, response_body="x")
    b = TurnObservation(response_status=500, response_body="x")
    assert a.fingerprint() != b.fingerprint()


# ── compute_reward components ─────────────────────────────────────────


def _state():
    return TrajectoryState(objective_id="OBJ-1", target="t", intent="i")


def test_oracle_fires_yields_full_credit():
    obs = TurnObservation(response_status=200, response_body="welcome, is_admin=true")
    oracle = SuccessOracle(pattern=r"is_admin=true")
    rb = compute_reward(obs, state=_state(), success_oracle=oracle)
    assert rb.oracle_fired is True
    assert rb.oracle == 1.0
    assert rb.total >= 1.0  # oracle + non-refusal + new-state + length


def test_oracle_in_headers():
    obs = TurnObservation(
        response_status=200,
        response_headers={"X-Auth": "valid"},
        response_body="",
    )
    oracle = SuccessOracle(pattern=r"X-Auth: valid", where="response_headers")
    rb = compute_reward(obs, state=_state(), success_oracle=oracle)
    assert rb.oracle_fired


def test_long_refusal_does_not_reward():
    """User concern: response_length alone would over-credit a long refusal."""
    obs = TurnObservation(
        response_status=401,
        response_body="I'm sorry, but " + "details " * 500,
    )
    rb = compute_reward(obs, state=_state(), success_oracle=None)
    assert rb.refusal_detected is True
    assert rb.refusal_penalty == -0.5
    assert rb.non_refusal == 0.0
    # Length contributes only the small tiebreaker
    assert rb.length <= 0.05
    assert rb.total < 0  # net negative


def test_non_refusal_short_response_gets_small_positive():
    obs = TurnObservation(response_status=200, response_body="data")
    rb = compute_reward(obs, state=_state())
    assert rb.refusal_detected is False
    assert rb.non_refusal == 0.1
    assert rb.state_was_new is True
    assert rb.new_state == 0.3


def test_repeated_state_drops_new_state_credit():
    state = _state()
    obs = TurnObservation(response_status=200, response_body="dup")
    # First time: new state
    rb1 = compute_reward(obs, state=state)
    assert rb1.state_was_new
    state.record_turn(StrategicAction.ESCALATE, obs, rb1.total)
    # Second time: same fingerprint → no new-state credit
    rb2 = compute_reward(obs, state=state)
    assert rb2.state_was_new is False
    assert rb2.new_state == 0.0


def test_rate_limit_counts_as_refusal():
    obs = TurnObservation(response_status=429, response_body="slow down")
    rb = compute_reward(obs, state=_state())
    assert rb.refusal_detected
    assert rb.refusal_penalty == -0.5


def test_custom_weights_override():
    obs = TurnObservation(response_status=200, response_body="hit")
    oracle = SuccessOracle(pattern=r"hit")
    weights = RewardWeights(oracle_hit=10.0, non_refusal=0.0, new_state=0.0,
                            length_tiebreak_cap=0.0)
    rb = compute_reward(obs, state=_state(), success_oracle=oracle, weights=weights)
    assert rb.oracle == 10.0
    assert rb.non_refusal == 0.0
    assert rb.new_state == 0.0
    assert rb.length == 0.0
    assert rb.total == 10.0


def test_length_is_tiebreaker_only():
    """Two states with identical reward components — longer one wins by epsilon."""
    short = TurnObservation(response_status=200, response_body="ok")
    long = TurnObservation(response_status=200, response_body="ok " * 1000)
    # Different content → both score as new, both non-refusal
    rs = compute_reward(short, state=_state())
    rl = compute_reward(long, state=_state())
    # The non-length components are identical; length is the only difference.
    non_length_short = rs.total - rs.length
    non_length_long = rl.total - rl.length
    assert pytest.approx(non_length_short, abs=1e-9) == non_length_long
    assert rl.length > rs.length
    assert rl.length <= 0.05


# ── valid_actions filtering ───────────────────────────────────────────


def test_valid_actions_initial_excludes_replay():
    state = _state()
    actions = valid_actions(state)
    assert StrategicAction.REPLAY_WITH_MUTATION not in actions
    assert StrategicAction.BACK_OFF in actions


def test_valid_actions_after_one_turn_includes_replay():
    state = _state()
    obs = TurnObservation(response_status=200, response_body="x")
    state.record_turn(StrategicAction.ESCALATE, obs, 0.4)
    assert StrategicAction.REPLAY_WITH_MUTATION in valid_actions(state)


def test_two_consecutive_refusals_suppress_social_engineer():
    state = _state()
    refusal = TurnObservation(response_status=401, response_body="I can't help with that")
    state.record_turn(StrategicAction.ESCALATE, refusal, -0.5)
    state.record_turn(StrategicAction.PIVOT, refusal, -0.5)
    actions = valid_actions(state)
    assert StrategicAction.SOCIAL_ENGINEER not in actions


# ── _parse_json_object ────────────────────────────────────────────────


def test_parse_json_object_handles_fenced():
    text = "```json\n{\"action\": \"escalate\", \"rationale\": \"x\"}\n```"
    obj = _parse_json_object(text)
    assert obj["action"] == "escalate"


def test_parse_json_object_empty_returns_empty_dict():
    assert _parse_json_object("") == {}
    assert _parse_json_object("no json here") == {}


# ── HRLAttacker integration (mocked) ──────────────────────────────────


def _factory_for_actions(actions: list[str]):
    """Build a factory whose high-level model returns actions in order
    and whose low-level model always returns a GET / request."""
    queue = list(actions)
    high_responses = []
    for a in queue:
        high_responses.append(MagicMock(content=json.dumps({
            "action": a, "rationale": f"because-{a}",
        })))

    low_response = MagicMock(content=json.dumps({
        "method": "GET", "path": "/admin", "headers": {}, "body": "",
        "rationale": "probe",
    }))

    def make_model(role: str):
        m = MagicMock()
        m.model = f"{role}-mock"
        if role == "orchestrator":
            m.ainvoke = AsyncMock(side_effect=high_responses)
        else:
            m.ainvoke = AsyncMock(return_value=low_response)
        return m

    factory = MagicMock()
    factory.provider_for.side_effect = lambda r: (
        "anthropic" if r == "orchestrator" else "ollama"
    )
    factory.get_model.side_effect = make_model
    return factory


def test_hrl_attacker_terminates_on_oracle(tmp_path: Path):
    factory = _factory_for_actions(["escalate", "escalate", "escalate"])
    attacker = HRLAttacker(factory, log_path=tmp_path / "hrl.jsonl")

    obj = Objective(
        id="OBJ-X", phase=ObjectivePhase.INITIAL_ACCESS,
        title="auth bypass", description="get is_admin=true",
        multi_turn=True, max_turns=4,
        success_oracle=SuccessOracle(pattern=r"is_admin=true"),
    )

    calls = {"n": 0}

    async def env(req: dict) -> TurnObservation:
        calls["n"] += 1
        # Oracle fires on turn 2
        body = "is_admin=true" if calls["n"] == 2 else "no luck"
        return TurnObservation(response_status=200, response_body=body)

    state = asyncio.run(attacker.run(obj, "http://t", "intent", env))
    assert state.terminal
    assert state.terminal_reason == "oracle_fired"
    assert state.turns_taken == 2
    assert (tmp_path / "hrl.jsonl").exists()


def test_hrl_attacker_terminates_on_back_off(tmp_path: Path):
    factory = _factory_for_actions(["back_off"])
    attacker = HRLAttacker(factory, log_path=tmp_path / "hrl.jsonl")

    obj = Objective(
        id="OBJ-Y", phase=ObjectivePhase.INITIAL_ACCESS,
        title="t", description="d", multi_turn=True, max_turns=8,
    )

    async def env(req: dict) -> TurnObservation:
        return TurnObservation(response_status=200, response_body="x")

    state = asyncio.run(attacker.run(obj, "http://t", "i", env))
    assert state.terminal_reason == "back_off"
    assert state.turns_taken == 0  # back_off is picked before any request


def test_hrl_attacker_caps_at_max_turns(tmp_path: Path):
    factory = _factory_for_actions(["escalate"] * 10)
    attacker = HRLAttacker(factory, log_path=tmp_path / "hrl.jsonl")

    obj = Objective(
        id="OBJ-Z", phase=ObjectivePhase.INITIAL_ACCESS,
        title="t", description="d", multi_turn=True, max_turns=3,
        success_oracle=SuccessOracle(pattern=r"never-matches-this"),
    )

    async def env(req: dict) -> TurnObservation:
        return TurnObservation(response_status=200, response_body="hi")

    state = asyncio.run(attacker.run(obj, "http://t", "i", env))
    assert state.terminal_reason == "max_turns"
    assert state.turns_taken == 3


def test_hrl_attacker_falls_back_on_bad_action(tmp_path: Path):
    factory = _factory_for_actions(["definitely-not-an-action", "escalate"])
    attacker = HRLAttacker(factory, log_path=tmp_path / "hrl.jsonl")

    obj = Objective(
        id="OBJ-W", phase=ObjectivePhase.INITIAL_ACCESS,
        title="t", description="d", multi_turn=True, max_turns=2,
        success_oracle=SuccessOracle(pattern=r"nope"),
    )

    async def env(req: dict) -> TurnObservation:
        return TurnObservation(response_status=200, response_body="x")

    # Should not raise — invalid action coerced to ESCALATE.
    state = asyncio.run(attacker.run(obj, "http://t", "i", env))
    assert state.turns_taken == 2
