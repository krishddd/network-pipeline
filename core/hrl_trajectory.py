"""HRL (Hierarchical Reinforcement Learning) trajectory primitives.

Background — see ``LLM Red-Teaming Techniques Explained.md`` section
*Trajectory-Based Multi-Turn Attack Learning via Hierarchical MDPs*
(Belaire, Sinha & Varakantham, 2025). The paper formalises multi-turn
red-teaming as a Markov Decision Process with two decoupled policies:

  * **High-level policy** picks a strategic *action* every N turns
    (escalate, pivot, social-engineer, replay-with-mutation, back-off).
  * **Low-level policy** generates the actual tokens / HTTP request
    for the picked action.

We borrow the *runtime structure* — the State/Action/reward shaping —
without the offline RL training pipeline (training is out of scope and
economically unjustified for a single deployment). The reward function
is what makes long-horizon attacks tractable: instead of a sparse
binary success signal at turn N, every turn contributes a dense
intermediate reward, giving the high-level policy a strong gradient.

## Composite reward (Phase-3 user concern: naive length-delta is too
noisy because a long refusal scores well)

  + 1.0   if the objective's `success_oracle` (regex) fires this turn
  + 0.3   for new-state discovery (response hash not seen before)
  + 0.1   for non-refusal heuristic (response lacks "I can't", 401/403)
  − 0.5   for explicit refusal markers or rate-limit responses
  + tiebreaker  response length, scaled to [0, 0.05]

Each component is opt-in via the corresponding ``RewardWeights`` knob.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from network_pipeline.core.schemas import SuccessOracle


# ── Action space ──────────────────────────────────────────────────────


class StrategicAction(str, Enum):
    """High-level policy's discrete action set.

    Mirrors the paper's Action enum. Names chosen to be self-documenting
    for the high-level model that picks them.
    """

    ESCALATE = "escalate"
    """Push harder along the current vector — more privilege, deeper depth."""

    PIVOT = "pivot"
    """Abandon the current angle; try a different vuln class or endpoint."""

    SOCIAL_ENGINEER = "social_engineer"
    """Add a persona/pretext layer to the same intent (delegates to CoP)."""

    REPLAY_WITH_MUTATION = "replay_with_mutation"
    """Re-run the last request with a small payload mutation (encoding swap, case flip)."""

    BACK_OFF = "back_off"
    """Concede this trajectory; the attacker stops the objective. Terminal."""


# ── Observation / State ──────────────────────────────────────────────


@dataclass(frozen=True)
class TurnObservation:
    """What the low-level policy returns after one turn.

    Fields are deliberately HTTP-shaped because that's the dominant
    target modality. For non-HTTP exchanges (shell, MQ), the runner
    fills only the relevant fields and leaves the rest empty.
    """

    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_cookies: dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def combined(self) -> str:
        """Flat string view used by success_oracle when where='combined'."""
        return (
            f"status={self.response_status}\n"
            + "\n".join(f"{k}: {v}" for k, v in self.response_headers.items())
            + "\n\n"
            + self.response_body
            + "\n"
            + "\n".join(f"{k}={v}" for k, v in self.response_cookies.items())
        )

    def fingerprint(self) -> str:
        """Stable hash for new-state-discovery; ignores body whitespace."""
        norm_body = re.sub(r"\s+", " ", self.response_body).strip()
        material = f"{self.response_status}|{sorted(self.response_headers.items())}|{norm_body}"
        return hashlib.sha1(material.encode("utf-8", errors="ignore")).hexdigest()


@dataclass
class TrajectoryState:
    """Running state passed between turns of the HRL loop.

    Mutable by design — the high-level policy needs an evolving view
    of the conversation, not an immutable snapshot. Persisted into the
    workspace at the end of each turn so a Ctrl+C resume picks up
    cleanly.
    """

    objective_id: str
    target: str
    intent: str
    turns_taken: int = 0
    actions_taken: list[StrategicAction] = field(default_factory=list)
    observations: list[TurnObservation] = field(default_factory=list)
    seen_fingerprints: set[str] = field(default_factory=set)
    cumulative_reward: float = 0.0
    last_action_rationale: str = ""
    terminal: bool = False
    terminal_reason: str = ""

    def record_turn(
        self,
        action: StrategicAction,
        observation: TurnObservation,
        reward: float,
        rationale: str = "",
    ) -> bool:
        """Append a turn; return True if this was a *new* state."""
        self.actions_taken.append(action)
        self.observations.append(observation)
        self.turns_taken += 1
        self.cumulative_reward += reward
        self.last_action_rationale = rationale
        fp = observation.fingerprint()
        new_state = fp not in self.seen_fingerprints
        self.seen_fingerprints.add(fp)
        return new_state


# ── Reward shaping ────────────────────────────────────────────────────


# Refusal markers — case-insensitive substring or HTTP status. Deliberately
# conservative so we don't accuse a genuine partial-credit response of
# refusing. The list is data, not policy — operators can extend via
# RewardWeights.extra_refusal_markers.
_DEFAULT_REFUSAL_MARKERS: tuple[str, ...] = (
    "i can't", "i cannot", "i'm sorry", "i am sorry",
    "as an ai", "i'm not able", "i am not able",
    "rate limit", "too many requests",
    "unauthorized", "forbidden",
)


@dataclass(frozen=True)
class RewardWeights:
    """Tunable weights for the composite reward. Defaults match the
    plan's published values."""

    oracle_hit: float = 1.0
    new_state: float = 0.3
    non_refusal: float = 0.1
    refusal_penalty: float = -0.5
    length_tiebreak_cap: float = 0.05  # max contribution of length
    refusal_status_codes: frozenset[int] = frozenset({401, 403, 429, 451})
    extra_refusal_markers: tuple[str, ...] = ()


def _check_oracle(oracle: SuccessOracle, observation: TurnObservation) -> bool:
    """Apply a SuccessOracle to a TurnObservation. True ⇒ +1.0 reward."""
    try:
        rx = re.compile(oracle.pattern, re.MULTILINE | re.DOTALL)
    except re.error:
        return False
    where = oracle.where.lower().strip()
    if where == "response_body":
        haystack = observation.response_body
    elif where == "response_headers":
        haystack = "\n".join(f"{k}: {v}" for k, v in observation.response_headers.items())
    elif where == "response_status":
        haystack = str(observation.response_status)
    elif where == "response_cookies":
        haystack = "\n".join(f"{k}={v}" for k, v in observation.response_cookies.items())
    elif where == "combined":
        haystack = observation.combined
    else:
        # Unknown location — be conservative; do not fire.
        return False
    return bool(rx.search(haystack))


def _looks_like_refusal(
    observation: TurnObservation, weights: RewardWeights,
) -> bool:
    if observation.response_status in weights.refusal_status_codes:
        return True
    body_lower = observation.response_body.lower()
    markers = _DEFAULT_REFUSAL_MARKERS + tuple(weights.extra_refusal_markers)
    return any(m in body_lower for m in markers)


@dataclass(frozen=True)
class RewardBreakdown:
    """Component-level reward attribution. Logged per turn for analytics."""

    oracle: float = 0.0
    new_state: float = 0.0
    non_refusal: float = 0.0
    refusal_penalty: float = 0.0
    length: float = 0.0
    total: float = 0.0
    oracle_fired: bool = False
    refusal_detected: bool = False
    state_was_new: bool = False


def compute_reward(
    observation: TurnObservation,
    *,
    state: TrajectoryState,
    success_oracle: Optional[SuccessOracle] = None,
    weights: Optional[RewardWeights] = None,
) -> RewardBreakdown:
    """Compute the composite reward for one turn's observation.

    `state.seen_fingerprints` is read but NOT mutated — the caller
    decides whether to commit the turn (via `record_turn`) based on the
    result. Keeping this pure makes the function easy to unit-test and
    safe to call from the high-level policy when it's planning a hypothetical.
    """
    w = weights or RewardWeights()

    oracle_fired = bool(success_oracle and _check_oracle(success_oracle, observation))
    is_refusal = _looks_like_refusal(observation, w)
    is_new_state = observation.fingerprint() not in state.seen_fingerprints

    oracle_r = w.oracle_hit if oracle_fired else 0.0
    new_state_r = w.new_state if is_new_state else 0.0
    refusal_r = w.refusal_penalty if is_refusal else 0.0
    # non-refusal credit is suppressed when an actual refusal is present
    # AND capped so it can't dominate the oracle signal.
    non_refusal_r = 0.0 if is_refusal else w.non_refusal

    # Length contribution — tiny tiebreaker only. Maps 0..4000 chars to
    # [0..length_tiebreak_cap]; longer responses get no extra credit.
    body_len = min(4000, len(observation.response_body))
    length_r = (body_len / 4000.0) * w.length_tiebreak_cap

    total = oracle_r + new_state_r + non_refusal_r + refusal_r + length_r

    return RewardBreakdown(
        oracle=oracle_r,
        new_state=new_state_r,
        non_refusal=non_refusal_r,
        refusal_penalty=refusal_r,
        length=length_r,
        total=total,
        oracle_fired=oracle_fired,
        refusal_detected=is_refusal,
        state_was_new=is_new_state,
    )


# ── Convenience: action validity given history ────────────────────────


def valid_actions(state: TrajectoryState) -> list[StrategicAction]:
    """Filter the action set to what's sensible given trajectory history.

    Heuristic only — the high-level policy may override by passing
    ``allow_all=True`` to its picker. The defaults:

      * REPLAY_WITH_MUTATION needs at least one prior turn to mutate.
      * SOCIAL_ENGINEER is suppressed when the last 2 turns both
        registered refusals (the persona angle has been used).
      * BACK_OFF is always available.
    """
    actions = [
        StrategicAction.ESCALATE,
        StrategicAction.PIVOT,
        StrategicAction.SOCIAL_ENGINEER,
        StrategicAction.BACK_OFF,
    ]
    if state.turns_taken >= 1:
        actions.insert(2, StrategicAction.REPLAY_WITH_MUTATION)

    # Suppress social-engineer after 2 consecutive refusals.
    if len(state.observations) >= 2:
        weights = RewardWeights()
        if all(_looks_like_refusal(o, weights) for o in state.observations[-2:]):
            actions = [a for a in actions if a != StrategicAction.SOCIAL_ENGINEER]

    return actions


__all__ = [
    "RewardBreakdown",
    "RewardWeights",
    "StrategicAction",
    "TrajectoryState",
    "TurnObservation",
    "compute_reward",
    "valid_actions",
]
