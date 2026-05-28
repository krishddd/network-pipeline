"""Token + wall-clock budget governor (Plan B.1.1).

A long-running engagement can burn through GPU minutes and electricity
on a single misbehaving objective. The 600 s per-iteration backstop in
``EngagementConfig`` catches one stuck call but does not bound aggregate
spend. ``BudgetGovernor`` is the aggregate cap.

Design:

* ``charge(role, tokens)`` is called by the engagement loop *before*
  each LLM invocation (or after, on ``on_llm_end`` from the trace
  callback) to decrement the per-role / per-phase / total counters.
* ``tick()`` updates the wall-clock counter; called once per iteration.
* ``should_abort()`` returns ``(True, reason)`` when any cap is breached
  — the loop translates that into ``IterationResult(outcome="ERROR",
  error="budget exhausted")`` so the existing retry / state-save code
  handles graceful shutdown.
* Counters live in the ``BudgetState`` Pydantic model (already on
  ``OPPLAN``) so they survive resume — re-running an engagement picks up
  the spend from where it stopped.

Token estimation is conservative: we use character-count / 3.5 as a
rough proxy when the trace handler has not produced a tiktoken estimate
yet. It runs ahead of the real count, so the cap is hit *earlier* than
the LLM's true tokenisation would suggest — better than the reverse.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import BudgetState, ObjectivePhase

log = get_logger("core.budget")


# Phase-name canonicalisation: BudgetState.per_phase_tokens uses lower-
# kebab strings ("recon", "scan", "initial-access", ...) — same as
# ObjectivePhase.value — so callers can pass either an enum or a str.
def _phase_key(phase: ObjectivePhase | str | None) -> str:
    if phase is None:
        return "_unknown"
    if isinstance(phase, ObjectivePhase):
        return phase.value
    return str(phase)


@dataclass
class AbortDecision:
    """Returned from ``should_abort``. Truthy when the budget is busted."""

    abort: bool
    reason: str = ""

    def __bool__(self) -> bool:
        return self.abort


class BudgetGovernor:
    """Tracks token + wall-clock spend against an immutable cap.

    The cap lives in ``BudgetState``; counters update in place. The
    governor is created with a reference to the live ``BudgetState`` so
    every charge mutates the same object that the engagement state
    serializer writes to disk.
    """

    def __init__(self, state: BudgetState) -> None:
        self._state = state
        self._t0 = time.monotonic()
        self._aborted_reason: str | None = None

    # ── public ─────────────────────────────────────────────────────

    @property
    def state(self) -> BudgetState:
        return self._state

    def charge(
        self,
        role: str,
        *,
        prompt_chars: int = 0,
        response_chars: int = 0,
        explicit_tokens: int | None = None,
        phase: ObjectivePhase | str | None = None,
    ) -> None:
        """Decrement counters for one LLM exchange.

        Pass either an ``explicit_tokens`` (when the trace handler has a
        real tiktoken estimate) or ``prompt_chars + response_chars``
        (when only character counts are available).
        """
        if explicit_tokens is not None:
            tokens = max(0, int(explicit_tokens))
        else:
            # Conservative chars→tokens ratio of 3.5. Real tiktoken is
            # closer to 4 for English, lower for code. Erring small here
            # means we hit the cap *before* the LLM's true budget is
            # exhausted.
            chars = max(0, int(prompt_chars)) + max(0, int(response_chars))
            tokens = math.ceil(chars / 3.5) if chars else 0
        if tokens <= 0:
            return
        self._state.tokens_used += tokens
        pkey = _phase_key(phase)
        self._state.per_phase_used[pkey] = (
            self._state.per_phase_used.get(pkey, 0) + tokens
        )
        log.debug(
            "budget charge role=%s phase=%s tokens=%d total=%d",
            role, pkey, tokens, self._state.tokens_used,
        )

    def tick(self) -> None:
        """Refresh the wall-clock counter."""
        self._state.seconds_used = time.monotonic() - self._t0

    def should_abort(self) -> AbortDecision:
        """Return an abort decision if any cap is breached."""
        if self._aborted_reason is not None:
            return AbortDecision(True, self._aborted_reason)
        self.tick()
        s = self._state
        if s.total_tokens is not None and s.tokens_used >= s.total_tokens:
            return self._latch(
                f"total token budget exhausted: {s.tokens_used} >= {s.total_tokens}",
            )
        if s.total_seconds is not None and s.seconds_used >= s.total_seconds:
            return self._latch(
                f"wall-clock budget exhausted: {s.seconds_used:.0f}s >= "
                f"{s.total_seconds}s",
            )
        for phase, cap in s.per_phase_tokens.items():
            used = s.per_phase_used.get(phase, 0)
            if used >= cap:
                return self._latch(
                    f"phase '{phase}' token budget exhausted: {used} >= {cap}",
                )
        return AbortDecision(False)

    def remaining_for_phase(self, phase: ObjectivePhase | str) -> int | None:
        """Tokens left for a phase (None = uncapped). For tests / logs."""
        cap = self._state.per_phase_tokens.get(_phase_key(phase))
        if cap is None:
            return None
        used = self._state.per_phase_used.get(_phase_key(phase), 0)
        return max(0, cap - used)

    # ── internals ──────────────────────────────────────────────────

    def _latch(self, reason: str) -> AbortDecision:
        # Once we abort, stay aborted — the loop should not "recover"
        # by accident on a later tick where the counter wraps.
        self._aborted_reason = reason
        log.warning("budget abort: %s", reason)
        return AbortDecision(True, reason)
