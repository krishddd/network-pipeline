"""Per-provider USD/token accounting with live CLI surface + budget cap.

Two surfaces:
  1. JSON line per exchange (provider, model, prompt_tokens,
     completion_tokens, cost_usd) appended to agent_traces.log by
     `core/logging.py` (it asks the tracker for the current exchange's
     numbers).
  2. A running-total line emitted to the CLI via `rich.live` after every
     exchange — operators see spend in real time instead of after the
     fact.

A hard `--budget-usd N` cap is enforced via `BudgetExceeded` raised at
exchange-record time; the engagement loop catches this, snapshots
state, and exits cleanly.

Pricing is approximate and easy to drift — keep `_PRICING_PER_1K` in
sync with the provider price pages, and surface "unknown model" with a
0-cost entry (so an unknown model never silently zeros the budget).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Optional

from network_pipeline.core.logging import get_logger
from network_pipeline.llm.profiles import Provider

log = get_logger("llm.cost")


# USD per 1K tokens. Keys are case-insensitive model prefixes. Values
# are (prompt_price, completion_price). Updated cautiously — wrong by
# default rather than guessed.
_PRICING_PER_1K: dict[str, tuple[float, float]] = {
    # Anthropic — placeholder pricing, refresh from console.anthropic.com.
    "claude-opus-4":     (0.015, 0.075),
    "claude-sonnet-4":   (0.003, 0.015),
    "claude-haiku-4":    (0.0008, 0.004),
    # OpenAI — placeholder.
    "gpt-5":             (0.005, 0.015),
    "gpt-4o":            (0.0025, 0.010),
    "gpt-4o-mini":       (0.00015, 0.0006),
    # Ollama — free locally.
    "llama":             (0.0, 0.0),
    "qwen":              (0.0, 0.0),
}


def _price_for(model: str) -> tuple[float, float]:
    """Longest-prefix match against `_PRICING_PER_1K`. Returns (0,0) if unknown."""
    lower = model.lower()
    matches = [(k, v) for k, v in _PRICING_PER_1K.items() if lower.startswith(k)]
    if not matches:
        return (0.0, 0.0)
    matches.sort(key=lambda kv: -len(kv[0]))
    return matches[0][1]


class BudgetExceeded(RuntimeError):
    """Raised when the engagement's cumulative spend crosses `--budget-usd`."""


@dataclass
class CostTotals:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0

    def add(self, p: int, c: int, usd: float) -> None:
        self.prompt_tokens += p
        self.completion_tokens += c
        self.cost_usd += usd


@dataclass
class CostTracker:
    """Process-wide singleton tracking spend across an engagement."""

    by_provider: dict[Provider, CostTotals] = field(default_factory=dict)
    budget_usd: Optional[float] = None  # None = unlimited
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _live_emit: Optional[callable] = None  # set by CLI; void(str)

    def record(
        self,
        provider: Provider,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> float:
        """Record an exchange, return the USD cost of *this* exchange."""
        ppk, cpk = _price_for(model)
        usd = (prompt_tokens / 1000.0) * ppk + (completion_tokens / 1000.0) * cpk
        with self._lock:
            totals = self.by_provider.setdefault(provider, CostTotals())
            totals.add(prompt_tokens, completion_tokens, usd)
            total = sum(t.cost_usd for t in self.by_provider.values())
            if self._live_emit is not None:
                self._live_emit(self._format_line(total))
            if self.budget_usd is not None and total > self.budget_usd:
                raise BudgetExceeded(
                    f"engagement spend ${total:.2f} exceeded budget ${self.budget_usd:.2f}"
                )
        return usd

    def _format_line(self, total: float) -> str:
        parts = [
            f"{p} ${self.by_provider[p].cost_usd:.2f}"
            for p in sorted(self.by_provider)
        ]
        return f"[cost] {' | '.join(parts)} | total ${total:.2f}"

    def total_usd(self) -> float:
        with self._lock:
            return sum(t.cost_usd for t in self.by_provider.values())

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "total_usd": sum(t.cost_usd for t in self.by_provider.values()),
                "by_provider": {
                    p: {
                        "prompt_tokens": t.prompt_tokens,
                        "completion_tokens": t.completion_tokens,
                        "cost_usd": t.cost_usd,
                    }
                    for p, t in self.by_provider.items()
                },
                "budget_usd": self.budget_usd,
            }


_TRACKER: CostTracker = CostTracker()


def get_tracker() -> CostTracker:
    return _TRACKER


def configure(budget_usd: Optional[float] = None, live_emit: Optional[callable] = None) -> None:
    """Wire CLI-supplied budget + live-emit hook into the singleton."""
    _TRACKER.budget_usd = budget_usd
    _TRACKER._live_emit = live_emit
