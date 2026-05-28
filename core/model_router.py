"""Adaptive model promotion / demotion (Plan B.1.2).

The eco profile pins each role to one model. If recon's
``llama3.2:3b`` keeps timing out we lose iterations. The
``AdaptiveRouter`` watches per-role success / latency / timeout stats
and silently swaps the role's model up or down a tier.

Anti-thrash from Plan risk #6:

* EWMA over the last ≥10 calls — single failures don't trigger.
* 5-iteration cooldown after every promotion / demotion.
* Routing decisions are persisted to ``workspace/llm/routing.json`` so
  resume preserves them.

The router is consulted from ``OllamaLLMFactory.get_model`` via
``effective_model_name(role)`` — when a routing override exists, the
factory builds a ChatOllama for the override instead of the profile
default.

NOTE: this module is opt-in via the ``--adaptive-models`` CLI flag.
When the flag is off, the router is never consulted and the factory
behaves exactly as in Phase 1.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from network_pipeline.core.logging import get_logger

log = get_logger("core.model_router")


# Promotion ladder per role — base profile model → next tier(s) up.
# Demotion is the reverse traversal. We list 3-tier ladders for the
# default eco profile; max-profile users will rarely need promotion.
_LADDERS: dict[str, list[str]] = {
    "recon":       ["llama3.2:3b", "llama3.1:8b", "qwen2.5-coder:7b"],
    "scanner":     ["llama3.2:3b", "llama3.1:8b", "qwen2.5-coder:7b"],
    "exploit":     ["qwen2.5-coder:7b", "llama3.1:8b"],
    "postexploit": ["qwen2.5-coder:7b", "llama3.1:8b"],
    "analyst":     ["llama3.1:8b", "qwen2.5-coder:7b"],
    "defender":    ["llama3.1:8b", "qwen2.5-coder:7b"],
    "verifier":    ["qwen2.5-coder:7b", "llama3.1:8b"],
    "orchestrator": ["llama3.1:8b"],
}


# Decision thresholds.
_MIN_CALLS_BEFORE_DECISION = 10
_PROMOTE_TIMEOUT_RATIO = 0.30   # >30 % timeouts → promote
_DEMOTE_TIMEOUT_RATIO = 0.0     # 0 timeouts AND ≥0.95 success → demote
_DEMOTE_MIN_CALLS = 30          # only demote after lots of evidence
_COOLDOWN_ITERATIONS = 5


# ── Stats + decision state ───────────────────────────────────────────


@dataclass
class RoleStats:
    """Per-role rolling counters; EWMA computed on the fly."""

    role: str
    total_calls: int = 0
    success: int = 0
    timeouts: int = 0
    errors: int = 0
    latency_sum_ms: float = 0.0
    cooldown_until_iter: int = 0
    current_model: str = ""

    @property
    def timeout_ratio(self) -> float:
        return self.timeouts / max(1, self.total_calls)

    @property
    def success_ratio(self) -> float:
        return self.success / max(1, self.total_calls)

    @property
    def avg_latency_ms(self) -> float:
        return self.latency_sum_ms / max(1, self.total_calls)


# ── Router ───────────────────────────────────────────────────────────


@dataclass
class AdaptiveRouter:
    """Stateful router persisted to ``workspace/llm/routing.json``."""

    workspace: Path
    enabled: bool = True
    stats: dict[str, RoleStats] = field(default_factory=dict)
    overrides: dict[str, str] = field(default_factory=dict)
    iteration: int = 0

    @classmethod
    def load(cls, workspace: Path, *, enabled: bool = True) -> "AdaptiveRouter":
        path = workspace / "llm" / "routing.json"
        if not path.exists():
            return cls(workspace=workspace, enabled=enabled)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:  # pragma: no cover
            log.warning("could not load routing.json: %r", e)
            return cls(workspace=workspace, enabled=enabled)
        stats_raw = data.get("stats", {}) or {}
        stats = {
            role: RoleStats(role=role, **{
                k: v for k, v in s.items()
                if k in RoleStats.__dataclass_fields__ and k != "role"
            })
            for role, s in stats_raw.items()
        }
        return cls(
            workspace=workspace,
            enabled=enabled,
            stats=stats,
            overrides=dict(data.get("overrides") or {}),
            iteration=int(data.get("iteration", 0)),
        )

    def save(self) -> None:
        path = self.workspace / "llm" / "routing.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "iteration": self.iteration,
            "overrides": self.overrides,
            "stats": {
                role: {
                    "total_calls": s.total_calls,
                    "success": s.success,
                    "timeouts": s.timeouts,
                    "errors": s.errors,
                    "latency_sum_ms": s.latency_sum_ms,
                    "cooldown_until_iter": s.cooldown_until_iter,
                    "current_model": s.current_model,
                }
                for role, s in self.stats.items()
            },
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, path)

    # ── public API ────────────────────────────────────────────────

    def effective_model(self, role: str, default_model: str) -> str:
        """Return the model name the factory should actually use for ``role``.

        When ``enabled=False`` always returns ``default_model``.
        """
        if not self.enabled:
            return default_model
        # Initialise current_model on first sight so a load-then-decide
        # cycle has a baseline to roll back to.
        s = self.stats.setdefault(role, RoleStats(role=role, current_model=default_model))
        if not s.current_model:
            s.current_model = default_model
        return self.overrides.get(role) or s.current_model or default_model

    def record_call(
        self, role: str, *, success: bool, timeout: bool,
        latency_ms: float = 0.0, error: bool = False,
    ) -> None:
        """Update rolling stats for one LLM exchange."""
        s = self.stats.setdefault(role, RoleStats(role=role))
        s.total_calls += 1
        if timeout:
            s.timeouts += 1
        elif error:
            s.errors += 1
        elif success:
            s.success += 1
            s.latency_sum_ms += float(latency_ms)

    def tick_iteration(self) -> None:
        """Called by the engagement loop at the start of each iteration."""
        if not self.enabled:
            return
        self.iteration += 1
        for role, s in self.stats.items():
            if self.iteration < s.cooldown_until_iter:
                continue
            if s.total_calls < _MIN_CALLS_BEFORE_DECISION:
                continue
            self._maybe_decide(role, s)

    # ── internals ────────────────────────────────────────────────

    def _maybe_decide(self, role: str, s: RoleStats) -> None:
        ladder = _LADDERS.get(role) or []
        if not ladder:
            return
        try:
            cur_idx = ladder.index(s.current_model) if s.current_model else 0
        except ValueError:
            cur_idx = 0

        # Promote on persistent timeouts
        if s.timeout_ratio > _PROMOTE_TIMEOUT_RATIO and cur_idx + 1 < len(ladder):
            new_model = ladder[cur_idx + 1]
            self.overrides[role] = new_model
            s.current_model = new_model
            s.cooldown_until_iter = self.iteration + _COOLDOWN_ITERATIONS
            log.warning(
                "model_router PROMOTING %s → %s (timeouts %.0f%% over %d calls)",
                role, new_model, s.timeout_ratio * 100, s.total_calls,
            )
            self.save()
            return

        # Demote on long success streak
        if (
            s.total_calls >= _DEMOTE_MIN_CALLS
            and s.timeout_ratio == _DEMOTE_TIMEOUT_RATIO
            and s.success_ratio >= 0.95
            and cur_idx > 0
        ):
            new_model = ladder[cur_idx - 1]
            self.overrides[role] = new_model
            s.current_model = new_model
            s.cooldown_until_iter = self.iteration + _COOLDOWN_ITERATIONS
            log.info(
                "model_router DEMOTING %s → %s (success %.0f%% over %d calls)",
                role, new_model, s.success_ratio * 100, s.total_calls,
            )
            self.save()
            return


__all__ = ["AdaptiveRouter", "RoleStats"]
