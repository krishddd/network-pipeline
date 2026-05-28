"""Engagement state machine and per-iteration result types.

Ported from Decepticon-main/decepticon/core/engagement.py with the
Decepticon-specific ``langgraph_url`` removed (we run agents in-process,
not via the LangGraph Platform HTTP API).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class EngagementPhase(str, Enum):
    PLANNING = "planning"
    ATTACK = "attack"
    VACCINE = "vaccine"
    COMPLETE = "complete"


class VaccineMode(str, Enum):
    BATCH = "batch"
    IMMEDIATE = "immediate"


class EngagementConfig(BaseModel):
    """Configuration for one engagement run."""

    target: str = Field(description="Primary target spec (URL, domain, or CIDR)")
    workspace: Path = Field(description="Per-engagement workspace directory")
    max_iterations: int = 50
    iteration_max_seconds: int = Field(
        default=600, description="Per-iteration wall-clock cap. Backstop for stuck agents."
    )
    vaccine_mode: VaccineMode = VaccineMode.BATCH
    ollama_base_url: str = "http://localhost:11434"
    profile: str = Field(
        default="eco",
        description="Model profile: eco | max | test | cloud_eco | cloud_max | hybrid (see llm/profiles.py)",
    )
    provider_overrides: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Per-role provider pin, e.g. {'exploit': 'ollama', 'analyst': 'anthropic'}. "
            "Overrides the profile's provider for that role. Provider values: ollama | openai | anthropic."
        ),
    )
    openai_base_url: str | None = Field(
        default=None,
        description="Optional OpenAI-compatible endpoint (vLLM, OpenRouter, ...).",
    )
    anthropic_base_url: str | None = Field(
        default=None,
        description="Optional Anthropic base URL override.",
    )
    budget_usd: float | None = Field(
        default=None,
        description="Hard cap on cumulative cloud spend (USD). None = unlimited.",
    )
    structured_reasoning: bool = Field(
        default=True,
        description=(
            "Phase-2 SIRAJ-style structured reasoning contract. When True "
            "(default), every agent prompt gets the 4-component reasoning "
            "JSON contract appended and reasoning_tokens are logged to "
            "agent_traces.log. Set False to A/B compare against free-form."
        ),
    )
    cop_enabled: bool = Field(
        default=True,
        description=(
            "Phase-3 CoP (Composition-of-Principles) payload synthesis. "
            "When True (default), the exploit agent gets a "
            "`cop_compose_payloads` tool that synthesises and dual-judges "
            "candidates. Set False to A/B compare against single-payload mode."
        ),
    )
    agent_selection: dict[str, str] = Field(
        default_factory=lambda: {
            "recon": "recon",
            "scan": "scanner",
            "initial-access": "exploit",
            "post-exploit": "postexploit",
            "exfiltration": "postexploit",
        },
        description="Maps ObjectivePhase → sub-agent name",
    )


class IterationResult(BaseModel):
    objective_id: str
    agent_used: str
    outcome: str = Field(description="COMPLETED | BLOCKED | ERROR")
    findings_produced: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    error: str | None = None


class EngagementState(BaseModel):
    """Persisted loop state — written to ``workspace/.engagement-state.json``."""

    engagement_id: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("eng-%Y%m%d-%H%M%S"))
    phase: EngagementPhase = EngagementPhase.PLANNING
    iteration: int = 0
    max_iterations: int = 50
    current_objective_id: str | None = None
    objectives_completed: list[str] = Field(default_factory=list)
    objectives_blocked: list[str] = Field(default_factory=list)
    findings_discovered: list[str] = Field(default_factory=list)
    iteration_history: list[IterationResult] = Field(default_factory=list)
    workspace: str = ""
    target: str = ""
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resumed_at: datetime | None = None

    # ── persistence ────────────────────────────────────────────────

    def save(self, workspace: Path) -> None:
        workspace.mkdir(parents=True, exist_ok=True)
        state_file = workspace / ".engagement-state.json"
        tmp = state_file.with_suffix(".json.tmp")
        tmp.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(state_file)

    @classmethod
    def load(cls, workspace: Path) -> "EngagementState | None":
        state_file = workspace / ".engagement-state.json"
        if not state_file.exists():
            return None
        return cls.model_validate_json(state_file.read_text(encoding="utf-8"))

    # ── derived ────────────────────────────────────────────────────

    @property
    def is_complete(self) -> bool:
        return (
            self.iteration >= self.max_iterations
            or self.phase == EngagementPhase.COMPLETE
        )

    @property
    def summary(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "phase": self.phase,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "completed": len(self.objectives_completed),
            "blocked": len(self.objectives_blocked),
            "findings": len(self.findings_discovered),
        }


def snapshot_state(workspace: Path, iteration: int, payload: dict) -> Path:
    """Dump a per-iteration LangGraph state snapshot for replay debugging."""
    snap_dir = workspace / "state_snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)
    path = snap_dir / f"{iteration:04d}.json"
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path
