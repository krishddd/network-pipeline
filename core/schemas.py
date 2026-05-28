"""Engagement document schemas — RoE, CONOPS, OPPLAN, Finding.

Ported from Decepticon-main/decepticon/core/schemas.py and trimmed to the
network-pentest subset. AD/cloud/contract-specific fields removed.

Severity reuses the existing Security_module taxonomy where possible
(see ``models.enums.Severity``) so reports can be merged across the ASI
suite and the network pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum


def _utcnow_iso() -> str:
    """Timezone-aware UTC ISO-8601 timestamp (Python 3.12+ safe)."""
    return datetime.now(timezone.utc).isoformat()


def _utcnow_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()

from pydantic import BaseModel, Field, model_validator

# ── Enums ─────────────────────────────────────────────────────────────


class EngagementType(str, Enum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    HYBRID = "hybrid"
    ASSUMED_BREACH = "assumed-breach"


class ObjectivePhase(str, Enum):
    """Kill-chain phases for objective ordering and sub-agent routing."""

    RECON = "recon"
    SCAN = "scan"
    INITIAL_ACCESS = "initial-access"
    POST_EXPLOIT = "post-exploit"
    EXFILTRATION = "exfiltration"
    # Phase-6: LLM-target red-team objectives (prompt injection,
    # jailbreak, RAG poisoning, multi-turn HRL). Routed to the
    # ``llm_redteam`` specialist agent.
    LLM_REDTEAM = "llm-redteam"


class OpsecLevel(str, Enum):
    LOUD = "loud"
    STANDARD = "standard"
    CAREFUL = "careful"
    QUIET = "quiet"
    SILENT = "silent"


class ObjectiveStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class FindingSeverity(str, Enum):
    """CVSS-aligned severity levels.

    Mirrors ``Security_module.models.enums.Severity`` values (lowercased
    here to match Decepticon convention; the report adapter handles the
    case mapping).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingConfidence(str, Enum):
    VERIFIED = "verified"
    PROBABLE = "probable"
    UNVERIFIED = "unverified"


class C2Tier(str, Enum):
    """C2 infrastructure tier for objective execution (mirrors Decepticon)."""

    INTERACTIVE = "interactive"  # seconds callback
    SHORT_HAUL = "short-haul"  # minutes-hours callback
    LONG_HAUL = "long-haul"  # hours-days persistent fallback


class RemediationPriority(str, Enum):
    """Remediation urgency aligned with PTES/CREST reporting standards."""

    IMMEDIATE = "immediate"  # 0-7 days
    SHORT_TERM = "short-term"  # ~30 days
    LONG_TERM = "long-term"  # 90+ days


# ── Evidence + Finding ───────────────────────────────────────────────


class Evidence(BaseModel):
    type: str = Field(description="screenshot | http-request | terminal-log | scan-output | artifact")
    path: str = Field(description="Relative path within the engagement workspace")
    description: str = ""
    sha256: str = ""
    collected_at: str = Field(default_factory=lambda: _utcnow_iso())


class Finding(BaseModel):
    """A single discovered vulnerability or noteworthy observation."""

    id: str = Field(description="FIND-001, FIND-002, ...")
    title: str
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.PROBABLE
    cvss_score: float | None = None
    cvss_vector: str = ""
    cwe: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list, description="ATT&CK technique IDs")

    # Where
    affected_target: str
    affected_component: str = ""

    # What
    description: str
    steps_to_reproduce: list[str] = Field(default_factory=list)
    impact: str = ""

    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str = ""
    remediation_priority: RemediationPriority | None = None

    # Detection gap tracking (Purple Team / TIBER-EU — mirrors Decepticon)
    detected: bool = False
    detection_notes: str = ""

    # Verification methods used (enforced for CRITICAL/HIGH via validator below)
    verified_methods: list[str] = Field(default_factory=list)

    # Provenance
    objective_id: str = ""
    phase: ObjectivePhase | None = None
    agent: str = ""
    iteration: int = 0
    discovered_at: str = Field(default_factory=lambda: _utcnow_iso())

    # ── Phase-3 cognitive additions (defaulted → backward-compat) ──
    # See plan B.2.1 (self-critique) and B.2.4 (synthesis).
    confidence_score: float = Field(
        default=1.0,
        description="0.0–1.0 numeric confidence emitted by the self-critic.",
    )
    critic_notes: str = ""
    critic_used: int = Field(
        default=0,
        description="Number of critic passes; capped at 2 to prevent loops.",
    )
    superseded_by: str | None = Field(
        default=None,
        description=(
            "Finding id of the parent finding this one was merged into "
            "by confidence-weighted synthesis. None = primary."
        ),
    )

    # ── Phase-6: LLM-target attack metadata ─────────────────────────
    # Free-form bag keyed for the LLM red-team scanners. Kept out of the
    # core schema so non-LLM findings don't pay for the fields. Known
    # keys (by convention, not enforced):
    #   attack_type:           "prompt_injection" | "jailbreak_cop" |
    #                          "rag_poisoning" | "multi_turn_jailbreak" |
    #                          "persona_probe"
    #   asr_score:             float in 0..1, attack success metric
    #   transferability_notes: str, notes on cross-model behaviour
    #   principles_used:       list[str] (CoP)
    #   judge_verdicts:        list[dict]
    attack_metadata: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def _enforce_finding_protocol(self) -> "Finding":
        """Decepticon finding-protocol gate.

        CRITICAL/HIGH severity requires confidence=VERIFIED AND at least
        two entries in ``verified_methods``. All other severities are
        unrestricted.
        """
        gated = {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
        if self.severity in gated:
            if self.confidence != FindingConfidence.VERIFIED:
                raise ValueError(
                    f"{self.severity.value} severity requires "
                    f"confidence=verified (got {self.confidence.value})"
                )
            if len(self.verified_methods) < 2:
                raise ValueError(
                    f"{self.severity.value} severity requires "
                    f">=2 verified_methods (got {len(self.verified_methods)})"
                )
        return self


# ── Rules of Engagement ──────────────────────────────────────────────


class ScopeEntry(BaseModel):
    target: str = Field(description="Domain, IP, or CIDR")
    type: str = Field(description="domain | ip | cidr | url")
    notes: str = ""
    # Per-target capability override (B.4.3). When ``mode="paranoid"`` the
    # argv guard strips offensive tools for THIS target only, even at
    # OPSEC=loud. Useful for "in scope but customer asked us to be gentle".
    mode: str = Field(
        default="normal",
        description="normal | paranoid — paranoid forces silent OPSEC for this target",
    )


class EscalationContact(BaseModel):
    name: str
    role: str = ""
    channel: str = ""
    available: str = "24/7"


class RoE(BaseModel):
    """Rules of Engagement — checked at the start of every loop iteration."""

    engagement_name: str
    client: str = ""
    start_date: str = Field(default_factory=lambda: _utcnow_date())
    end_date: str = ""
    engagement_type: EngagementType = EngagementType.EXTERNAL
    testing_window: str = "24/7"

    in_scope: list[ScopeEntry] = Field(default_factory=list)
    out_of_scope: list[ScopeEntry] = Field(default_factory=list)

    prohibited_actions: list[str] = Field(
        default_factory=lambda: [
            "Denial of Service (DoS/DDoS) against production",
            "Modification or deletion of production data",
            "Exfiltration of real customer data",
        ]
    )
    permitted_actions: list[str] = Field(default_factory=list)

    escalation_contacts: list[EscalationContact] = Field(default_factory=list)
    incident_procedure: str = (
        "Stop immediately, document the incident, notify engagement lead within 15 minutes."
    )
    authorization_reference: str = ""
    cleanup_required: bool = True
    version: str = "1.0"

    # ── Phase-5: human review stamp ─────────────────────────────────
    reviewed_by: str = Field(
        default="",
        description=(
            "Set by `soundwave review <ws>` — usually a git user / "
            "operator handle. `cli run` warns (not blocks) when empty so "
            "operators know an unreviewed plan was used."
        ),
    )
    reviewed_at: str = Field(
        default="",
        description="ISO-8601 UTC timestamp set alongside reviewed_by.",
    )

    # ── Phase-5/6: destructive-write gate for RAG poisoning + writes ─
    allow_destructive_writes: bool = Field(
        default=False,
        description=(
            "Master switch for Phase-6 rag_poisoning + any other write-"
            "side scanner. MUST be explicitly True AND the endpoint must "
            "match `write_allowlist`. Default False refuses every write."
        ),
    )
    write_allowlist: list[str] = Field(
        default_factory=list,
        description=(
            "Endpoint URL substrings that may receive write traffic when "
            "allow_destructive_writes=True. Exact substring match — "
            "scope_guard's CIDR/domain logic does not apply here."
        ),
    )


# ── Deconfliction ────────────────────────────────────────────────────


class Deconfliction(BaseModel):
    """SOC-facing deconfliction plan.

    Decepticon-style attribution markers so the blue team can tell
    authorised red-team traffic from real adversaries during an
    engagement. Mirrors the structure in the README plan.
    """

    engagement_name: str
    source_ips: list[str] = Field(
        default_factory=list,
        description="IP addresses the engagement will originate from.",
    )
    time_windows: list[str] = Field(
        default_factory=list,
        description=(
            "Allowed operational windows, e.g. 'Mon-Fri 09:00-18:00 UTC'. "
            "Free text — operators schedule manually around these."
        ),
    )
    shared_signature: str = Field(
        default="",
        description=(
            "Unique attribution marker echoed on every probe — typically "
            "set as a custom User-Agent (`network_pipeline-redteam/<sig>`). "
            "The engagement loop reads this and applies it to "
            "HTTPClient + scanner subprocesses."
        ),
    )
    soc_contacts: list[EscalationContact] = Field(
        default_factory=list,
        description="Who to ping on the SOC side if a stop-card is needed.",
    )
    stop_card_phrase: str = Field(
        default="STOP RED TEAM — DECONFLICT",
        description="Free-text out-of-band phrase the SOC can use to halt the engagement.",
    )
    version: str = "1.0"


# ── CONOPS ───────────────────────────────────────────────────────────


class ThreatActor(BaseModel):
    name: str
    sophistication: str = "medium"
    motivation: str = ""
    initial_access: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)


class CONOPS(BaseModel):
    engagement_name: str
    executive_summary: str = ""
    threat_actors: list[ThreatActor] = Field(default_factory=list)
    attack_narrative: str = ""
    methodology: str = "PTES + MITRE ATT&CK"
    success_criteria: list[str] = Field(default_factory=list)


# ── OPPLAN ───────────────────────────────────────────────────────────


class SuccessOracle(BaseModel):
    """Declarative success signal for HRL-driven multi-turn attacks.

    Used by the reward function in ``core/hrl_trajectory.py``. Kept
    deliberately small: the model can author one of these without
    needing to embed Python predicates in the OPPLAN.
    """

    pattern: str = Field(
        description=(
            "Regex (Python flavour) the oracle searches for. Match → +1.0. "
            "Use anchors (^/$) when the signal is line-based."
        ),
    )
    where: str = Field(
        default="response_body",
        description=(
            "Where to match: response_body | response_headers | "
            "response_status | response_cookies | combined."
        ),
    )
    description: str = Field(
        default="",
        description="Human-readable note for the report — what success looks like.",
    )


class Objective(BaseModel):
    id: str = Field(description="OBJ-001, OBJ-002, ...")
    phase: ObjectivePhase
    title: str
    description: str
    acceptance_criteria: list[str] = Field(default_factory=list)
    priority: int = Field(
        default=100,
        description=(
            "Execution order: LOWER value runs FIRST. next_pending() "
            "picks min(priority) across pending objectives whose "
            "blocked_by dependencies are all completed."
        ),
    )
    status: ObjectiveStatus = ObjectiveStatus.PENDING
    mitre: list[str] = Field(default_factory=list)
    opsec: OpsecLevel = OpsecLevel.STANDARD
    c2_tier: C2Tier | None = None
    blocked_by: list[str] = Field(default_factory=list)
    notes: str = ""
    parent_id: str | None = None

    # ── Adaptive retry on BLOCKED/TIMEOUT ──────────────────────────
    retries: int = Field(
        default=0,
        description="Number of times this objective has been re-dispatched.",
    )
    max_retries: int = Field(
        default=3,
        description="Upper bound on retries before objective is final-BLOCKED.",
    )
    retry_hints: list[str] = Field(
        default_factory=list,
        description=(
            "Free-form hints appended by the engagement loop on each retry "
            "(e.g. 'narrow port range to 1-1024', 'skip nuclei templates')."
        ),
    )

    # ── Provenance for KG-driven auto-synthesised objectives ───────
    synthesized_from: str | None = Field(
        default=None,
        description=(
            "If set, the KG node id (or iteration tag) this objective "
            "was auto-generated from. Human-authored objectives leave None."
        ),
    )

    # ── Phase-4: HRL multi-turn trajectory optimisation ─────────────
    multi_turn: bool = Field(
        default=False,
        description=(
            "When True, the engagement loop dispatches this objective to "
            "the HRL attacker (high-level strategy policy + low-level "
            "token policy) instead of the standard single-shot ReAct "
            "agent. Use for objectives that require chained, "
            "context-dependent exchanges — auth bypass, IDOR walks, "
            "multi-step credential access."
        ),
    )
    max_turns: int = Field(
        default=8,
        description="Hard cap on HRL attacker turns. Ignored when multi_turn=False.",
    )
    success_oracle: SuccessOracle | None = Field(
        default=None,
        description=(
            "Per-objective predicate that, when satisfied, contributes "
            "the +1.0 terminal reward in the HRL reward function. "
            "Required for multi_turn=True objectives; without one the "
            "attacker falls back to the orchestrator's non-refusal "
            "heuristic and logs a warning."
        ),
    )


# ── Budget + Seed state (Phase 1) ────────────────────────────────────


class BudgetState(BaseModel):
    """Per-engagement token + wall-time budget.

    The BudgetGovernor decrements these as agents make LLM calls and
    subprocess invocations. ``per_phase_tokens`` lets the operator cap
    individual phases (e.g. exploit phase usually dominates spend).
    Defaults are unbounded (None = no cap) so legacy snapshots are
    backwards-compatible.
    """

    total_tokens: int | None = Field(
        default=None,
        description="Hard cap on total prompt+completion tokens. None = unlimited.",
    )
    total_seconds: int | None = Field(
        default=None,
        description="Hard cap on engagement wall-clock seconds. None = unlimited.",
    )
    per_phase_tokens: dict[str, int] = Field(
        default_factory=dict,
        description="Phase name → token cap, e.g. {'exploit': 200000}.",
    )
    # Live counters — incremented as the engagement runs
    tokens_used: int = 0
    seconds_used: float = 0.0
    per_phase_used: dict[str, int] = Field(default_factory=dict)

    @classmethod
    def unlimited(cls) -> "BudgetState":
        return cls()


class SeedState(BaseModel):
    """Reproducibility seed — applied to random / Ollama / decoy jitter."""

    seed: int = 0
    seeded: bool = False


class OPPLAN(BaseModel):
    engagement_name: str
    objectives: list[Objective] = Field(default_factory=list)
    version: str = "1.0"
    last_updated: str = Field(default_factory=lambda: _utcnow_iso())
    # Phase-1 additions — defaulted so existing snapshots still load.
    seed: SeedState = Field(default_factory=SeedState)
    budget: BudgetState = Field(default_factory=BudgetState.unlimited)

    def next_pending(self) -> Objective | None:
        """Return the next pending objective whose deps are met.

        "Next" = lowest ``priority`` value (ascending — 10 runs before 20).
        """
        completed_ids = {
            o.id for o in self.objectives if o.status == ObjectiveStatus.COMPLETED
        }
        candidates = [
            o
            for o in self.objectives
            if o.status == ObjectiveStatus.PENDING
            and all(dep in completed_ids for dep in o.blocked_by)
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda o: o.priority)

    def get(self, objective_id: str) -> Objective | None:
        for o in self.objectives:
            if o.id == objective_id:
                return o
        return None
