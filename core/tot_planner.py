"""Tree-of-thought planner for the orchestrator (Plan B.2.2).

When ``--tot`` is set, the orchestrator's "what objective should run
next" decision goes through this planner instead of a single-shot
``opplan.next_pending`` call.

Algorithm:

1. Generate ``k`` candidate next-objective branches via one LLM call
   that emits structured JSON (title, description, phase, mitre,
   expected_value 0–10, feasibility 0–10, cost_minutes).
2. Score each branch as ``(value × feasibility) / max(1, cost)``.
3. Commit the top branch back into the OPPLAN as a new Objective at
   priority band 50 (between seeded 10/20/30 and playbook 300+).
4. Persist rejected branches to ``state_snapshots/<n>/tot.json`` for
   later replay / audit.

Hard caps from Plan risk #4: ``k=3``, ``depth=2``. Token spend stays
within the orchestrator role's budget (BudgetGovernor charges the
LLM call on the orchestrator phase).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    OPPLAN,
    Objective,
    ObjectivePhase,
    OpsecLevel,
)

log = get_logger("core.tot_planner")


# ToT priority band — sits between seeded operator objectives and
# playbook-engine work so ToT-suggested branches run early but never
# pre-empt explicitly-planned items.
TOT_PRIORITY_BASE = 50

DEFAULT_K = 3
DEFAULT_DEPTH = 2


class ToTBranch(BaseModel):
    """One LLM-proposed next-objective candidate."""

    title: str
    description: str
    phase: str = "recon"
    mitre: list[str] = Field(default_factory=list)
    expected_value: float = Field(default=5.0, ge=0.0, le=10.0)
    feasibility: float = Field(default=5.0, ge=0.0, le=10.0)
    cost_minutes: float = Field(default=5.0, ge=0.0)
    rationale: str = ""

    model_config = {"extra": "ignore"}

    def score(self) -> float:
        return (self.expected_value * self.feasibility) / max(1.0, self.cost_minutes)


_TOT_SYSTEM_PROMPT = """You are a red-team planner generating attack-path branches.

Given the engagement state (target, current OPPLAN, KG snapshot, RoE
constraints), propose K candidate NEXT objectives. Each must be
within RoE. Return STRICT JSON of the form:

{
  "branches": [
    {
      "title": "short title",
      "description": "what to do, ~3 sentences",
      "phase": "recon" | "scan" | "initial-access" | "post-exploit" | "exfiltration",
      "mitre": ["T1190", ...],
      "expected_value": 0..10,
      "feasibility": 0..10,
      "cost_minutes": positive number,
      "rationale": "one sentence"
    },
    ...
  ]
}

Rules:
- Return EXACTLY {k} branches. No fewer, no more.
- Branches must be DIFFERENT angles (e.g. one recon, one exploit,
  one chain-pivot). Don't propose three variants of the same scan.
- expected_value reflects security impact; feasibility reflects how
  likely this is to actually surface a finding given the KG state.
- Return ONLY the JSON. No prose.
"""


def _parse_branches(text: str) -> list[ToTBranch]:
    if not text:
        return []
    body = text.strip()
    if body.startswith("```"):
        body = body.strip("`")
        if body.lstrip().lower().startswith("json"):
            body = body.split("\n", 1)[-1]
    a = body.find("{")
    b = body.rfind("}")
    if a == -1 or b == -1:
        return []
    try:
        data = json.loads(body[a:b + 1])
    except json.JSONDecodeError:
        return []
    raw_branches = data.get("branches") or []
    out: list[ToTBranch] = []
    for r in raw_branches:
        try:
            out.append(ToTBranch.model_validate(r))
        except ValidationError as e:
            log.warning("tot branch invalid: %r", e)
    return out


class TreeOfThoughtPlanner:
    """Single-pass branch generator + scorer.

    ``depth`` is reserved for a future deeper search; today the
    implementation is depth=1 (one round of branches) which covers the
    "diversify before committing" use case without the cost of a real
    DFS. depth>1 → multi-step look-ahead, deferred per Plan risk #4.
    """

    def __init__(
        self,
        llm: Any,
        *,
        k: int = DEFAULT_K,
        depth: int = DEFAULT_DEPTH,
    ) -> None:
        self._llm = llm
        self._k = max(1, min(5, int(k)))
        self._depth = max(1, min(2, int(depth)))

    def plan(
        self,
        *,
        opplan: OPPLAN,
        kg_summary: str,
        target: str,
        roe_summary: str,
        opsec: OpsecLevel = OpsecLevel.STANDARD,
        snapshot_dir: Path | None = None,
        iteration: int = 0,
    ) -> Objective | None:
        """Generate, score, and commit the winning branch as an Objective.

        Returns the Objective the caller should run next, or None when
        branch generation fails (caller should fall back to
        ``opplan.next_pending``).
        """
        try:
            from langchain_core.messages import (  # type: ignore[import-not-found]
                HumanMessage, SystemMessage,
            )
            user = (
                f"Target: {target}\n"
                f"OPSEC: {opsec.value}\n"
                f"RoE summary: {roe_summary}\n"
                f"KG snapshot:\n{kg_summary}\n\n"
                f"Existing pending objectives ({len(opplan.objectives)}):\n"
                + "\n".join(
                    f"- {o.id} [{o.phase.value}] {o.title}"
                    for o in opplan.objectives[:20]
                )
                + f"\n\nReturn exactly {self._k} branches."
            )
            messages = [
                SystemMessage(content=_TOT_SYSTEM_PROMPT.replace("{k}", str(self._k))),
                HumanMessage(content=user),
            ]
            resp = self._llm.invoke(messages)
            text = getattr(resp, "content", "") or ""
        except Exception as e:  # pragma: no cover - defensive
            log.warning("ToT LLM call failed: %r", e)
            return None

        branches = _parse_branches(text)
        if not branches:
            log.warning("ToT produced no parseable branches; falling back")
            return None

        # Persist all branches for replay / audit
        if snapshot_dir is not None:
            try:
                snapshot_dir.mkdir(parents=True, exist_ok=True)
                (snapshot_dir / "tot.json").write_text(
                    json.dumps(
                        [b.model_dump() | {"score": b.score()} for b in branches],
                        indent=2,
                    ),
                    encoding="utf-8",
                    encoding="utf-8",
                )
            except OSError as e:  # pragma: no cover - defensive
                log.warning("ToT snapshot write failed: %r", e)

        # Score + pick winner
        winner = max(branches, key=lambda b: b.score())
        try:
            phase = ObjectivePhase(winner.phase)
        except ValueError:
            phase = ObjectivePhase.RECON
            log.warning("ToT branch had invalid phase %r; defaulting to recon", winner.phase)

        next_n = len(opplan.objectives) + 1
        obj = Objective(
            id=f"OBJ-TOT{next_n:03d}",
            phase=phase,
            title=winner.title,
            description=(
                f"[ToT-selected, score={winner.score():.2f}, "
                f"value={winner.expected_value}, feas={winner.feasibility}, "
                f"cost={winner.cost_minutes}m]\n{winner.description}\n\n"
                f"Rationale: {winner.rationale}"
            ),
            acceptance_criteria=[
                "Branch produces at least one KG node or finding",
                "Wall-clock under cost_minutes × 2",
            ],
            priority=TOT_PRIORITY_BASE + iteration,
            mitre=list(winner.mitre),
            opsec=opsec,
            synthesized_from=f"tot:iter{iteration}",
        )
        opplan.objectives.append(obj)
        log.info(
            "ToT committed %s (score %.2f from %d branches)",
            obj.id, winner.score(), len(branches),
        )
        return obj


__all__ = [
    "DEFAULT_DEPTH",
    "DEFAULT_K",
    "TOT_PRIORITY_BASE",
    "ToTBranch",
    "TreeOfThoughtPlanner",
]
