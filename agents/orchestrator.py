"""Orchestrator agent — engagement lead.

Owns the OPPLAN. Plans objectives, dispatches sub-agents via the
``task`` tool, updates objective status. The actual ralph loop driving
this agent across iterations lives in ``core.engagement_loop``.

The OPPLAN CRUD tools are exposed here as plain @tool wrappers (not
middleware) so they're testable in isolation and obvious in the trace.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from network_pipeline.agents._common import build_agent
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    OPPLAN,
    C2Tier,
    Objective,
    ObjectivePhase,
    ObjectiveStatus,
    OpsecLevel,
)
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph
# ShellRunner removed in pure-Python redesign; runner kept as untyped optional kwarg
# for legacy compat.

log = get_logger("agents.orchestrator")


def _opplan_path(workspace: Path) -> Path:
    return workspace / "plan" / "opplan.json"


def load_opplan(workspace: Path) -> OPPLAN | None:
    path = _opplan_path(workspace)
    if not path.exists():
        return None
    # Explicit UTF-8: opplan.json is written UTF-8 (save_opplan below)
    # but Path.read_text() without encoding= defaults to the OS locale
    # (cp1252 on en-US Windows) and dies on em-dashes / smart quotes
    # baked into the auto-generated objective descriptions.
    return OPPLAN.model_validate_json(path.read_text(encoding="utf-8"))


def save_opplan(workspace: Path, opplan: OPPLAN) -> None:
    """Atomic OPPLAN write — tmp + ``os.replace`` so readers never see
    a half-written file even if the process dies mid-write.
    """
    path = _opplan_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    opplan.last_updated = datetime.now(timezone.utc).isoformat()
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(opplan.model_dump_json(indent=2), encoding="utf-8")
    os.replace(tmp, path)  # atomic on POSIX and NTFS


def make_opplan_tools(workspace: Path):
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    @tool
    def opplan_get() -> str:
        """Return the full OPPLAN as JSON."""
        opplan = load_opplan(workspace)
        if opplan is None:
            return "(no OPPLAN — call opplan_create first)"
        return opplan.model_dump_json(indent=2)

    @tool
    def opplan_create(engagement_name: str) -> str:
        """Create a fresh empty OPPLAN. Errors if one already exists."""
        if _opplan_path(workspace).exists():
            return "OPPLAN already exists; use opplan_add_objective."
        save_opplan(workspace, OPPLAN(engagement_name=engagement_name))
        return f"OPPLAN created for {engagement_name}"

    @tool
    def opplan_add_objective(
        title: str,
        description: str,
        phase: str,
        priority: int = 100,
        acceptance_criteria: list[str] | None = None,
        mitre: list[str] | None = None,
        blocked_by: list[str] | None = None,
    ) -> str:
        """Append an objective to the OPPLAN.
        phase: recon | scan | initial-access | post-exploit | exfiltration.
        """
        opplan = load_opplan(workspace)
        if opplan is None:
            return "no OPPLAN — call opplan_create first"
        try:
            phase_enum = ObjectivePhase(phase)
        except ValueError:
            return f"invalid phase {phase!r}"
        next_n = len(opplan.objectives) + 1
        obj = Objective(
            id=f"OBJ-{next_n:03d}",
            phase=phase_enum,
            title=title,
            description=description,
            acceptance_criteria=acceptance_criteria or [],
            priority=priority,
            mitre=mitre or [],
            blocked_by=blocked_by or [],
        )
        opplan.objectives.append(obj)
        save_opplan(workspace, opplan)
        return f"added {obj.id} ({phase})"

    @tool
    def opplan_update_objective(
        objective_id: str,
        status: str | None = None,
        notes: str = "",
    ) -> str:
        """Update an objective's status and/or notes.
        status: pending | in-progress | completed | blocked | cancelled.
        """
        opplan = load_opplan(workspace)
        if opplan is None:
            return "no OPPLAN"
        obj = opplan.get(objective_id)
        if obj is None:
            return f"unknown objective {objective_id}"
        if status:
            try:
                obj.status = ObjectiveStatus(status)
            except ValueError:
                return f"invalid status {status!r}"
        if notes:
            obj.notes = (obj.notes + "\n" + notes).strip()
        save_opplan(workspace, opplan)
        return f"{objective_id} -> {obj.status.value}"

    @tool
    def opplan_next() -> str:
        """Return the next pending objective (highest priority, deps met)."""
        opplan = load_opplan(workspace)
        if opplan is None:
            return "no OPPLAN"
        nxt = opplan.next_pending()
        if nxt is None:
            return "(no pending objectives)"
        return nxt.model_dump_json(indent=2)

    return [opplan_get, opplan_create, opplan_add_objective,
            opplan_update_objective, opplan_next]


def create_orchestrator_agent(
    *,
    workspace: Path,
    config: EngagementConfig,
    runner=None,
    kg: KnowledgeGraph,
    findings: FindingsLog,
    factory: OllamaLLMFactory,
    iteration: int = 0,
    engagement_id: str = "",
    opsec_level: OpsecLevel | None = None,
    c2_tier: C2Tier | None = None,
    tot_enabled: bool = False,
    rag = None,
    http_client=None,
    dns_client=None,
):
    """Build the orchestrator. The ``task`` dispatcher tool is wired by
    the engagement_loop to avoid a circular import (it needs to know the
    full sub-agent registry).

    When ``tot_enabled=True``, exposes a ``tot_plan_branches`` tool that
    runs the tree-of-thought planner and commits the winning branch as
    a new Objective (priority band 50). The orchestrator system prompt
    nudges the model to use this tool before calling
    ``opplan_next`` on iterations where multiple plausible directions
    exist.
    """
    extra = list(make_opplan_tools(workspace))

    # Phase-4: RAG recall — let the orchestrator query prior engagement
    # findings for the current target signature. Returns a compact
    # text block (top-k items) so the orchestrator can fold the wisdom
    # into next-objective planning.
    if rag is not None:
        from langchain_core.tools import tool  # type: ignore[import-not-found]

        @tool
        def rag_recall(query: str, k: int = 5) -> str:
            """Recall top-k cross-engagement learnings semantically similar to ``query``.

            Embeds locally via Ollama nomic-embed-text and ranks by
            cosine similarity against prior findings/KG-summary items.
            Returns a compact summary; use to seed objectives for
            target classes you've seen before.
            """
            try:
                hits = rag.recall(query, k=int(k))
            except Exception as e:
                return f"[rag_recall failed] {e!r}"
            if not hits:
                return "(rag empty or query embedding failed)"
            lines = [f"top {len(hits)} prior items:"]
            for score, item in hits:
                meta = item.meta or {}
                lines.append(
                    f"  [{score:.2f}] {meta.get('kind', '?')} "
                    f"engagement={meta.get('engagement_id', '')} "
                    f"target={meta.get('target_signature', '')}\n    "
                    + item.text.replace("\n", " ")[:240]
                )
            return "\n".join(lines)

        extra.append(rag_recall)

    if tot_enabled:
        from langchain_core.tools import tool  # type: ignore[import-not-found]

        from network_pipeline.core.tot_planner import TreeOfThoughtPlanner

        orch_llm = factory.get_model("orchestrator")
        planner = TreeOfThoughtPlanner(orch_llm)

        @tool
        def tot_plan_branches(target: str = "", roe_summary: str = "",
                              kg_summary: str = "") -> str:
            """Generate K=3 alternative next-objective branches and commit the winner.

            Inputs are free-form strings. The orchestrator should pass
            the current target, a one-line RoE summary, and a KG
            summary (e.g. node-type histogram) so the planner has
            context to reason over.
            """
            opplan = load_opplan(workspace)
            if opplan is None:
                return "no OPPLAN — call opplan_create first"
            snapshot_dir = workspace / "state_snapshots" / f"iter{iteration:04d}"
            obj = planner.plan(
                opplan=opplan,
                kg_summary=kg_summary or "(empty)",
                target=target or "(unset)",
                roe_summary=roe_summary or "(none)",
                opsec=opsec_level or OpsecLevel.STANDARD,
                snapshot_dir=snapshot_dir,
                iteration=iteration,
            )
            if obj is None:
                return "ToT planner produced no parseable branches"
            save_opplan(workspace, opplan)
            return f"ToT committed {obj.id}: {obj.title}"

        extra.append(tot_plan_branches)

    return build_agent(
        "orchestrator",
        workspace=workspace, config=config, runner=runner,
        kg=kg, findings=findings, factory=factory,
        extra_tools=extra,
        iteration=iteration, engagement_id=engagement_id,
        opsec_level=opsec_level, c2_tier=c2_tier,
    )
