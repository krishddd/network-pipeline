"""Defender sub-agent — vaccine phase, produces defense_brief.json."""

from __future__ import annotations

import json
from pathlib import Path

from network_pipeline.agents._common import build_agent
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.schemas import C2Tier, OpsecLevel
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph


def create_defender_agent(
    *, workspace: Path, config: EngagementConfig, runner=None,
    kg: KnowledgeGraph, findings: FindingsLog, factory: OllamaLLMFactory,
    iteration: int = 0, engagement_id: str = "",
    opsec_level: OpsecLevel | None = None, c2_tier: C2Tier | None = None,
    http_client=None, dns_client=None,
):
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    brief_path = workspace / "defense_brief.json"

    @tool
    def list_findings() -> str:
        """Return all findings (id, severity, target, title)."""
        items = findings.all()
        return "\n".join(
            f"- {f.id} [{f.severity.value}] {f.affected_target}: {f.title}"
            for f in items
        ) or "(no findings)"

    @tool
    def write_defense_brief(recommendations: list[dict]) -> str:
        """Write the defense brief to ``defense_brief.json``.
        recommendations: list of {finding_ids, root_cause, patch, detection, hardening}.

        Phase-7: each recommendation is ALSO materialised as a
        DefenseAction node in the KG with MITIGATES + RESPONDS_TO edges
        back to every listed finding_id. The vaccine remains read-only
        — no infrastructure mutation backend is invoked; the graph
        annotations are pure metadata for the Mermaid attack-chain
        report.
        """
        payload = {"recommendations": recommendations}
        brief_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        emitted = 0
        for idx, rec in enumerate(recommendations or [], start=1):
            if not isinstance(rec, dict):
                continue
            finding_ids = rec.get("finding_ids") or []
            if not isinstance(finding_ids, list):
                continue
            action_id = rec.get("id") or f"REC-{idx:03d}"
            title = str(rec.get("title") or rec.get("root_cause") or action_id)
            try:
                kg.add_defense_action(
                    action_id=str(action_id),
                    title=title,
                    finding_ids=[str(f) for f in finding_ids],
                    root_cause=str(rec.get("root_cause", "")),
                    patch=str(rec.get("patch", "")),
                    detection=str(rec.get("detection", "")),
                    hardening=str(rec.get("hardening", "")),
                )
                emitted += 1
            except Exception:
                # Graph-side annotation must not block the brief itself.
                pass
        return (
            f"defense brief written: {brief_path} "
            f"({len(recommendations)} recommendations, "
            f"{emitted} DefenseAction nodes emitted)"
        )

    return build_agent(
        "defender",
        workspace=workspace, config=config, runner=runner,
        kg=kg, findings=findings, factory=factory,
        extra_tools=[list_findings, write_defense_brief],
        iteration=iteration, engagement_id=engagement_id,
        opsec_level=opsec_level, c2_tier=c2_tier,
    )
