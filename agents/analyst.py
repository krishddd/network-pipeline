"""Analyst sub-agent — correlate findings into attack chains.

Phase-3 additions:

* ``critique_finding`` tool — pulls a finding by id, runs the
  ``SelfCritic`` against it, applies the verdict, and persists the
  updated finding back to ``findings.jsonl``. Bounded at 2 passes per
  finding via ``Finding.critic_used``.
* ``synthesize_findings`` tool — runs the confidence-weighted parent /
  child merge from ``core.finding_synthesis``. Lets the analyst
  promote two probable siblings into one verified parent without
  needing the underlying tools to gather a second method.
* ``infer_causal_edges`` tool — builds ``enables`` edges across the
  KG (heuristic; LLM-judged variant is gated by tool-evidence).
"""

from __future__ import annotations

import json
from pathlib import Path

from network_pipeline.agents._common import build_agent
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.schemas import C2Tier, OpsecLevel
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph


def create_analyst_agent(
    *, workspace: Path, config: EngagementConfig, runner=None,
    kg: KnowledgeGraph, findings: FindingsLog, factory: OllamaLLMFactory,
    iteration: int = 0, engagement_id: str = "",
    opsec_level: OpsecLevel | None = None, c2_tier: C2Tier | None = None,
    http_client=None, dns_client=None,
):
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    from network_pipeline.core.causal_kg import infer_causal_edges_heuristic
    from network_pipeline.core.critic import SelfCritic, apply_critique
    from network_pipeline.core.finding_synthesis import synthesize_findings

    # The critic + synthesis use the analyst's own LLM to keep cost
    # contained — no separate role budget. ``factory.get_model("analyst")``
    # is cached, so this is the same instance the agent uses.
    analyst_llm = factory.get_model("analyst")

    @tool
    def critique_finding(finding_id: str) -> str:
        """Run the self-critic against one finding (max 2 passes per finding).

        Updates ``confidence_score``, ``critic_notes``, ``critic_used``
        in place and rewrites ``findings.jsonl`` while PRESERVING any
        existing HMAC signatures (Bug-fix A: the prior implementation
        silently wiped them).
        """
        all_items = findings.all()
        target = next((f for f in all_items if f.id == finding_id), None)
        if target is None:
            return f"finding {finding_id!r} not found"
        critic = SelfCritic(analyst_llm)
        result = critic.critique(target)
        if result is None:
            return f"critic could not produce a verdict for {finding_id}"
        apply_critique(target, result)
        findings.rewrite_all(all_items)
        return (
            f"critic {result.verdict} {finding_id}: severity={target.severity.value}, "
            f"confidence={target.confidence.value}, score={target.confidence_score:.2f}, "
            f"passes={target.critic_used}"
        )

    @tool
    def synthesize_findings_now() -> str:
        """Merge probable sibling findings into verified parents (idempotent).

        Parents are emitted via ``findings.append`` (signs + leafs);
        children's ``superseded_by`` field updates land via
        ``rewrite_all`` which re-signs every line.
        """
        all_items = findings.all()
        new_parents = synthesize_findings(all_items, next_id_fn=findings.next_id)
        if not new_parents:
            return "no synthesis candidates"
        # Append parents through the normal path so they get signed +
        # leafed once. The rewrite below preserves those signatures.
        for parent in new_parents:
            findings.append(parent)
        findings.rewrite_all(all_items + new_parents)
        return (
            f"synthesised {len(new_parents)} parent finding(s): "
            + ", ".join(f"{p.id} {p.severity.value}" for p in new_parents)
        )

    @tool
    def infer_causal_edges() -> str:
        """Add structural ``enables`` edges across the KG (host→port→service→finding)."""
        added = infer_causal_edges_heuristic(kg)
        return f"causal_kg: {added} new enables edges"

    return build_agent(
        "analyst",
        workspace=workspace, config=config, runner=runner,
        kg=kg, findings=findings, factory=factory,
        extra_tools=[critique_finding, synthesize_findings_now, infer_causal_edges],
        iteration=iteration, engagement_id=engagement_id,
        opsec_level=opsec_level, c2_tier=c2_tier,
    )


# Bug-fix A: the previous local rewrite helper silently stripped HMAC
# signatures from every line. All callers now use ``FindingsLog.rewrite_all``
# which preserves (and re-signs when a key is set) every line.
