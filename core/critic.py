"""Self-critic loop (Plan B.2.1).

After the exploit / postexploit agent records a finding, the analyst
is invoked in a critic role: it re-reads the finding + evidence and
either upholds it (raising confidence_score), downgrades severity,
rejects it (sets superseded_by sentinel), or asks for more evidence
(synthesises a follow-up objective).

Hard caps from the plan's risk #3:

* ``critic_used`` counter on the Finding is incremented every pass.
* Maximum 2 passes per finding — after that, the analyst can only
  uphold or downgrade, never re-queue for more evidence.
* If the critic itself errors / times out, the finding is left as the
  agent emitted it; the engagement loop never blocks on critic failure.

The critic is intentionally model-side cheap: a single LLM call with a
strict JSON schema response. We use ``with_structured_output`` when the
model supports it, falling back to JSON-in-text parsing otherwise.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import Finding, FindingConfidence, FindingSeverity

log = get_logger("core.critic")


# Hard cap — Plan risk #3.
MAX_CRITIC_PASSES = 2


# ── Verdict schema ───────────────────────────────────────────────────


class CritiqueResult(BaseModel):
    """Structured critic response. Fed straight back into Finding fields."""

    verdict: str = Field(
        description="upheld | downgrade | reject | needs-evidence",
    )
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    new_severity: str | None = Field(
        default=None,
        description="If verdict='downgrade', the new severity (low/medium/high/critical/informational).",
    )
    notes: str = Field(
        default="",
        description="One-paragraph rationale for the verdict. Surfaces in Finding.critic_notes.",
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="If verdict='needs-evidence', concrete checks the agent should perform on retry.",
    )
    follow_up_title: str = ""
    follow_up_description: str = ""

    model_config = {"extra": "ignore"}


# ── Prompt ───────────────────────────────────────────────────────────


_CRITIC_SYSTEM_PROMPT = """You are a finding critic for a network/web pentest pipeline.

Read the supplied Finding (severity, confidence, evidence, verified_methods,
description) and return STRICT JSON matching this schema:

{
  "verdict": "upheld" | "downgrade" | "reject" | "needs-evidence",
  "confidence_score": 0.0..1.0,
  "new_severity": null | "informational" | "low" | "medium" | "high" | "critical",
  "notes": "one paragraph",
  "missing_evidence": ["check 1", "check 2"],
  "follow_up_title": "",
  "follow_up_description": ""
}

Rules:
1. UPHOLD only when the verified_methods list contains ≥2 distinct methods
   AND each method is concretely supported by the evidence text.
2. DOWNGRADE when the impact described is real but the severity is inflated
   relative to standard CVSS guidance — set new_severity accordingly.
3. REJECT when the finding looks like a false positive (e.g. tool output
   echoes a payload but the response shows no real impact).
4. NEEDS-EVIDENCE when one more concrete check would confirm the finding —
   list the checks in missing_evidence and propose a follow_up_title /
   follow_up_description for a retry objective.
5. Set confidence_score in [0.0, 1.0] reflecting your overall confidence.
6. Return ONLY the JSON object. No prose before or after.
"""


def _render_finding(finding: Finding) -> str:
    """Render the finding as a stable, copy-pasteable string for the critic."""
    evidence_lines = "\n".join(
        f"- {e.type}: {e.path} — {e.description}" for e in finding.evidence
    ) or "(no evidence attached)"
    repro = "\n".join(f"- {s}" for s in finding.steps_to_reproduce) or "(none)"
    return (
        f"Finding {finding.id}: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"Confidence: {finding.confidence.value} (score={finding.confidence_score})\n"
        f"Affected target: {finding.affected_target}\n"
        f"CWE: {finding.cwe} | MITRE: {finding.mitre}\n"
        f"Verified methods: {finding.verified_methods}\n"
        f"Description:\n{finding.description}\n"
        f"Steps to reproduce:\n{repro}\n"
        f"Evidence:\n{evidence_lines}\n"
        f"Impact: {finding.impact}\n"
    )


# ── Critic ───────────────────────────────────────────────────────────


def _coerce_severity(value: str | None) -> FindingSeverity | None:
    if not value:
        return None
    try:
        return FindingSeverity(value.lower())
    except ValueError:
        return None


def _parse_response(text: str) -> CritiqueResult | None:
    """Pull a JSON object out of a possibly-noisy LLM response."""
    if not text:
        return None
    candidate = text.strip()
    # Common: model wraps JSON in ```json fences. Strip them.
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        if candidate.lstrip().lower().startswith("json"):
            candidate = candidate.split("\n", 1)[-1]
    # Heuristic: take the substring from the first { to the last }.
    a = candidate.find("{")
    b = candidate.rfind("}")
    if a == -1 or b == -1 or b <= a:
        return None
    blob = candidate[a:b + 1]
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return None
    try:
        return CritiqueResult.model_validate(data)
    except ValidationError as e:  # pragma: no cover - defensive
        log.warning("critic JSON validate failed: %r", e)
        return None


class SelfCritic:
    """Wraps an LLM as a critic. Stateless beyond the bound model."""

    def __init__(self, llm: Any) -> None:
        self._llm = llm

    def critique(self, finding: Finding) -> CritiqueResult | None:
        """Run one critic pass; returns None on transport / parse failure."""
        if finding.critic_used >= MAX_CRITIC_PASSES:
            log.info(
                "critic skipped %s — already at cap (%d passes)",
                finding.id, finding.critic_used,
            )
            return None
        try:
            from langchain_core.messages import (  # type: ignore[import-not-found]
                HumanMessage, SystemMessage,
            )
            messages = [
                SystemMessage(content=_CRITIC_SYSTEM_PROMPT),
                HumanMessage(content=_render_finding(finding)),
            ]
            resp = self._llm.invoke(messages)
            text = getattr(resp, "content", "") or ""
        except Exception as e:  # pragma: no cover - defensive
            log.warning("critic LLM call failed for %s: %r", finding.id, e)
            return None
        result = _parse_response(text)
        if result is None:
            log.warning(
                "critic returned unparseable response for %s (first 200 chars: %r)",
                finding.id, text[:200],
            )
        return result


# ── Application helpers ──────────────────────────────────────────────


def apply_critique(finding: Finding, result: CritiqueResult) -> Finding:
    """Mutate ``finding`` per the critic's verdict.

    Always increments ``critic_used`` so subsequent passes converge.
    For ``reject`` we set ``superseded_by="critic-reject"`` as a
    sentinel so the report writer can hide it without losing the
    audit trail.
    """
    finding.critic_used = min(finding.critic_used + 1, MAX_CRITIC_PASSES)
    finding.confidence_score = float(result.confidence_score)
    finding.critic_notes = (
        finding.critic_notes + ("\n" if finding.critic_notes else "") + result.notes
    ).strip()
    verdict = result.verdict.lower()
    if verdict == "upheld":
        finding.confidence = FindingConfidence.VERIFIED
    elif verdict == "downgrade":
        new_sev = _coerce_severity(result.new_severity)
        if new_sev is not None:
            finding.severity = new_sev
        finding.confidence = FindingConfidence.PROBABLE
    elif verdict == "reject":
        finding.superseded_by = "critic-reject"
        finding.confidence = FindingConfidence.UNVERIFIED
    elif verdict == "needs-evidence":
        finding.confidence = FindingConfidence.PROBABLE
    log.info(
        "critic %s on %s: severity=%s confidence=%s score=%.2f",
        verdict, finding.id, finding.severity.value,
        finding.confidence.value, finding.confidence_score,
    )
    return finding


__all__ = [
    "MAX_CRITIC_PASSES",
    "CritiqueResult",
    "SelfCritic",
    "apply_critique",
]
