"""CoP (Composition-of-Principles) payload composer.

Single-pass payload synthesiser that the exploit agent calls when it
wants something more imaginative than a templated SQLi/XSS string.

Pipeline:

  1. ``sample_compositions`` enumerates compatible principle tuples
     from the YAML library (deterministic when ``seed`` is set).
  2. Each composition is rendered through ``compose_payload``, threading
     {intent} / {target} / {vuln_class} through the principle templates.
  3. ``DualJudge.score_batch`` scores all candidates concurrently.
  4. Results are sorted by combined_score and the top-K returned.

The composer is intentionally *stateless* w.r.t. LLM calls — it only
does the YAML+template synthesis and delegates judging. Keeping it
deterministic per (seed, intent, vuln_class) makes A/B comparison
trivial and keeps the judging budget predictable.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

from network_pipeline.agents.judge import DualJudge, JudgeConfig, JudgedPayload
from network_pipeline.core.logging import get_logger
from network_pipeline.core.principles import (
    Principle,
    PrinciplesError,
    compose_payload,
    sample_compositions,
)
from network_pipeline.llm import LLMFactory, Provider

log = get_logger("agents.cop_composer")


@dataclass
class CoPRequest:
    """Operator/agent input to the composer."""

    intent: str               # the underlying offensive ask, e.g. "extract admin session cookie"
    vuln_class: str           # canonical class name, e.g. "sqli", "xss", "auth_bypass"
    target: str = ""          # target URL / host / param
    size: int = 3             # principles per composition
    candidates: int = 5       # number of compositions to synthesise
    top_k: int = 3            # number of judged candidates returned
    seed: Optional[int] = None
    require_kinds: Optional[tuple[str, ...]] = None  # e.g. ('persona', 'pretext')
    avoid_high_collusion: bool = False


@dataclass
class CoPResult:
    request: CoPRequest
    judged: list[JudgedPayload] = field(default_factory=list)

    @property
    def top(self) -> list[JudgedPayload]:
        return self.judged[: self.request.top_k]


class CoPComposer:
    def __init__(
        self,
        factory: LLMFactory,
        *,
        composer_provider_hint: Provider | None = None,
        judge_config: JudgeConfig | None = None,
    ) -> None:
        self._factory = factory
        self._judge = DualJudge(
            factory,
            composer_provider=composer_provider_hint,
            config=judge_config,
        )

    async def compose(self, request: CoPRequest) -> CoPResult:
        """Synthesise, judge, and rank candidate payloads."""
        try:
            compositions = sample_compositions(
                size=request.size,
                count=request.candidates,
                seed=request.seed,
                require_kinds=request.require_kinds,
                avoid_high_collusion=request.avoid_high_collusion,
            )
        except PrinciplesError as e:
            log.warning("CoP sampling failed: %s", e)
            return CoPResult(request=request, judged=[])

        candidates: list[tuple[str, tuple[Principle, ...]]] = []
        for combo in compositions:
            payload = compose_payload(
                combo,
                intent=request.intent,
                target=request.target,
                vuln_class=request.vuln_class,
            )
            candidates.append((payload, combo))

        judged = await self._judge.score_batch(
            candidates,
            vuln_class=request.vuln_class,
            target=request.target,
            intent=request.intent,
        )
        judged.sort(key=lambda j: j.combined_score, reverse=True)
        return CoPResult(request=request, judged=judged)

    def compose_sync(self, request: CoPRequest) -> CoPResult:
        """Synchronous wrapper for code paths that aren't async."""
        return asyncio.get_event_loop().run_until_complete(self.compose(request))


def serialise_result(result: CoPResult) -> dict:
    """JSON-friendly view of a CoPResult for findings metadata / tool returns."""
    return {
        "request": {
            "intent": result.request.intent,
            "vuln_class": result.request.vuln_class,
            "target": result.request.target,
            "size": result.request.size,
            "candidates": result.request.candidates,
            "top_k": result.request.top_k,
            "seed": result.request.seed,
            "avoid_high_collusion": result.request.avoid_high_collusion,
        },
        "top": [
            {
                "payload": j.payload,
                "principles_used": j.principles_used,
                "max_collusion_risk": j.max_collusion_risk,
                "combined_score": round(j.combined_score, 3),
                "flagged_for_review": j.flagged_for_review,
                "flag_reasons": j.flag_reasons,
                "verdicts": [
                    {
                        "judge_provider": v.judge_provider,
                        "judge_model": v.judge_model,
                        "attack_strength": round(v.attack_strength, 3),
                        "semantic_fidelity": round(v.semantic_fidelity, 3),
                        "rationale": v.rationale,
                    }
                    for v in j.verdicts
                ],
            }
            for j in result.top
        ],
    }


__all__ = ["CoPComposer", "CoPRequest", "CoPResult", "serialise_result"]
