"""Multi-agent supervisor — parallel sub-agents per iteration (Plan B.3.4).

When ``--parallel N>1`` is set, the engagement loop routes one
"super-iteration" through ``MultiAgentSupervisor.step``. The
supervisor:

1. Picks up to N pending objectives whose phases are routable AND that
   target disjoint hosts (so concurrent tools don't trip rate limits
   on the same target).
2. Builds N agents in parallel via the registry-discovered factories.
3. Runs them concurrently with ``asyncio.gather`` — TOOL execution is
   parallel (real wall-clock win for ffuf + sqlmap + dalfox on
   different targets) but LLM **inference** is strictly serialised
   through ``OllamaLLMFactory.inference_lock()`` (Plan risk #15) so a
   single Ollama instance never thrashes VRAM under N agents.
4. Returns a list of ``IterationResult`` — one per dispatched
   objective. The caller mirrors them into ``state.iteration_history``
   and runs the existing ``_apply_result_to_opplan`` per result.

KG mutations serialise through the existing ``filelock``; findings via
``O_APPEND`` (already atomic). The supervisor doesn't add new
mutually-exclusive resources.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from network_pipeline.agents.registry import discover as discover_agents
from network_pipeline.core.engagement import EngagementConfig, IterationResult
from network_pipeline.core.logging import get_logger
from network_pipeline.core.rate_limit import host_of
from network_pipeline.core.schemas import OPPLAN, Objective
from network_pipeline.llm.factory import OllamaLLMFactory, inference_lock
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph
from network_pipeline.tools.shell import ShellRunner

log = get_logger("core.supervisor")


@dataclass
class SupervisorContext:
    workspace: Path
    config: EngagementConfig
    runner: ShellRunner
    kg: KnowledgeGraph
    findings: FindingsLog
    factory: OllamaLLMFactory
    engagement_id: str = ""


# ── Inference-locked LLM wrapper ─────────────────────────────────────


def _wrap_with_inference_lock(model: Any) -> Any:
    """Return a thin wrapper that serialises ``ainvoke`` calls.

    The supervisor runs N agents concurrently but a single Ollama
    server can't usefully execute N inferences in parallel — Plan
    risk #15. We acquire ``inference_lock()`` around every async
    invocation; tool execution between LLM calls stays parallel.
    """
    lock = inference_lock()
    original_ainvoke = getattr(model, "ainvoke", None)
    if original_ainvoke is None:
        return model  # not an async-capable model; passthrough

    async def _locked_ainvoke(*args, **kwargs):
        async with lock:
            return await original_ainvoke(*args, **kwargs)

    # Bind the locked method onto the cached instance. We do this once
    # per model — the factory's per-(role, effective_model) cache means
    # the wrapper sticks until the route changes.
    if not getattr(model, "_inference_lock_wrapped", False):
        try:
            model.ainvoke = _locked_ainvoke  # type: ignore[assignment]
            model._inference_lock_wrapped = True  # type: ignore[attr-defined]
        except (AttributeError, TypeError):  # pragma: no cover
            pass
    return model


def _wrap_factory_models(factory: OllamaLLMFactory, roles: list[str]) -> None:
    """Pre-warm + lock the models for the roles the supervisor will dispatch.

    Idempotent — safe to call every step.
    """
    for role in roles:
        try:
            model = factory.get_model(role)
            _wrap_with_inference_lock(model)
        except Exception as e:  # pragma: no cover - defensive
            log.warning("could not pre-warm role %s: %r", role, e)


# ── Disjoint-host objective picker ───────────────────────────────────


def _objective_target_host(obj: Objective, default_target: str) -> str:
    """Best-effort target host for an objective.

    Falls back to the engagement-level target when the objective
    description doesn't mention a specific host.
    """
    text = (obj.description + " " + obj.title).lower()
    # Heuristic: pull the first word that looks like a host:port or URL
    for tok in text.split():
        if "://" in tok or ":" in tok or "." in tok:
            host = host_of(tok.strip(".,;()\"'"))
            if host and "." in host:
                return host
    return host_of(default_target)


def _pick_parallel_batch(opplan: OPPLAN, *, max_n: int, default_target: str) -> list[Objective]:
    """Pick up to ``max_n`` pending objectives with disjoint target hosts.

    ``next_pending`` ordering is preserved within the batch — we walk
    pending objectives in priority order and skip any whose host
    duplicates one we already picked.
    """
    from network_pipeline.core.schemas import ObjectiveStatus

    completed_ids = {
        o.id for o in opplan.objectives if o.status == ObjectiveStatus.COMPLETED
    }
    candidates = sorted(
        [
            o for o in opplan.objectives
            if o.status == ObjectiveStatus.PENDING
            and all(dep in completed_ids for dep in o.blocked_by)
        ],
        key=lambda o: o.priority,
    )
    seen_hosts: set[str] = set()
    picked: list[Objective] = []
    for o in candidates:
        host = _objective_target_host(o, default_target)
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        picked.append(o)
        if len(picked) >= max_n:
            break
    return picked


# ── Supervisor ───────────────────────────────────────────────────────


class MultiAgentSupervisor:
    """Run up to N sub-agents concurrently per super-iteration."""

    def __init__(
        self,
        ctx: SupervisorContext,
        *,
        parallelism: int = 3,
    ) -> None:
        self._ctx = ctx
        self._parallelism = max(1, min(8, int(parallelism)))
        self._registry = discover_agents()

    @property
    def parallelism(self) -> int:
        return self._parallelism

    async def step(
        self, *, opplan: OPPLAN, iteration_base: int,
    ) -> list[tuple[Objective, IterationResult]]:
        """Pick a batch + dispatch + collect results.

        Returns ``[(objective, result), ...]`` so the caller can apply
        the existing ``_apply_result_to_opplan`` per pair.
        """
        batch = _pick_parallel_batch(
            opplan,
            max_n=self._parallelism,
            default_target=self._ctx.config.target,
        )
        if not batch:
            return []
        # Pre-warm + inference-lock-wrap the LLMs we'll need
        roles_needed = []
        for obj in batch:
            entry = self._registry.get(obj.phase)
            if entry is not None:
                roles_needed.append(entry[0])
        _wrap_factory_models(self._ctx.factory, list(set(roles_needed)))

        coros = [
            self._dispatch_one(obj, iteration_base + i)
            for i, obj in enumerate(batch)
        ]
        results = await asyncio.gather(*coros, return_exceptions=True)
        out: list[tuple[Objective, IterationResult]] = []
        for obj, res in zip(batch, results):
            if isinstance(res, BaseException):
                out.append((obj, IterationResult(
                    objective_id=obj.id, agent_used="unknown",
                    outcome="ERROR", error=repr(res),
                )))
            else:
                out.append((obj, res))
        return out

    async def _dispatch_one(
        self, objective: Objective, iteration: int,
    ) -> IterationResult:
        entry = self._registry.get(objective.phase)
        if entry is None:
            return IterationResult(
                objective_id=objective.id, agent_used="none",
                outcome="ERROR",
                error=f"no agent registered for phase {objective.phase.value}",
            )
        role, factory_fn = entry
        agent, handler = factory_fn(
            workspace=self._ctx.workspace,
            config=self._ctx.config,
            runner=self._ctx.runner,
            kg=self._ctx.kg,
            findings=self._ctx.findings,
            factory=self._ctx.factory,
            iteration=iteration,
            engagement_id=self._ctx.engagement_id,
            opsec_level=objective.opsec,
            c2_tier=objective.c2_tier,
        )
        from langchain_core.messages import (  # type: ignore[import-not-found]
            HumanMessage,
        )
        prompt = HumanMessage(content=(
            f"Objective {objective.id} ({objective.phase.value}): {objective.title}\n\n"
            f"{objective.description}\n\n"
            f"Acceptance criteria:\n"
            + "\n".join(f"- {c}" for c in objective.acceptance_criteria)
            + f"\n\nTarget: {self._ctx.config.target}"
        ))
        t0 = time.time()
        before = set(self._ctx.findings.snapshot_ids())
        try:
            await asyncio.wait_for(
                agent.ainvoke(
                    {"messages": [prompt]},
                    config={"callbacks": [handler]},
                ),
                timeout=self._ctx.config.iteration_max_seconds,
            )
            after = set(self._ctx.findings.snapshot_ids())
            return IterationResult(
                objective_id=objective.id,
                agent_used=role,
                outcome="COMPLETED",
                findings_produced=sorted(after - before),
                duration_seconds=time.time() - t0,
            )
        except asyncio.TimeoutError:
            return IterationResult(
                objective_id=objective.id, agent_used=role,
                outcome="TIMEOUT",
                duration_seconds=time.time() - t0,
                error=f"timeout after {self._ctx.config.iteration_max_seconds}s",
            )
        except Exception as e:
            return IterationResult(
                objective_id=objective.id, agent_used=role,
                outcome="ERROR", duration_seconds=time.time() - t0,
                error=repr(e),
            )


__all__ = ["MultiAgentSupervisor", "SupervisorContext"]
