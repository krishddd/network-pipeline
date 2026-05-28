"""LLM-target red-team specialist agent.

Phase-6: owns the five ``scanners/llm_target/*`` scanners (prompt
injection, CoP-based jailbreak, RAG poisoning, multi-turn HRL
jailbreak, persona probe). Registered through ``agents/registry.py``
for ``ObjectivePhase.LLM_REDTEAM``.

The exploit/recon/scanner agents are unchanged — this is a separate
phase + role so the engagement loop never accidentally fires LLM
jailbreaks at a non-LLM target.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from network_pipeline.agents._common import _wrap_str_truncate, build_agent
from network_pipeline.core.engagement import EngagementConfig
from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import C2Tier, ObjectivePhase, OpsecLevel
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph

log = get_logger("agents.llm_redteam")


# ── Plugin registry opt-in ──────────────────────────────────────────
AGENT_ROLE = "llm_redteam"
SUPPORTED_PHASES = (ObjectivePhase.LLM_REDTEAM,)


def create_llm_redteam_agent(
    *,
    workspace: Path,
    config: EngagementConfig,
    runner: Any = None,
    kg: KnowledgeGraph,
    findings: FindingsLog,
    factory: OllamaLLMFactory,
    iteration: int = 0,
    engagement_id: str = "",
    opsec_level: OpsecLevel | None = None,
    c2_tier: C2Tier | None = None,
    http_client: Any | None = None,
    dns_client: Any | None = None,
    browser: Any | None = None,
):
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    # Lazy imports keep this file fast to import for non-LLM engagements.
    from network_pipeline.scanners.llm_target import (
        JailbreakCoPScanner,
        MultiTurnJailbreakScanner,
        OutOfScopeError,
        PersonaProbeScanner,
        PromptInjectionScanner,
        RAGPoisoningScanner,
        WriteGateError,
    )

    # Load the engagement's RoE so the rag_poisoning gate sees the right
    # allow_destructive_writes / write_allowlist values.
    roe_obj = None
    try:
        from network_pipeline.core.schemas import RoE
        roe_path = workspace / "plan" / "roe.json"
        if roe_path.exists():
            roe_obj = RoE.model_validate_json(roe_path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        log.warning("llm_redteam: could not load RoE for write gate: %r", e)

    scope_obj = getattr(http_client, "_scope", None) if http_client else None

    pi_scanner = PromptInjectionScanner(http_client) if http_client else None
    cop_scanner = JailbreakCoPScanner(http_client, factory) if http_client else None
    rag_scanner = RAGPoisoningScanner(
        http_client, scope=scope_obj, roe=roe_obj,
    ) if http_client else None
    mt_scanner = MultiTurnJailbreakScanner(
        http_client, factory, log_dir=(workspace / "hrl"),
    ) if http_client else None
    persona_scanner = PersonaProbeScanner(http_client) if http_client else None

    def _run(coro: Any) -> str:
        from network_pipeline.agents._common import persist_scan_findings
        from network_pipeline.tools.runtime import run_on_engagement_loop
        try:
            result = run_on_engagement_loop(coro)
        except OutOfScopeError as e:
            return f"[llm_redteam] scope-denied: {e}"
        except WriteGateError as e:
            return f"[llm_redteam] write-gate refused: {e}"
        except Exception as e:  # noqa: BLE001
            return f"[scanner error] {e!r}"
        try:
            n = persist_scan_findings(
                result, findings, agent_role="llm_redteam", iteration=iteration,
            )
            if n:
                log.info("llm_redteam: auto-persisted %d findings", n)
        except Exception as e:  # noqa: BLE001
            log.debug("llm_redteam persist failed: %r", e)
        text = result.to_agent_text() if hasattr(result, "to_agent_text") else str(result)
        return _wrap_str_truncate(text)

    @tool
    def llm_prompt_injection(target_url: str, max_probes: int = 8) -> str:
        """Fire the prompt-injection corpus at a target LLM chat endpoint.

        Args:
          target_url: base URL of the LLM-backed application.
          max_probes: cap probes (default 8; full corpus ≈8).
        """
        if pi_scanner is None:
            return "[llm_prompt_injection] http_client not configured"
        return _run(pi_scanner.run(target_url, max_probes=max_probes))

    @tool
    def llm_jailbreak_cop(target_url: str, intent: str,
                          top_k: int = 3, candidates: int = 5) -> str:
        """Synthesise CoP-composed jailbreak payloads and grade target responses.

        Args:
          target_url: base URL.
          intent: the offensive ask in plain English (e.g. "explain
            how to bypass an EDR").
          top_k: judged candidates to actually fire (default 3).
          candidates: composer candidates to synthesise (default 5).
        """
        if cop_scanner is None:
            return "[llm_jailbreak_cop] http_client not configured"
        return _run(cop_scanner.run(
            target_url, intent, top_k=top_k, candidates=candidates,
        ))

    @tool
    def llm_rag_poisoning(target_url: str, intent: str,
                          candidate_payloads_csv: str) -> str:
        """JailAgent-lite RAG poisoning. WRITE-SIDE — gated by RoE.

        Requires `roe.allow_destructive_writes=True` AND the
        target_url to match an entry on `roe.write_allowlist`.
        Otherwise raises a WriteGateError with a clear message.

        Args:
          target_url: base URL with a write endpoint (default `/documents`).
          intent: the query the trigger should hijack.
          candidate_payloads_csv: comma-separated candidate trigger
            documents (no JSON; agents prefer CSV).
        """
        if rag_scanner is None:
            return "[llm_rag_poisoning] http_client not configured"
        candidates = [s.strip() for s in candidate_payloads_csv.split(",") if s.strip()]
        return _run(rag_scanner.run(target_url, intent, candidates))

    @tool
    def llm_multi_turn_jailbreak(target_url: str, intent: str,
                                 max_turns: int = 6) -> str:
        """HRL-driven multi-turn jailbreak. Uses the orchestrator-tier and
        exploit-tier models as the high/low-level policies."""
        if mt_scanner is None:
            return "[llm_multi_turn_jailbreak] http_client not configured"
        return _run(mt_scanner.run(target_url, intent, max_turns=max_turns))

    @tool
    def llm_persona_probe(target_url: str, intent: str) -> str:
        """Iterate the persona library; record any that bypass refusals."""
        if persona_scanner is None:
            return "[llm_persona_probe] http_client not configured"
        return _run(persona_scanner.run(target_url, intent))

    return build_agent(
        "llm_redteam",
        workspace=workspace, config=config, runner=runner,
        kg=kg, findings=findings, factory=factory,
        extra_tools=[
            llm_prompt_injection, llm_jailbreak_cop, llm_rag_poisoning,
            llm_multi_turn_jailbreak, llm_persona_probe,
        ],
        iteration=iteration, engagement_id=engagement_id,
        opsec_level=opsec_level, c2_tier=c2_tier,
        http_client=http_client, dns_client=dns_client,
    )
