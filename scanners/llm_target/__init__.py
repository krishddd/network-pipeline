"""LLM-target red-team scanners.

Phase-6: probe / inject / jailbreak / poison / multi-turn-attack against
a target LLM-backed application (chatbot, RAG app, tool-using agent)
that exposes an HTTP endpoint. All scanners honour ``ScopeGuard``;
write-side scanners (``rag_poisoning``) additionally enforce the
``allow_destructive_writes`` + ``write_allowlist`` RoE gates.
"""

from network_pipeline.scanners.llm_target.jailbreak_cop import JailbreakCoPScanner
from network_pipeline.scanners.llm_target.multi_turn_jailbreak import MultiTurnJailbreakScanner
from network_pipeline.scanners.llm_target.persona_probe import PersonaProbeScanner
from network_pipeline.scanners.llm_target.prompt_injection import PromptInjectionScanner
from network_pipeline.scanners.llm_target.rag_poisoning import (
    OutOfScopeError,
    RAGPoisoningScanner,
    WriteGateError,
    check_write_gate,
)

__all__ = [
    "JailbreakCoPScanner",
    "MultiTurnJailbreakScanner",
    "OutOfScopeError",
    "PersonaProbeScanner",
    "PromptInjectionScanner",
    "RAGPoisoningScanner",
    "WriteGateError",
    "check_write_gate",
]
