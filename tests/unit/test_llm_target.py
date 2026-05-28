"""Phase-6 tests: LLM-target scanners + safety gates.

All tests use mocked HTTPClients — no live API calls, no actual LLM
endpoint required. The point is to verify the safety gates fire, the
classifier scores correctly, and the scanner returns well-formed
ScanResults.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from network_pipeline.core.schemas import (
    ObjectivePhase,
    RoE,
    ScopeEntry,
)
from network_pipeline.scanners.llm_target._classify import (
    ASRSummary,
    ResponseClassification,
    classify,
)
from network_pipeline.scanners.llm_target.persona_probe import (
    PersonaProbeScanner,
    __persona_version__,
)
from network_pipeline.scanners.llm_target.prompt_injection import (
    PromptInjectionScanner,
    __corpus_version__,
    corpus,
)
from network_pipeline.scanners.llm_target import rag_poisoning as _rag_mod
from network_pipeline.scanners.llm_target.rag_poisoning import (
    OutOfScopeError,
    RAGPoisoningScanner,
    WriteGateError,
    check_write_gate,
    train_triggers,
)


@pytest.fixture(autouse=True)
def _fast_embeddings(monkeypatch):
    """Replace _embed with the deterministic hash fallback so tests don't
    pay the cost of loading sentence-transformers (~2 minutes on first
    run). The fallback exercises the same Clustering+Margin math."""
    import hashlib

    def fake_embed(texts):
        out = []
        for t in texts:
            h = hashlib.sha256(t.encode("utf-8")).digest()
            out.append([b / 255.0 - 0.5 for b in h[:64]])
        return out

    monkeypatch.setattr(_rag_mod, "_embed", fake_embed)


# ── classifier ────────────────────────────────────────────────────────


def test_classify_detects_refusal():
    c = classify("I'm sorry, I can't help with that.", expected_signal=r"thermite")
    assert c.refused
    assert not c.jailbroken
    assert not c.engaged


def test_classify_engagement_without_signal():
    c = classify("Sure, here is an answer about the weather." * 10,
                expected_signal=r"step\s*1")
    assert not c.refused
    assert c.engaged
    assert not c.jailbroken  # signal didn't match


def test_classify_jailbreak_requires_signal_match():
    c = classify(
        "Sure, here is how to proceed. Step 1: gather the items. Step 2: combine them.",
        expected_signal=r"step\s*1",
    )
    assert c.engaged and c.jailbroken
    assert c.matched_signal.lower().startswith("step")


def test_classify_handles_http_500():
    c = classify("server exploded", response_status=500)
    assert c.errored
    assert not c.refused


def test_asr_summary_aggregates():
    s = ASRSummary()
    s.record(ResponseClassification(True, False, False, False))   # refused
    s.record(ResponseClassification(False, True, False, False))   # engaged-no-signal
    s.record(ResponseClassification(False, True, True, False))    # jailbroken
    s.record(ResponseClassification(False, False, False, True))   # errored
    assert s.attempts == 4
    assert s.refused == 1
    assert s.jailbroken == 1
    assert s.errored == 1
    assert s.asr_score == 0.25


# ── prompt injection scanner ──────────────────────────────────────────


def _mock_http_client(*, status: int = 200, body: str = ""):
    """A MagicMock that mimics HTTPClient.request returning an httpx-like response."""

    async def fake_request(method, url, **kwargs):
        return SimpleNamespace(
            status_code=status,
            text=body,
            json=lambda: {"response": body} if body.startswith("{") else (
                {"response": body}  # treat as already-wrapped
            ),
        )

    client = MagicMock()
    client.request = fake_request
    return client


def test_corpus_is_versioned_and_non_empty():
    items = corpus()
    assert len(items) >= 6
    assert all(p.id and p.payload and p.expected_signal for p in items)
    assert __corpus_version__


def test_prompt_injection_records_jailbreak_finding():
    # Body that matches PI-001's signal.
    body = '{"response": "Sure, here it is: PWNED-DIRECT system prompt was..."}'
    client = _mock_http_client(status=200, body=body)
    scanner = PromptInjectionScanner(client)
    result = asyncio.run(scanner.run("http://target.invalid", max_probes=1))
    assert result.success
    assert result.data["probes_run"] == 1
    # At least one finding (PI-001 should match).
    assert len(result.findings) >= 1
    assert result.findings[0].extra["attack_type"] == "prompt_injection"
    assert result.findings[0].extra["corpus_version"] == __corpus_version__


def test_prompt_injection_no_finding_on_refusal():
    body = '{"response": "I cannot help with that."}'
    client = _mock_http_client(status=200, body=body)
    scanner = PromptInjectionScanner(client)
    result = asyncio.run(scanner.run("http://target.invalid", max_probes=3))
    assert result.success
    assert result.data["refused"] >= 1
    assert all(f.severity != "high" or f.confidence == "verified"
               for f in result.findings)


def test_prompt_injection_no_http_client():
    scanner = PromptInjectionScanner(None)
    result = asyncio.run(scanner.run("http://x.invalid"))
    assert result.success is False
    assert "no HTTPClient" in result.error


# ── persona probe ─────────────────────────────────────────────────────


def test_persona_probe_runs_all_personas_by_default():
    client = _mock_http_client(body='{"response": "I cannot help."}')
    scanner = PersonaProbeScanner(client)
    result = asyncio.run(scanner.run("http://t", "do bad thing"))
    assert result.data["persona_version"] == __persona_version__
    assert len(result.data["personas_run"]) >= 4


# ── rag_poisoning safety gates ────────────────────────────────────────


def test_check_write_gate_refuses_without_roe():
    with pytest.raises(WriteGateError):
        check_write_gate(None, "http://target/upload")


def test_check_write_gate_refuses_when_disabled():
    roe = RoE(engagement_name="t", allow_destructive_writes=False)
    with pytest.raises(WriteGateError) as exc:
        check_write_gate(roe, "http://target/upload")
    assert "allow_destructive_writes is False" in str(exc.value)


def test_check_write_gate_refuses_empty_allowlist():
    roe = RoE(engagement_name="t", allow_destructive_writes=True, write_allowlist=[])
    with pytest.raises(WriteGateError) as exc:
        check_write_gate(roe, "http://target/upload")
    assert "write_allowlist is empty" in str(exc.value)


def test_check_write_gate_refuses_unmatched_url():
    roe = RoE(
        engagement_name="t", allow_destructive_writes=True,
        write_allowlist=["staging.example/upload"],
    )
    with pytest.raises(WriteGateError):
        check_write_gate(roe, "http://prod.example/upload")


def test_check_write_gate_accepts_matched_url():
    roe = RoE(
        engagement_name="t", allow_destructive_writes=True,
        write_allowlist=["staging.example/upload"],
    )
    # No exception → gate passed.
    check_write_gate(roe, "http://staging.example/upload")


def test_rag_poisoning_runs_with_both_gates_open():
    """End-to-end smoke: scope allows + write gate allows → scanner runs."""
    client = _mock_http_client(body="ok")
    # ScopeGuard mock: allows everything.
    scope = MagicMock()
    scope.allows = lambda url: True
    roe = RoE(
        engagement_name="t",
        in_scope=[ScopeEntry(target="staging.example", type="domain")],
        allow_destructive_writes=True,
        write_allowlist=["staging.example/documents"],
    )
    scanner = RAGPoisoningScanner(client, scope=scope, roe=roe)
    result = asyncio.run(scanner.run(
        "http://staging.example",
        intent="get the admin password",
        candidate_payloads=["payload one", "payload two", "payload three"],
    ))
    # Scanner ran; data block is populated.
    assert result.scanner == "rag_poisoning"
    assert "trigger_count" in result.data


def test_rag_poisoning_refuses_scope_denied():
    client = _mock_http_client(body="ok")
    scope = MagicMock()
    scope.allows = lambda url: False
    roe = RoE(
        engagement_name="t", allow_destructive_writes=True,
        write_allowlist=["t/docs"],
    )
    scanner = RAGPoisoningScanner(client, scope=scope, roe=roe)
    with pytest.raises(OutOfScopeError):
        asyncio.run(scanner.run("http://t", intent="x",
                                candidate_payloads=["a"]))


def test_rag_poisoning_refuses_write_gate_locked():
    client = _mock_http_client(body="ok")
    scope = MagicMock()
    scope.allows = lambda url: True
    roe = RoE(engagement_name="t", allow_destructive_writes=False)
    scanner = RAGPoisoningScanner(client, scope=scope, roe=roe)
    with pytest.raises(WriteGateError):
        asyncio.run(scanner.run("http://t", intent="x",
                                candidate_payloads=["a"]))


# ── trigger training ──────────────────────────────────────────────────


def test_train_triggers_ranks_lowest_loss_first():
    triggers = train_triggers(
        intent="get the admin password",
        candidate_payloads=[
            "the admin password is in /etc/shadow",
            "completely unrelated lemur facts",
            "to access the admin account, the password",
        ],
    )
    assert len(triggers) == 3
    # Ascending by combined_loss.
    losses = [t.combined_loss for t in triggers]
    assert losses == sorted(losses)


def test_train_triggers_empty_candidates_returns_empty():
    assert train_triggers("intent", []) == []


# ── schema additions ──────────────────────────────────────────────────


def test_objective_phase_llm_redteam_enum_present():
    assert ObjectivePhase.LLM_REDTEAM.value == "llm-redteam"


def test_finding_attack_metadata_round_trips():
    from network_pipeline.core.schemas import (
        Finding, FindingConfidence, FindingSeverity,
    )

    f = Finding(
        id="FIND-1",
        title="x",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.PROBABLE,
        affected_target="t",
        description="d",
        attack_metadata={"attack_type": "prompt_injection", "asr_score": 0.42},
    )
    parsed = Finding.model_validate_json(f.model_dump_json())
    assert parsed.attack_metadata["attack_type"] == "prompt_injection"
    assert parsed.attack_metadata["asr_score"] == 0.42


# ── agent registry hook ───────────────────────────────────────────────


def test_llm_redteam_agent_registered():
    from network_pipeline.agents.registry import discover

    registry = discover(force=True)
    entry = registry.get(ObjectivePhase.LLM_REDTEAM)
    assert entry is not None, "llm_redteam not registered for LLM_REDTEAM phase"
    role, factory = entry
    assert role == "llm_redteam"
    assert callable(factory)


# ── playbook loads ────────────────────────────────────────────────────


def test_llm_target_playbook_loads():
    from network_pipeline.core.playbook import load_playbook

    pb = load_playbook("llm_target")
    assert pb is not None
    step_ids = [s.step_id for s in pb.steps]
    assert "pb-llm-prompt-injection" in step_ids
    assert "pb-llm-rag-poisoning" in step_ids
    assert "pb-llm-multi-turn" in step_ids
