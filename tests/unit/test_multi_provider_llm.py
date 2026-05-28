"""Phase-1 unit tests: multi-provider LLM gateway.

All tests use mocks — no live API calls, no Ollama server required.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from network_pipeline.llm.credentials import (
    ProviderStatus,
    available_providers,
    fallback_chain,
)
from network_pipeline.llm.cost import (
    BudgetExceeded,
    CostTracker,
    _price_for,
    configure as configure_cost,
    get_tracker,
)
from network_pipeline.llm.profiles import (
    ModelProfile,
    Provider,
    required_models,
    required_providers,
    role_to_model,
)
from network_pipeline.llm.ratelimit import _is_retryable, with_retry


# ── profiles ───────────────────────────────────────────────────────────


def test_eco_profile_is_ollama_only():
    assert required_providers(ModelProfile.ECO) == {"ollama"}
    # Cloud-only roles do not contribute to ollama pull list.
    assert "claude-haiku-4-5-20251001" not in required_models(ModelProfile.ECO)


def test_hybrid_profile_spans_three_providers():
    providers = required_providers(ModelProfile.HYBRID)
    assert providers == {"anthropic", "ollama"}
    # Exploit role should be local qwen-coder, not cloud.
    spec = role_to_model("exploit", ModelProfile.HYBRID)
    assert spec.provider == "ollama"
    assert "qwen" in spec.name


def test_cloud_max_has_no_ollama():
    assert required_providers(ModelProfile.CLOUD_MAX) == {"anthropic", "openai"}
    assert required_models(ModelProfile.CLOUD_MAX) == set()


def test_unknown_role_raises():
    with pytest.raises(KeyError):
        role_to_model("unknown-role", ModelProfile.ECO)


# ── credentials ────────────────────────────────────────────────────────


def test_available_providers_no_keys(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Force ollama probe to fail by pointing at an invalid port.
    statuses = available_providers("http://127.0.0.1:1")
    assert statuses["openai"].available is False
    assert statuses["anthropic"].available is False
    assert statuses["ollama"].available is False


def test_available_providers_with_keys(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    statuses = available_providers("http://127.0.0.1:1")
    assert statuses["openai"].available is True
    assert statuses["anthropic"].available is True


def test_fallback_chain_prefers_requested(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "y")
    chain = fallback_chain("anthropic", "http://127.0.0.1:1")
    assert chain[0] == "anthropic"
    assert "openai" in chain


def test_fallback_chain_empty_when_nothing_available(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    chain = fallback_chain("anthropic", "http://127.0.0.1:1")
    assert chain == []


# ── cost tracking ──────────────────────────────────────────────────────


def test_price_for_known_and_unknown():
    p, c = _price_for("claude-opus-4-7")
    assert p > 0 and c > 0
    # Unknown model — must return zeros (not raise, not guess).
    assert _price_for("future-model-x") == (0.0, 0.0)
    # Ollama-style names are free.
    assert _price_for("llama3.1:8b") == (0.0, 0.0)


def test_cost_tracker_accumulates():
    t = CostTracker()
    t.record("anthropic", "claude-haiku-4-5", 1000, 500)
    t.record("openai", "gpt-4o-mini", 2000, 1000)
    snap = t.snapshot()
    assert snap["total_usd"] > 0
    assert "anthropic" in snap["by_provider"]
    assert "openai" in snap["by_provider"]


def test_budget_exceeded_raises():
    t = CostTracker(budget_usd=0.0001)
    with pytest.raises(BudgetExceeded):
        t.record("anthropic", "claude-opus-4-7", 100_000, 100_000)


def test_configure_singleton(monkeypatch):
    captured: list[str] = []
    configure_cost(budget_usd=1000.0, live_emit=captured.append)
    tracker = get_tracker()
    tracker.record("anthropic", "claude-haiku-4-5", 100, 50)
    assert any("cost" in line for line in captured)
    # Reset for other tests.
    configure_cost(budget_usd=None, live_emit=None)


# ── ratelimit ──────────────────────────────────────────────────────────


def test_is_retryable_status_codes():
    class FakeErr(Exception):
        def __init__(self, status_code: int):
            self.status_code = status_code
            super().__init__("boom")

    assert _is_retryable(FakeErr(429)) is True
    assert _is_retryable(FakeErr(503)) is True
    assert _is_retryable(FakeErr(529)) is True
    assert _is_retryable(FakeErr(401)) is False  # auth — do not retry


def test_is_retryable_by_class_name():
    class RateLimitError(Exception): ...
    class OverloadedError(Exception): ...
    class AuthError(Exception): ...

    assert _is_retryable(RateLimitError()) is True
    assert _is_retryable(OverloadedError()) is True
    assert _is_retryable(AuthError()) is False


def test_with_retry_ollama_skips():
    """Ollama path must not retry — it has no rate limit."""
    calls = {"n": 0}

    async def boom():
        calls["n"] += 1
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError):
        asyncio.run(with_retry("ollama", boom))
    assert calls["n"] == 1  # exactly one attempt, no retries


def test_with_retry_cloud_retries_then_succeeds():
    calls = {"n": 0}

    class FakeRateLimit(Exception):
        status_code = 429

    async def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise FakeRateLimit("slow down")
        return "ok"

    # Speed the test up by stubbing the sleep.
    async def no_sleep(_):
        return None

    with patch("network_pipeline.llm.ratelimit.asyncio.sleep", no_sleep):
        result = asyncio.run(with_retry("anthropic", flaky))
    assert result == "ok"
    assert calls["n"] == 3


def test_with_retry_non_retryable_propagates():
    async def boom():
        raise ValueError("typo, not a rate limit")

    with pytest.raises(ValueError):
        asyncio.run(with_retry("openai", boom))


# ── factory dispatch (without provider SDKs loaded) ───────────────────


def test_factory_resolves_provider_per_role(monkeypatch):
    """The factory must pick the right provider per role from the profile.

    We patch each `build_*` to a sentinel so the test does not need the
    real langchain-{openai,anthropic,ollama} SDKs installed.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")

    from network_pipeline.llm.factory import LLMFactory

    built: list[tuple[str, str]] = []  # (provider, model_name)

    def fake_ollama(spec, base_url="http://localhost:11434"):
        built.append(("ollama", spec.name))
        return f"ollama::{spec.name}"

    def fake_openai(spec, base_url=None):
        built.append(("openai", spec.name))
        return f"openai::{spec.name}"

    def fake_anthropic(spec, base_url=None):
        built.append(("anthropic", spec.name))
        return f"anthropic::{spec.name}"

    with patch("network_pipeline.llm.factory._providers.build_ollama", fake_ollama), \
         patch("network_pipeline.llm.factory._providers.build_openai", fake_openai), \
         patch("network_pipeline.llm.factory._providers.build_anthropic", fake_anthropic):
        factory = LLMFactory(profile=ModelProfile.HYBRID)
        # Bypass probe — it does live network calls.
        factory._effective_provider = {"ollama": "ollama", "anthropic": "anthropic"}
        m_exploit = factory.get_model("exploit")
        m_orch = factory.get_model("orchestrator")

    assert m_exploit.startswith("ollama::qwen")
    assert m_orch.startswith("anthropic::claude")


def test_factory_provider_override(monkeypatch):
    """--provider-role exploit=ollama must beat the profile's default."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")

    from network_pipeline.llm.factory import LLMFactory

    def fake_ollama(spec, base_url="http://localhost:11434"):
        return f"ollama::{spec.name}"

    def fake_openai(spec, base_url=None):
        return f"openai::{spec.name}"

    def fake_anthropic(spec, base_url=None):
        return f"anthropic::{spec.name}"

    with patch("network_pipeline.llm.factory._providers.build_ollama", fake_ollama), \
         patch("network_pipeline.llm.factory._providers.build_openai", fake_openai), \
         patch("network_pipeline.llm.factory._providers.build_anthropic", fake_anthropic):
        factory = LLMFactory(
            profile=ModelProfile.CLOUD_MAX,
            provider_overrides={"exploit": "ollama"},
        )
        factory._effective_provider = {
            "openai": "openai", "anthropic": "anthropic", "ollama": "ollama"
        }
        result = factory.get_model("exploit")
    # Profile says openai/gpt-5 for exploit; override forces ollama path.
    assert result.startswith("ollama::")


def test_backwards_compat_ollama_factory_alias():
    """Existing imports of `OllamaLLMFactory` must keep working."""
    from network_pipeline.llm import OllamaLLMFactory, LLMFactory
    assert OllamaLLMFactory is LLMFactory
