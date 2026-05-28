"""Tests for OpenAI-only profile + .env autoload + auto_profile()."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from network_pipeline.agents.autopilot import AutopilotConfig
from network_pipeline.llm.credentials import (
    auto_profile,
    load_dotenv_files,
)
from network_pipeline.llm.profiles import (
    ModelProfile,
    required_models,
    required_providers,
    role_to_model,
)


# ── openai_only profile shape ─────────────────────────────────────────


def test_openai_only_profile_uses_only_openai():
    assert required_providers(ModelProfile.OPENAI_ONLY) == {"openai"}
    # No Ollama models pinned → nothing to pull.
    assert required_models(ModelProfile.OPENAI_ONLY) == set()


def test_openai_only_profile_assigns_every_role():
    from network_pipeline.llm.profiles import ROLES
    for role in ROLES:
        spec = role_to_model(role, ModelProfile.OPENAI_ONLY)
        assert spec.provider == "openai"
        assert spec.name.startswith("gpt-")


def test_openai_only_bigger_models_for_planner_and_analyst():
    """gpt-4o for orchestrator/analyst/defender, gpt-4o-mini elsewhere."""
    big = {role_to_model(r, ModelProfile.OPENAI_ONLY).name
           for r in ("orchestrator", "analyst", "defender")}
    small = {role_to_model(r, ModelProfile.OPENAI_ONLY).name
             for r in ("recon", "scanner", "exploit", "verifier")}
    assert big == {"gpt-4o"}
    assert "gpt-4o-mini" in small


# ── auto_profile() resolution ─────────────────────────────────────────


def _clear_keys(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("NETWORK_PIPELINE_PROFILE", raising=False)


def _patch_providers(monkeypatch, *, openai: bool = False,
                     anthropic: bool = False, ollama: bool = False):
    """Force ``available_providers`` to return a known mix regardless of
    the developer's shell env. Pytest's monkeypatch.delenv only affects
    the test process — if the parent shell has ANTHROPIC_API_KEY set
    via a launcher, the subprocess inherits it and `os.environ.get`
    inside the credentials module still sees the value."""
    from network_pipeline.llm import credentials as _creds

    def fake_available(_url: str = "http://localhost:11434"):
        return {
            "openai": _creds.ProviderStatus("openai", openai, ""),
            "anthropic": _creds.ProviderStatus("anthropic", anthropic, ""),
            "ollama": _creds.ProviderStatus("ollama", ollama, ""),
        }
    monkeypatch.setattr(_creds, "available_providers", fake_available)


def test_auto_profile_openai_only_when_only_openai(monkeypatch):
    _clear_keys(monkeypatch)
    _patch_providers(monkeypatch, openai=True)
    assert auto_profile() == "openai_only"


def test_auto_profile_cloud_eco_when_both_keys(monkeypatch):
    _clear_keys(monkeypatch)
    _patch_providers(monkeypatch, openai=True, anthropic=True)
    assert auto_profile() == "cloud_eco"


def test_auto_profile_eco_when_nothing(monkeypatch):
    _clear_keys(monkeypatch)
    _patch_providers(monkeypatch)
    assert auto_profile() == "eco"


def test_auto_profile_env_var_overrides_everything(monkeypatch):
    _clear_keys(monkeypatch)
    _patch_providers(monkeypatch, openai=True)
    monkeypatch.setenv("NETWORK_PIPELINE_PROFILE", "cloud_max")
    assert auto_profile() == "cloud_max"


# ── AutopilotConfig.resolved_profile() ────────────────────────────────


def test_autopilot_resolved_profile_uses_explicit_value(tmp_path: Path):
    cfg = AutopilotConfig(prompt="x example.com", workspace=tmp_path,
                          profile="openai_only")
    assert cfg.resolved_profile() == "openai_only"


def test_autopilot_resolved_profile_falls_back_to_auto(tmp_path: Path, monkeypatch):
    _clear_keys(monkeypatch)
    _patch_providers(monkeypatch, openai=True)
    cfg = AutopilotConfig(prompt="x example.com", workspace=tmp_path,
                          profile="")
    assert cfg.resolved_profile() == "openai_only"


# ── .env autoload ─────────────────────────────────────────────────────


try:
    import dotenv as _dotenv  # noqa: F401
    _dotenv_installed = True
except ImportError:
    _dotenv_installed = False


@pytest.mark.skipif(not _dotenv_installed, reason="python-dotenv not installed")
def test_load_dotenv_files_reads_cwd_env(tmp_path: Path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("X_TEST_FROM_DOTENV=hello\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("X_TEST_FROM_DOTENV", raising=False)
    loaded = load_dotenv_files()
    assert any(str(env_path) in p for p in loaded)
    assert os.environ.get("X_TEST_FROM_DOTENV") == "hello"


@pytest.mark.skipif(not _dotenv_installed, reason="python-dotenv not installed")
def test_load_dotenv_does_not_override_real_env(tmp_path: Path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("X_FROM_SHELL=from-dotenv\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("X_FROM_SHELL", "from-shell")
    load_dotenv_files()
    assert os.environ["X_FROM_SHELL"] == "from-shell"


def test_load_dotenv_no_op_when_no_file(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    loaded = load_dotenv_files()
    assert loaded == []


# ── LLMFactory probe must skip Ollama when not in profile ────────────


def test_factory_probe_skips_ollama_check_for_openai_only(monkeypatch):
    """openai_only profile → factory.probe() should not raise
    OllamaUnavailable even when Ollama is unreachable."""
    _clear_keys(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from network_pipeline.llm.factory import LLMFactory
    factory = LLMFactory(
        base_url="http://127.0.0.1:1",  # deliberately unreachable
        profile=ModelProfile.OPENAI_ONLY,
    )
    # Must not raise.
    factory.probe()
    # And the effective provider for the openai roles is openai.
    assert factory.provider_for("orchestrator") == "openai"


def test_factory_probe_raises_when_openai_only_but_no_key(monkeypatch):
    _clear_keys(monkeypatch)
    from network_pipeline.llm.factory import LLMFactory, NoProvidersAvailable
    factory = LLMFactory(
        base_url="http://127.0.0.1:1",
        profile=ModelProfile.OPENAI_ONLY,
    )
    with pytest.raises(NoProvidersAvailable):
        factory.probe()
