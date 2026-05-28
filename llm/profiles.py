"""Per-role model assignment across multiple LLM providers.

Profiles:
  * eco         — small/fast Ollama models (default, local-only)
  * max         — biggest local Ollama models (slower, better reasoning)
  * test        — tiniest Ollama model everywhere (CI / smoke tests)
  * cloud_eco   — cheap cloud-tier (Haiku + 4o-mini) + local qwen-coder for exploits
  * cloud_max   — top cloud-tier (Opus + Sonnet + GPT-5*) — production quality
  * hybrid      — planner/analyst → Anthropic, exploit → local qwen-coder,
                  recon/scanner → Haiku. Recommended default for paid users.

Each role gets a (provider, name, context_window, timeout_seconds).

NOTE on model names: cloud model IDs in this file are *current as of plan
authoring* and may drift. Before treating any profile as canonical, run
`models.list` against the relevant provider and pin the actually-available
IDs. The plan calls for this verification step explicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal


class ModelProfile(str, Enum):
    ECO = "eco"
    MAX = "max"
    TEST = "test"
    CLOUD_ECO = "cloud_eco"
    CLOUD_MAX = "cloud_max"
    HYBRID = "hybrid"
    # OpenAI-only profile — the recommended default when the operator
    # only provides OPENAI_API_KEY (via .env or shell). Auto-selected
    # by `llm.credentials.auto_profile()` in that scenario.
    OPENAI_ONLY = "openai_only"


Provider = Literal["ollama", "openai", "anthropic"]


@dataclass(frozen=True)
class ModelSpec:
    name: str
    context_window: int
    timeout_seconds: int
    provider: Provider = "ollama"


# Roles — keep aligned with engagement.EngagementConfig.agent_selection
# values plus "orchestrator" / "analyst" / "defender".
ROLES = (
    "orchestrator",
    "recon",
    "scanner",
    "exploit",
    "postexploit",
    "analyst",
    "defender",
    "verifier",
)


_PROFILES: dict[ModelProfile, dict[str, ModelSpec]] = {
    ModelProfile.ECO: {
        "orchestrator": ModelSpec("llama3.1:8b", 8192, 180, "ollama"),
        "recon":        ModelSpec("llama3.2:3b", 8192, 60,  "ollama"),
        "scanner":      ModelSpec("llama3.2:3b", 8192, 60,  "ollama"),
        "exploit":      ModelSpec("qwen2.5-coder:7b", 8192, 120, "ollama"),
        "postexploit":  ModelSpec("qwen2.5-coder:7b", 8192, 120, "ollama"),
        "analyst":      ModelSpec("llama3.1:8b", 8192, 120, "ollama"),
        "defender":     ModelSpec("llama3.1:8b", 8192, 120, "ollama"),
        "verifier":     ModelSpec("qwen2.5-coder:7b", 8192, 120, "ollama"),
    },
    ModelProfile.MAX: {
        "orchestrator": ModelSpec("llama3.1:70b", 8192, 600, "ollama"),
        "recon":        ModelSpec("llama3.1:8b", 8192, 120, "ollama"),
        "scanner":      ModelSpec("llama3.1:8b", 8192, 120, "ollama"),
        "exploit":      ModelSpec("qwen2.5-coder:32b", 8192, 300, "ollama"),
        "postexploit":  ModelSpec("qwen2.5-coder:32b", 8192, 300, "ollama"),
        "analyst":      ModelSpec("llama3.1:70b", 8192, 300, "ollama"),
        "defender":     ModelSpec("llama3.1:70b", 8192, 300, "ollama"),
        "verifier":     ModelSpec("qwen2.5-coder:32b", 8192, 300, "ollama"),
    },
    ModelProfile.TEST: {
        role: ModelSpec("llama3.2:1b", 4096, 30, "ollama") for role in ROLES
    },
    ModelProfile.CLOUD_ECO: {
        "orchestrator": ModelSpec("claude-haiku-4-5-20251001", 200_000, 180, "anthropic"),
        "recon":        ModelSpec("claude-haiku-4-5-20251001", 200_000, 60,  "anthropic"),
        "scanner":      ModelSpec("claude-haiku-4-5-20251001", 200_000, 60,  "anthropic"),
        "exploit":      ModelSpec("gpt-4o-mini",               128_000, 120, "openai"),
        "postexploit":  ModelSpec("gpt-4o-mini",               128_000, 120, "openai"),
        "analyst":      ModelSpec("claude-haiku-4-5-20251001", 200_000, 120, "anthropic"),
        "defender":     ModelSpec("claude-haiku-4-5-20251001", 200_000, 120, "anthropic"),
        "verifier":     ModelSpec("gpt-4o-mini",               128_000, 120, "openai"),
    },
    ModelProfile.CLOUD_MAX: {
        "orchestrator": ModelSpec("claude-opus-4-7",          200_000, 600, "anthropic"),
        "recon":        ModelSpec("claude-sonnet-4-6",        200_000, 120, "anthropic"),
        "scanner":      ModelSpec("claude-sonnet-4-6",        200_000, 120, "anthropic"),
        "exploit":      ModelSpec("gpt-5",                    200_000, 300, "openai"),
        "postexploit":  ModelSpec("gpt-5",                    200_000, 300, "openai"),
        "analyst":      ModelSpec("claude-opus-4-7",          200_000, 300, "anthropic"),
        "defender":     ModelSpec("claude-opus-4-7",          200_000, 300, "anthropic"),
        "verifier":     ModelSpec("gpt-5",                    200_000, 300, "openai"),
    },
    ModelProfile.OPENAI_ONLY: {
        # Every role on OpenAI. Bigger models for planner/analyst/judge,
        # cheaper mini for high-volume scanner/recon/exploit so the
        # cost cap stays usable on a small budget. Adjust freely.
        "orchestrator": ModelSpec("gpt-4o",       128_000, 300, "openai"),
        "recon":        ModelSpec("gpt-4o-mini",  128_000, 60,  "openai"),
        "scanner":      ModelSpec("gpt-4o-mini",  128_000, 60,  "openai"),
        "exploit":      ModelSpec("gpt-4o-mini",  128_000, 120, "openai"),
        "postexploit":  ModelSpec("gpt-4o-mini",  128_000, 120, "openai"),
        "analyst":      ModelSpec("gpt-4o",       128_000, 180, "openai"),
        "defender":     ModelSpec("gpt-4o",       128_000, 180, "openai"),
        "verifier":     ModelSpec("gpt-4o-mini",  128_000, 120, "openai"),
    },
    ModelProfile.HYBRID: {
        # Planner/analyst quality matters most → cloud. Exploit code matters
        # → local code-specialised qwen-coder (cheap, fast, no rate limit).
        # Recon/scanner is bulk lookups → cheap cloud Haiku for speed.
        "orchestrator": ModelSpec("claude-opus-4-7",          200_000, 600, "anthropic"),
        "recon":        ModelSpec("claude-haiku-4-5-20251001", 200_000, 60,  "anthropic"),
        "scanner":      ModelSpec("claude-haiku-4-5-20251001", 200_000, 60,  "anthropic"),
        "exploit":      ModelSpec("qwen2.5-coder:7b",          8192,   120, "ollama"),
        "postexploit":  ModelSpec("qwen2.5-coder:7b",          8192,   120, "ollama"),
        "analyst":      ModelSpec("claude-sonnet-4-6",        200_000, 300, "anthropic"),
        "defender":     ModelSpec("claude-sonnet-4-6",        200_000, 300, "anthropic"),
        "verifier":     ModelSpec("qwen2.5-coder:7b",          8192,   120, "ollama"),
    },
}


def role_to_model(role: str, profile: ModelProfile | str = ModelProfile.ECO) -> ModelSpec:
    if isinstance(profile, str):
        profile = ModelProfile(profile)
    if role not in ROLES:
        raise KeyError(f"Unknown role {role!r}. Known: {ROLES}")
    return _PROFILES[profile][role]


def required_models(profile: ModelProfile | str = ModelProfile.ECO) -> set[str]:
    """The set of distinct *Ollama* model names a profile needs pulled.

    Cloud-only roles do not contribute — they are checked via
    `llm.credentials.check_provider` instead of the Ollama tag list.
    """
    if isinstance(profile, str):
        profile = ModelProfile(profile)
    return {
        spec.name
        for spec in _PROFILES[profile].values()
        if spec.provider == "ollama"
    }


def required_providers(profile: ModelProfile | str = ModelProfile.ECO) -> set[Provider]:
    """The set of distinct providers a profile needs credentials/connectivity for."""
    if isinstance(profile, str):
        profile = ModelProfile(profile)
    return {spec.provider for spec in _PROFILES[profile].values()}
