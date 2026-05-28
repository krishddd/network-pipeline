"""Multi-provider ChatModel factory.

Per-role model resolution across Ollama / OpenAI / Anthropic. Each role
in the active profile names a provider; this factory dispatches to the
right adapter and caches the resulting ChatModel.

Backwards-compat: `OllamaLLMFactory` is kept as a thin alias of
`LLMFactory` so existing imports continue to work. Old code that passes
only `base_url` and an Ollama-only profile still behaves identically.

Phase-1 additions:

* Multi-provider dispatch via `llm.providers.*` adapters.
* `available_providers` / `fallback_chain` consulted at probe time —
  if a profile names anthropic/openai but the key is missing, the
  fallback chain transparently routes to ollama (or aborts if no
  provider has credentials).
* Cost tracking (`llm.cost.CostTracker`) is wired at call sites
  (engagement loop), not in the factory itself, because we need the
  *post-response* token counts.
* Rate-limit retry (`llm.ratelimit.with_retry`) is also wired at call
  sites — wrapping `bind_tools()` here would break the
  `create_react_agent` contract.
* `_INFERENCE_LOCK` is preserved for Ollama-only callers; cloud
  providers do not need it (they don't share local VRAM).
"""

from __future__ import annotations

import asyncio
from typing import Any

from network_pipeline.core.logging import get_logger
from network_pipeline.llm import providers as _providers
from network_pipeline.llm.credentials import (
    available_providers,
    fallback_chain,
)
from network_pipeline.llm.profiles import (
    ModelProfile,
    ModelSpec,
    Provider,
    required_models,
    required_providers,
    role_to_model,
)

log = get_logger("llm.factory")


_INFERENCE_LOCK = asyncio.Lock()


def inference_lock() -> asyncio.Lock:
    """Return the process-wide Ollama-inference lock for parallel scheduling.

    Cloud providers do NOT acquire this lock — they are network-bound and
    have their own rate-limit handling via `llm.ratelimit.with_retry`.
    """
    return _INFERENCE_LOCK


class OllamaUnavailable(RuntimeError):
    """Raised when the Ollama server is unreachable or missing required models."""


class NoProvidersAvailable(RuntimeError):
    """Raised when no provider has working credentials/connectivity."""


class LLMFactory:
    """Resolves and caches ChatModel instances per role, dispatched by provider."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        profile: ModelProfile | str = ModelProfile.ECO,
        provider_overrides: dict[str, Provider] | None = None,
        openai_base_url: str | None = None,
        anthropic_base_url: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._profile = ModelProfile(profile) if isinstance(profile, str) else profile
        self._provider_overrides = dict(provider_overrides or {})
        self._openai_base_url = openai_base_url
        self._anthropic_base_url = anthropic_base_url
        self._cache: dict[str, Any] = {}
        # Will be populated by .probe() — maps a *requested* provider for
        # the active profile to the *effective* provider after fallback.
        self._effective_provider: dict[Provider, Provider] = {}

    # ── readiness probe ────────────────────────────────────────────

    def probe(self, timeout: float = 5.0) -> None:
        """Per-provider readiness check honouring the credentials chain.

        Raises:
          NoProvidersAvailable — when nothing is usable.
          OllamaUnavailable — when Ollama is the *only* required provider
            and it's down (preserved for backwards-compat callers).

        Short-circuits the Ollama tag-list check when the active
        profile (e.g. ``openai_only``) doesn't reference Ollama at all
        — otherwise an operator with only an OpenAI key would fail
        the probe purely because Ollama isn't running.
        """
        needed = required_providers(self._profile)
        statuses = available_providers(self._base_url)

        for provider in needed:
            if statuses[provider].available:
                self._effective_provider[provider] = provider
                continue
            chain = fallback_chain(provider, self._base_url)
            if not chain:
                if needed == {"ollama"}:
                    raise OllamaUnavailable(statuses["ollama"].reason)
                raise NoProvidersAvailable(
                    "No LLM provider is reachable. "
                    + "; ".join(f"{p}: {s.reason}" for p, s in statuses.items())
                )
            self._effective_provider[provider] = chain[0]
            log.warning(
                "provider %s unavailable (%s) — falling back to %s",
                provider, statuses[provider].reason, chain[0],
            )

        # Ollama-specific extra check: tag list must contain the required
        # model families. Skip for cloud-only effective routings.
        if "ollama" in {self._effective_provider.get(p, p) for p in needed}:
            self._probe_ollama_tags()

        log.info(
            "LLM probe OK (profile=%s, providers=%s)",
            self._profile, self._effective_provider,
        )

    def _probe_ollama_tags(self) -> None:
        import httpx  # local to keep tests dependency-light

        try:
            resp = httpx.get(f"{self._base_url}/api/tags", timeout=5.0)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise OllamaUnavailable(
                f"Cannot reach Ollama at {self._base_url}: {e!r}. "
                "Is `ollama serve` running?"
            ) from e

        installed = {m["name"].split(":")[0] for m in resp.json().get("models", [])}
        required_families = {m.split(":")[0] for m in required_models(self._profile)}
        missing = required_families - installed
        if missing:
            raise OllamaUnavailable(
                f"Ollama reachable but missing model families: {sorted(missing)}. "
                f"Pull them: ollama pull {' '.join(sorted(missing))}"
            )

    # ── model creation ─────────────────────────────────────────────

    def _resolve_provider(self, spec: ModelSpec, role: str) -> Provider:
        if role in self._provider_overrides:
            return self._provider_overrides[role]
        return self._effective_provider.get(spec.provider, spec.provider)

    def get_model(self, role: str) -> Any:
        """Return a ChatModel for the role, dispatched by effective provider."""
        spec: ModelSpec = role_to_model(role, self._profile)
        # Adaptive override (Phase-3 router; no-op when not attached).
        router = getattr(self, "_adaptive_router", None)
        effective_name = spec.name
        if router is not None:
            effective_name = router.effective_model(role, spec.name)
        provider = self._resolve_provider(spec, role)
        cache_key = f"{role}::{provider}::{effective_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Build with the effective name (router may have promoted).
        effective_spec = ModelSpec(
            name=effective_name,
            context_window=spec.context_window,
            timeout_seconds=spec.timeout_seconds,
            provider=provider,
        )
        if provider == "ollama":
            model = _providers.build_ollama(effective_spec, self._base_url)
        elif provider == "openai":
            model = _providers.build_openai(effective_spec, self._openai_base_url)
        elif provider == "anthropic":
            model = _providers.build_anthropic(effective_spec, self._anthropic_base_url)
        else:
            raise ValueError(f"unknown provider {provider!r} for role {role!r}")

        self._cache[cache_key] = model
        log.debug(
            "created ChatModel role=%s provider=%s model=%s timeout=%ds",
            role, provider, effective_name, spec.timeout_seconds,
        )
        return model

    def context_window(self, role: str) -> int:
        return role_to_model(role, self._profile).context_window

    def provider_for(self, role: str) -> Provider:
        """Public accessor used by cost/ratelimit wiring at call sites."""
        spec = role_to_model(role, self._profile)
        return self._resolve_provider(spec, role)


# Backwards-compat alias — existing imports in engagement_loop etc.
OllamaLLMFactory = LLMFactory
