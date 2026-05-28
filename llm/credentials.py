"""Credentials-aware provider availability check.

Inspired by Decepticon's `DECEPTICON_AUTH_PRIORITY`. Inspects the
environment for cloud API keys and probes Ollama reachability, returning
which providers are usable in this process. Consumed by `LLMFactory` to
fall back gracefully when a profile names a provider whose credentials
are missing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable

import httpx

from network_pipeline.core.logging import get_logger
from network_pipeline.llm.profiles import Provider

log = get_logger("llm.credentials")


@dataclass(frozen=True)
class ProviderStatus:
    provider: Provider
    available: bool
    reason: str  # human-readable: "OPENAI_API_KEY set", "ollama 404 on /api/tags", ...


def _check_openai() -> ProviderStatus:
    if os.environ.get("OPENAI_API_KEY"):
        return ProviderStatus("openai", True, "OPENAI_API_KEY set")
    return ProviderStatus("openai", False, "OPENAI_API_KEY missing")


def _check_anthropic() -> ProviderStatus:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ProviderStatus("anthropic", True, "ANTHROPIC_API_KEY set")
    return ProviderStatus("anthropic", False, "ANTHROPIC_API_KEY missing")


def _check_ollama(base_url: str, timeout: float = 3.0) -> ProviderStatus:
    url = base_url.rstrip("/") + "/api/tags"
    try:
        resp = httpx.get(url, timeout=timeout)
        resp.raise_for_status()
        return ProviderStatus("ollama", True, f"ollama reachable at {base_url}")
    except httpx.HTTPError as e:
        return ProviderStatus("ollama", False, f"ollama unreachable at {base_url}: {e!r}")


def check_provider(provider: Provider, ollama_base_url: str = "http://localhost:11434") -> ProviderStatus:
    if provider == "openai":
        return _check_openai()
    if provider == "anthropic":
        return _check_anthropic()
    if provider == "ollama":
        return _check_ollama(ollama_base_url)
    raise ValueError(f"unknown provider {provider!r}")


def available_providers(
    ollama_base_url: str = "http://localhost:11434",
) -> dict[Provider, ProviderStatus]:
    """Probe every supported provider; return a map keyed by provider name."""
    return {
        "openai": _check_openai(),
        "anthropic": _check_anthropic(),
        "ollama": _check_ollama(ollama_base_url),
    }


def fallback_chain(
    requested: Provider,
    ollama_base_url: str = "http://localhost:11434",
) -> list[Provider]:
    """Ordered fallback list for a requested provider.

    Preference: requested → other cloud → ollama. Only providers that pass
    `check_provider` are included. Returns at least one entry on success;
    empty list means *nothing* is usable (caller should abort).
    """
    statuses = available_providers(ollama_base_url)
    # Preference order: requested first, then sibling cloud, then ollama.
    preference: dict[Provider, list[Provider]] = {
        "anthropic": ["anthropic", "openai", "ollama"],
        "openai":    ["openai", "anthropic", "ollama"],
        "ollama":    ["ollama", "anthropic", "openai"],
    }
    return [p for p in preference[requested] if statuses[p].available]


def auto_profile(ollama_base_url: str = "http://localhost:11434") -> str:
    """Choose a sensible profile based on which providers are reachable.

    Highest priority: ``NETWORK_PIPELINE_PROFILE`` env var (set via
    ``.env`` or shell). When unset, falls back to credential probing:

      - OpenAI key present, Ollama NOT reachable  → ``openai_only``
      - Anthropic + OpenAI keys present           → ``cloud_eco``
      - Anthropic key + Ollama reachable          → ``hybrid``
      - OpenAI key + Ollama reachable             → ``cloud_eco``
      - Ollama only                                → ``eco``
      - Nothing reachable                          → ``eco`` (will error at probe)
    """
    override = os.environ.get("NETWORK_PIPELINE_PROFILE", "").strip()
    if override:
        return override
    statuses = available_providers(ollama_base_url)
    has_openai = statuses["openai"].available
    has_anthropic = statuses["anthropic"].available
    has_ollama = statuses["ollama"].available

    if has_openai and not has_anthropic and not has_ollama:
        return "openai_only"
    if has_openai and has_anthropic:
        return "cloud_eco"
    if has_anthropic and has_ollama:
        return "hybrid"
    if has_openai and has_ollama:
        return "cloud_eco"
    if has_openai:
        return "openai_only"
    return "eco"


def load_dotenv_files() -> list[str]:
    """Load .env files if python-dotenv is installed. Searches:

      1. ``$CWD/.env``                — the conventional place
      2. ``$CWD/../.env``             — one level up (monorepo root)
      3. ``<network_pipeline>/.env``  — the package directory itself

    The third lookup means users can run ``python -m network_pipeline.cli``
    from any directory and the package's ``.env`` is still found. Real
    shell env vars override values from the file (``override=False``).

    Returns the list of files actually loaded. Idempotent.
    """
    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]
    except ImportError:
        return []
    from pathlib import Path as _P

    # credentials.py lives at network_pipeline/llm/credentials.py — go
    # up two levels for the package directory.
    package_dir = _P(__file__).resolve().parent.parent

    candidates = [
        _P.cwd() / ".env",
        _P.cwd().parent / ".env",
        package_dir / ".env",
    ]
    loaded: list[str] = []
    for candidate in candidates:
        if not candidate.is_file():
            continue
        canonical = str(candidate.resolve())
        if canonical in loaded:
            continue
        # override=False so a real shell env var wins over a .env file.
        if load_dotenv(dotenv_path=candidate, override=False):
            loaded.append(canonical)
    return loaded


def format_status_report(ollama_base_url: str = "http://localhost:11434") -> str:
    lines = ["Provider availability:"]
    for status in available_providers(ollama_base_url).values():
        mark = "OK " if status.available else "-- "
        lines.append(f"  {mark}{status.provider:9s}  {status.reason}")
    return "\n".join(lines)
