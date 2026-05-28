"""Ollama provider adapter — wraps the existing ChatOllama path.

Carries over the existing factory's behaviour: forwards reproducibility
seed via `seed` kwarg, sets `num_ctx`, attaches request timeout. Does
NOT wrap with `.with_retry()` (that returns a RunnableRetry which has
no `bind_tools` — same bug noted in the original factory.py).
"""

from __future__ import annotations

from typing import Any

from network_pipeline.core.seed import current_seed
from network_pipeline.llm.profiles import ModelSpec


def build(spec: ModelSpec, base_url: str = "http://localhost:11434") -> Any:
    from langchain_ollama import ChatOllama  # type: ignore[import-not-found]

    kwargs: dict[str, Any] = dict(
        model=spec.name,
        base_url=base_url.rstrip("/"),
        timeout=spec.timeout_seconds,
        num_ctx=spec.context_window,
    )
    seed_val = current_seed()
    if seed_val is not None:
        kwargs["seed"] = int(seed_val)
    return ChatOllama(**kwargs)
