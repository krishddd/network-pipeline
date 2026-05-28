"""OpenAI provider adapter.

Returns a ChatOpenAI that supports `bind_tools` (required by
`create_react_agent`). Rate-limit retry is handled at the call site by
`llm.ratelimit.with_retry`, not here.
"""

from __future__ import annotations

import os
from typing import Any

from network_pipeline.llm.profiles import ModelSpec


def build(spec: ModelSpec, base_url: str | None = None) -> Any:
    from langchain_openai import ChatOpenAI  # type: ignore[import-not-found]

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Either export the key, switch to a profile "
            "that does not use openai (e.g. --profile eco), or pin the role to "
            "another provider via --provider-role."
        )
    kwargs: dict[str, Any] = dict(
        model=spec.name,
        timeout=spec.timeout_seconds,
        api_key=api_key,
    )
    if base_url:
        # Support OpenAI-compatible endpoints (e.g. local vLLM, OpenRouter).
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)
