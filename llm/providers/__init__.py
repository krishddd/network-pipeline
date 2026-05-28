"""Per-provider ChatModel adapters.

Each adapter exposes `build(spec, base_url=None)` returning a LangChain
ChatModel that supports `bind_tools` (required by
`create_react_agent`). Imports of provider SDKs are deferred so the
test suite and the Ollama-only happy path don't need them installed.
"""

from network_pipeline.llm.providers.anthropic_chat import build as build_anthropic
from network_pipeline.llm.providers.ollama_chat import build as build_ollama
from network_pipeline.llm.providers.openai_chat import build as build_openai

__all__ = ["build_anthropic", "build_ollama", "build_openai"]
