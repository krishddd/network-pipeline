"""Structured logging + LangChain callback handler for offline observability.

Two artifacts are written per engagement under ``workspace/run/<id>/``:

* ``pipeline.log`` — human-readable engagement-level events.
* ``agent_traces.log`` — JSONL, one line per LLM exchange, captures the
  raw reasoning text. This is the primary artifact for post-mortems
  when LangSmith is not available.

If ``LANGCHAIN_API_KEY`` is set, LangSmith mirroring activates
automatically (LangChain handles that at the client level — we just
write our offline traces in addition).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from datetime import date, datetime
from pathlib import Path
from typing import Any
from uuid import UUID


def _trace_default(obj: Any) -> Any:
    """JSON encoder default for the trace log.

    Preserves structure for common non-serialisable types (datetime →
    ISO-8601, Path → str, bytes → utf-8/latin-1, Pydantic models →
    model_dump) instead of collapsing everything to str().
    """
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (bytes, bytearray)):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.decode("latin-1", errors="replace")
    if isinstance(obj, set):
        return sorted(obj, key=str)
    # Pydantic v2 models expose model_dump
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            return dump()
        except Exception:  # pragma: no cover - defensive
            pass
    return str(obj)

# LangChain imports are deferred so unit tests for non-agent code don't
# require langchain-core to be installed.
try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
except ImportError:  # pragma: no cover - allows partial installs
    BaseCallbackHandler = object  # type: ignore[misc,assignment]
    LLMResult = Any  # type: ignore[misc,assignment]


_LOGGERS: dict[str, logging.Logger] = {}


def get_logger(name: str) -> logging.Logger:
    if name in _LOGGERS:
        return _LOGGERS[name]
    log = logging.getLogger(f"network_pipeline.{name}")
    if not log.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        log.addHandler(h)
        log.setLevel(os.environ.get("NETWORK_PIPELINE_LOG_LEVEL", "INFO"))
    _LOGGERS[name] = log
    return log


def attach_pipeline_log(workspace: Path) -> logging.Handler:
    """Add a file handler that mirrors all pipeline logs into the workspace."""
    workspace.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(workspace / "pipeline.log")
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logging.getLogger("network_pipeline").addHandler(handler)
    return handler


class TraceCallbackHandler(BaseCallbackHandler):  # type: ignore[misc,valid-type]
    """LangChain callback that writes one JSONL line per LLM exchange.

    Captures: agent name, iteration, phase, prompt tokens (estimated),
    response text, tool calls, and latency. Cross-references the
    workspace ``tool_io/`` files via the LangChain ``run_id``.
    """

    def __init__(
        self,
        workspace: Path,
        agent: str,
        iteration: int = 0,
        phase: str = "",
        engagement_id: str = "",
    ) -> None:
        self._path = workspace / "agent_traces.log"
        self._agent = agent
        self._iteration = iteration
        self._phase = phase
        self._engagement_id = engagement_id
        self._t0: dict[UUID, float] = {}

    # ── helpers ────────────────────────────────────────────────────

    def _write(self, payload: dict[str, Any]) -> None:
        payload.setdefault("ts", time.time())
        payload.setdefault("agent", self._agent)
        payload.setdefault("iteration", self._iteration)
        payload.setdefault("phase", self._phase)
        payload.setdefault("engagement_id", self._engagement_id)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, default=_trace_default) + "\n")

    # ── LLM events ─────────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        if run_id is not None:
            self._t0[run_id] = time.time()
        # Hash-only of prompt to avoid balooning the trace file.
        self._write(
            {
                "event": "llm_start",
                "run_id": str(run_id) if run_id else "",
                "model": (serialized or {}).get("name", ""),
                "prompt_chars": sum(len(p) for p in prompts),
                "prompt_count": len(prompts),
            }
        )

    def on_llm_end(
        self,
        response: LLMResult,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        latency_ms = 0.0
        if run_id is not None and run_id in self._t0:
            latency_ms = (time.time() - self._t0.pop(run_id)) * 1000
        text = ""
        try:
            text = response.generations[0][0].text  # type: ignore[index]
        except Exception:
            pass
        payload: dict[str, Any] = {
            "event": "llm_end",
            "run_id": str(run_id) if run_id else "",
            "response_text": text[:8000],  # cap per-line size
            "latency_ms": round(latency_ms, 1),
        }
        # Phase-2: SIRAJ-style structured reasoning observability. Parses
        # the leading ```json{...}``` block in the assistant message and
        # tags the trace with reasoning_valid / reasoning_tokens so the
        # operator can A/B compare with --structured-reasoning off.
        try:
            from network_pipeline.core.structured_reasoning import annotate_message
            payload.update(annotate_message(text))
        except Exception:
            # Trace handler must never crash an engagement.
            pass
        self._write(payload)

    def on_llm_error(
        self, error: BaseException, *, run_id: UUID | None = None, **kwargs: Any
    ) -> None:
        self._write(
            {
                "event": "llm_error",
                "run_id": str(run_id) if run_id else "",
                "error": repr(error),
            }
        )

    # ── tool events ────────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        if run_id is not None:
            self._t0[run_id] = time.time()
        self._write(
            {
                "event": "tool_start",
                "run_id": str(run_id) if run_id else "",
                "tool": (serialized or {}).get("name", ""),
                "input_preview": input_str[:500],
            }
        )

    def on_tool_end(
        self, output: str, *, run_id: UUID | None = None, **kwargs: Any
    ) -> None:
        latency_ms = 0.0
        if run_id is not None and run_id in self._t0:
            latency_ms = (time.time() - self._t0.pop(run_id)) * 1000
        self._write(
            {
                "event": "tool_end",
                "run_id": str(run_id) if run_id else "",
                "output_preview": str(output)[:1000],
                "latency_ms": round(latency_ms, 1),
            }
        )

    def on_tool_error(
        self, error: BaseException, *, run_id: UUID | None = None, **kwargs: Any
    ) -> None:
        self._write(
            {
                "event": "tool_error",
                "run_id": str(run_id) if run_id else "",
                "error": repr(error),
            }
        )


def make_correlation_id() -> str:
    """Short prefix for correlating log lines across files."""
    return uuid.uuid4().hex[:8]
