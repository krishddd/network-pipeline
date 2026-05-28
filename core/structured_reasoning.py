"""SIRAJ-style structured reasoning for internal agents.

Background (see "LLM Red-Teaming Techniques Explained.md", section
*SIRAJ*): forcing a strict 4-component reasoning JSON before tool calls
compresses average reasoning traces by ~70% with no loss of attack
success — in the paper, the 8B distilled student beat its own 671B
teacher when both were constrained to this format. We apply the same
contract to our own internal agents (orchestrator, recon, scanner,
exploit, postexploit, analyst, defender, verifier).

This module is *enforcement-light*:

- A canonical reasoning contract block is appended to every agent's
  system prompt (see ``REASONING_CONTRACT_BLOCK``).
- The trace handler parses each assistant message for the leading
  ```json {...} ``` SIRAJ block via ``parse_reasoning_block`` and logs
  a ``reasoning_tokens`` + ``reasoning_valid`` field per LLM exchange
  so the operator can measure the compression win on their own runs
  (A/B with ``--structured-reasoning off``).
- We do NOT hard-reject a free-form response mid-iteration — that would
  break the ReAct loop unrecoverably for models that occasionally drop
  the JSON. Instead, observation + a clear contract in the prompt is
  what gets us most of the win; persistently non-compliant models
  surface in the trace stats and the operator can pin those roles to a
  better model via ``--provider-role``.

The contract:

  ```json
  {
    "understand":      "...",   # what is the objective right now
    "prior_failures":  "...",   # what just failed and why (or "none")
    "strategy_shift":  "...",   # the new angle being taken
    "implementation":  "..."    # exactly which tool call(s) are next
  }
  ```

Each field has a soft 100-token budget; the whole block is capped at
~400 tokens combined. Tool calls follow the JSON block.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable

from pydantic import BaseModel, Field


# Maximum tokens allowed inside the SIRAJ reasoning block before we flag
# the assistant message as over-budget. The model is reminded of this
# in the contract; the trace tags ``over_budget`` for analytics.
SIRAJ_MAX_REASONING_TOKENS = 400


class SIRAJReasoning(BaseModel):
    """The 4-component structured reasoning block."""

    understand: str = Field(..., description="Current objective in one sentence.")
    prior_failures: str = Field(
        ...,
        description="What was tried and failed in the last 1-3 turns, or 'none'.",
    )
    strategy_shift: str = Field(..., description="New angle / why it should work.")
    implementation: str = Field(..., description="Concrete next tool call(s).")


REASONING_CONTRACT_BLOCK = """\

## REASONING CONTRACT (mandatory, SIRAJ-style)

Before EVERY tool call, emit a single fenced JSON block matching this
schema EXACTLY:

```json
{
  "understand":     "<one sentence: what is the current objective>",
  "prior_failures": "<one short paragraph: what was just tried that did NOT work, and why; 'none' if first turn>",
  "strategy_shift": "<one short paragraph: the new angle you are taking and why it should work>",
  "implementation": "<one sentence: the exact next tool call(s) you will make>"
}
```

Rules:
- The JSON block MUST be the FIRST thing in your reply, before any
  tool calls or prose.
- Combined budget is ~400 tokens across all four fields. Be terse.
- No prose outside the JSON before tool calls. No commentary.
- After tool results return, emit a new JSON block updating
  ``prior_failures`` (what just happened) and ``strategy_shift``
  (next move). Do NOT repeat verbatim — refine.
- This format compresses your reasoning into the hot path. Long
  meandering chains-of-thought are explicitly discouraged.
"""


# Matches the FIRST ```json {...} ``` fenced block at the start of a
# message. We tolerate optional leading whitespace and an optional
# language hint (`json` is canonical but we accept the bare form).
_REASONING_BLOCK_RE = re.compile(
    r"^\s*```(?:json)?\s*\n(?P<body>\{.*?\})\s*\n```",
    re.DOTALL,
)


@dataclass(frozen=True)
class ReasoningExtraction:
    """Outcome of parsing an assistant message for the SIRAJ block."""

    valid: bool
    reasoning: SIRAJReasoning | None
    reasoning_text: str  # raw JSON substring if found, else ""
    reason: str  # human-readable diagnosis when valid is False


def parse_reasoning_block(message: str) -> ReasoningExtraction:
    """Extract + validate the leading SIRAJ JSON block from a message.

    Tolerant by design — returns ``valid=False`` with a diagnosis rather
    than raising. The diagnosis goes into the trace so the operator can
    grep for non-compliant roles.
    """
    if not message:
        return ReasoningExtraction(False, None, "", "empty message")

    match = _REASONING_BLOCK_RE.search(message)
    if not match:
        return ReasoningExtraction(False, None, "", "no leading ```json block")

    body = match.group("body")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        return ReasoningExtraction(False, None, body, f"json decode error: {e}")
    if not isinstance(payload, dict):
        return ReasoningExtraction(False, None, body, "json root is not an object")

    try:
        reasoning = SIRAJReasoning(**payload)
    except Exception as e:  # noqa: BLE001 — pydantic ValidationError varies by version
        return ReasoningExtraction(False, None, body, f"schema mismatch: {e}")

    return ReasoningExtraction(True, reasoning, body, "ok")


def estimate_reasoning_tokens(text: str) -> int:
    """Approximate token count of the reasoning text.

    Uses tiktoken when available (more accurate); falls back to a
    char/4 estimate otherwise. Either way the operator gets a useful
    A/B signal — absolute precision doesn't matter, deltas across
    runs do.
    """
    if not text:
        return 0
    try:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        # Char/4 is a well-known back-of-envelope for English text.
        return max(1, len(text) // 4)


def annotate_message(message: str) -> dict[str, object]:
    """Convenience: parse + count, return a dict ready for trace JSONL.

    Caller (TraceCallbackHandler) merges this dict into the trace
    record. Keeps the parse/tokenise logic in one place.
    """
    extraction = parse_reasoning_block(message)
    tokens = estimate_reasoning_tokens(extraction.reasoning_text)
    return {
        "reasoning_valid": extraction.valid,
        "reasoning_tokens": tokens,
        "reasoning_over_budget": tokens > SIRAJ_MAX_REASONING_TOKENS,
        "reasoning_diagnosis": extraction.reason,
    }


__all__ = [
    "REASONING_CONTRACT_BLOCK",
    "ReasoningExtraction",
    "SIRAJReasoning",
    "SIRAJ_MAX_REASONING_TOKENS",
    "annotate_message",
    "estimate_reasoning_tokens",
    "parse_reasoning_block",
]
