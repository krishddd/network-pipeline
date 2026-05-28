"""Two-tier memory hierarchy (Plan B.2.5).

* **Episodic memory** — at iteration end, a 200-token "what was learned"
  summary is appended to ``workspace/memory/episodic.jsonl``. The next
  iteration's orchestrator gets the most recent N entries injected into
  its system prompt as a "Recent learnings" block.

* **Working-set scratchpad** — ``scratch_append(text)`` is exposed to
  agents as a `@tool`; the file lives at
  ``workspace/memory/scratch/<obj_id>.txt`` and is capped at 8 KB.
  Crucially there is **NO** ``scratch_read`` tool — the orchestrator
  injects the file's contents into the system prompt automatically when
  ``objective.retries > 0``. This matches the plan's risk-#13 mitigation:
  the LLM can write but cannot spam-read, so it can't blow the budget on
  self-reflection tokens.

Both tiers are filesystem-backed JSONL / plain text — atomic writes via
tmp + os.replace; no locks needed for the per-objective scratchpad
(single agent at a time per objective).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from network_pipeline.core.logging import get_logger

log = get_logger("core.episodic")


# Hard cap so a runaway agent can't fill the disk via scratch_append.
SCRATCHPAD_MAX_BYTES = 8 * 1024


# ── Episodic memory (per-iteration "what was learned") ───────────────


class EpisodicMemory:
    """Append-only JSONL of per-iteration summaries."""

    def __init__(self, workspace: Path) -> None:
        self._path = workspace / "memory" / "episodic.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        *,
        iteration: int,
        objective_id: str,
        agent: str,
        learned: str,
        engagement_id: str = "",
    ) -> None:
        """Persist one episode. ``learned`` should be ≤200 tokens."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "engagement_id": engagement_id,
            "iteration": iteration,
            "objective_id": objective_id,
            "agent": agent,
            "learned": learned[:1500],  # ~200 tokens at 7-8 chars/token
        }
        # POSIX O_APPEND on small lines is atomic — no lock needed.
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

    def recent(self, n: int = 5) -> list[dict]:
        """Return the last ``n`` episodes, newest last."""
        if not self._path.exists():
            return []
        out: list[dict] = []
        # Tail-read: read the whole file (small) and slice.
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return []
        return out[-n:]

    def render_for_prompt(self, n: int = 5) -> str:
        """Format the last ``n`` episodes as a compact prompt block.

        Empty string when there are no episodes — caller can no-op
        the system message addition.
        """
        items = self.recent(n)
        if not items:
            return ""
        lines = ["## Recent learnings (last %d iterations)" % len(items)]
        for ep in items:
            lines.append(
                f"- iter {ep.get('iteration', '?')} "
                f"({ep.get('agent', '?')}, {ep.get('objective_id', '?')}): "
                f"{ep.get('learned', '').strip()}"
            )
        return "\n".join(lines)


# ── Working-set scratchpad (per-objective hypothesis log) ────────────


class Scratchpad:
    """Per-objective text file, append-only via tool, read-by-injection.

    The orchestrator injects ``read(obj_id)`` content into the system
    prompt only at the start of a retry iteration — see Plan risk #13
    and the engagement-loop wiring.
    """

    def __init__(self, workspace: Path) -> None:
        self._dir = workspace / "memory" / "scratch"
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, objective_id: str) -> Path:
        # Sanitise; objective ids look like OBJ-001 / OBJ-PB003.
        safe = "".join(
            c for c in (objective_id or "noobj") if c.isalnum() or c in "-_"
        )
        return self._dir / f"{safe}.txt"

    def append(self, objective_id: str, text: str) -> str:
        """Append ``text`` to the scratchpad. Returns a short status string.

        Truncates the file to ``SCRATCHPAD_MAX_BYTES`` (keeping the
        latest content) so a runaway agent can't grow it unboundedly.
        """
        if not text:
            return "scratch_append: empty text — no-op"
        p = self._path_for(objective_id)
        prefix = ""
        if p.exists():
            try:
                prefix = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                prefix = ""
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        new_block = f"\n[{ts}] {text.strip()}\n"
        combined = (prefix + new_block).encode("utf-8")
        if len(combined) > SCRATCHPAD_MAX_BYTES:
            # Drop the oldest bytes to fit the cap.
            combined = b"...[earlier truncated]\n" + combined[-(SCRATCHPAD_MAX_BYTES - 32):]
        tmp = p.with_suffix(".txt.tmp")
        tmp.write_bytes(combined)
        os.replace(tmp, p)
        return f"scratch_append: ok ({len(combined)} bytes total)"

    def read(self, objective_id: str) -> str:
        """Internal-only — for orchestrator system-prompt injection.

        Not exposed as a `@tool` (see module docstring).
        """
        p = self._path_for(objective_id)
        if not p.exists():
            return ""
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def render_for_retry_prompt(self, objective_id: str) -> str:
        """Format the scratchpad for inclusion at the START of a retry.

        Returns empty when no scratch exists. Caller checks
        ``objective.retries > 0`` before calling — attempt #1 sees
        nothing, attempt #2+ sees prior thinking.
        """
        body = self.read(objective_id).strip()
        if not body:
            return ""
        return (
            "## Prior attempt notes (from your earlier scratch on this objective)\n"
            "Read these before deciding what to try next; do not redo work that failed.\n\n"
            f"{body}"
        )


# ── @tool builder for scratch_append ─────────────────────────────────


def make_scratch_tool(workspace: Path):
    """Build a LangGraph ``@tool`` for ``scratch_append``.

    Note: read access is intentionally NOT exposed — see module
    docstring + plan risk #13.
    """
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    pad = Scratchpad(workspace)

    @tool
    def scratch_append(objective_id: str, text: str) -> str:
        """Append a short hypothesis / observation to this objective's scratchpad.

        The scratchpad survives across retries — the next attempt will
        see what you wrote here. There is no read tool: the orchestrator
        injects scratchpad content automatically on retries.
        Cap: 8 KB (oldest content is dropped when full).
        """
        return pad.append(objective_id, text)

    return scratch_append
