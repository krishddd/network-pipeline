"""Async streaming subprocess runner with early-abort (Plan B.1.3).

The synchronous ``ShellRunner.run`` waits for the subprocess to finish,
then summarises its output. For long-running tools (``nuclei`` over a
large target set, ``ffuf`` against a deep wordlist) that means the
agent waits 5+ minutes before seeing a single result. Half of that
wall-time is wasted producing findings the agent will ignore once it
has enough signal to act.

Streaming mode replaces ``subprocess.run(...)`` with
``asyncio.create_subprocess_exec(..., stdout=PIPE)`` and drains the
stdout pipe line-by-line. Each line is parsed via ``output_schemas``
and folded into a running summary that's surfaced to the agent every
``summary_interval_s`` seconds. The agent is given an ``early_abort``
tool that cancels the underlying ``asyncio.Task`` and terminates the
subprocess, freeing the iteration to record findings and move on.

## LangGraph async-purity constraint (per the plan's risk #12)

Streaming tools MUST be defined as ``async def``. The agent must be
invoked via ``app.ainvoke()`` (the engagement loop already does this).
We never call ``asyncio.run()`` inside a tool body — that would nest
event loops and raise ``RuntimeError: This event loop is already
running`` under LangGraph's runner.

``early_abort(stream_id)`` resolves the stream from a module-level
registry of running tasks keyed by ``f"{objective_id}:{tool_name}"``;
calling it cancels the task and the streamer catches
``asyncio.CancelledError`` to terminate the subprocess cleanly.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from network_pipeline.core.logging import get_logger

log = get_logger("tools.streaming")


# Registry of in-flight streams. Keyed by f"{objective_id}:{tool_name}".
# Populated by ``stream_subprocess`` on entry and cleared on exit.
_RUNNING_STREAMS: dict[str, asyncio.Task] = {}


# Type alias for a per-line summariser. Takes the parsed line (any
# Pydantic model) and the running summary dict; mutates the summary in
# place. Return True to signal "enough — abort the stream".
LineHandler = Callable[[str, dict], bool]


@dataclass
class StreamResult:
    """Outcome of a streamed subprocess invocation."""

    binary: str
    argv: list[str]
    returncode: int | None
    stdout_path: Path
    stderr_path: Path
    duration_s: float
    summary: dict = field(default_factory=dict)
    aborted: bool = False
    error: str | None = None
    lines_seen: int = 0


def stream_id_for(objective_id: str, tool_name: str) -> str:
    """Canonical key into ``_RUNNING_STREAMS``."""
    return f"{objective_id or 'noobj'}:{tool_name}"


def early_abort(stream_id: str) -> bool:
    """Cancel an in-flight stream by id. Safe from any context.

    Returns True if a matching task was cancelled, False if the stream
    was already done or never registered.
    """
    task = _RUNNING_STREAMS.get(stream_id)
    if task is None or task.done():
        return False
    task.cancel()
    log.info("early_abort signalled for stream %s", stream_id)
    return True


async def stream_subprocess(
    *,
    binary_path: str,
    argv: list[str],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_s: int,
    objective_id: str,
    tool_name: str,
    line_handler: LineHandler | None = None,
    summary_interval_s: float = 10.0,
) -> StreamResult:
    """Run a subprocess and drain stdout line-by-line.

    The caller (typically a web-tool wrapper) supplies a
    ``line_handler`` that updates a ``summary`` dict for each parsed
    line. The handler returns True when enough signal has accumulated
    to trigger an abort — the streamer then terminates the subprocess.

    The caller is also responsible for providing a stable ``tool_name``
    + ``objective_id`` pair so ``early_abort`` can target this stream.

    On ``asyncio.CancelledError`` (i.e. ``early_abort`` was called) we
    terminate the subprocess gracefully via ``proc.terminate()`` then
    wait, escalating to ``proc.kill()`` if it doesn't exit within 2 s.
    """
    sid = stream_id_for(objective_id, tool_name)
    summary: dict = {"hits_by_severity": {}, "first_hits": [], "lines": 0}
    t0 = time.time()
    aborted = False
    error: str | None = None
    proc: asyncio.subprocess.Process | None = None
    lines_seen = 0

    # Open output sinks BEFORE spawning so a creation failure surfaces
    # cleanly instead of mid-drain.
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    so = open(stdout_path, "wb")
    se = open(stderr_path, "wb")

    async def _drain_stderr(proc: asyncio.subprocess.Process) -> None:
        if proc.stderr is None:
            return
        try:
            while True:
                chunk = await proc.stderr.read(4096)
                if not chunk:
                    break
                se.write(chunk)
        except (asyncio.CancelledError, OSError):
            pass

    async def _drain_stdout(proc: asyncio.subprocess.Process) -> int:
        nonlocal aborted
        count = 0
        last_summary_at = t0
        if proc.stdout is None:
            return 0
        while True:
            try:
                line_b = await proc.stdout.readline()
            except (asyncio.IncompleteReadError, ValueError):
                break
            if not line_b:
                break
            so.write(line_b)
            count += 1
            line_s = line_b.decode("utf-8", errors="replace").rstrip("\n")
            if line_handler is not None:
                try:
                    enough = line_handler(line_s, summary)
                except Exception as e:  # pragma: no cover - defensive
                    log.warning("line_handler raised: %r", e)
                    enough = False
                if enough:
                    aborted = True
                    log.info(
                        "stream %s reports enough signal at line %d", sid, count,
                    )
                    raise asyncio.CancelledError("line_handler signalled enough")
            now = time.time()
            if now - last_summary_at >= summary_interval_s:
                summary["lines"] = count
                last_summary_at = now
        summary["lines"] = count
        return count

    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                binary_path, *map(str, argv),
                cwd=str(cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (FileNotFoundError, PermissionError, OSError) as e:
            error = f"spawn failed: {e!r}"
            log.warning("stream %s spawn failed: %r", sid, e)
            return StreamResult(
                binary=Path(binary_path).name,
                argv=list(argv),
                returncode=None,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                duration_s=time.time() - t0,
                summary=summary,
                aborted=False,
                error=error,
                lines_seen=0,
            )

        drain_out = asyncio.create_task(_drain_stdout(proc))
        drain_err = asyncio.create_task(_drain_stderr(proc))
        # Register for early-abort lookups
        current = asyncio.current_task()
        if current is not None:
            _RUNNING_STREAMS[sid] = current

        try:
            lines_seen = await asyncio.wait_for(drain_out, timeout=timeout_s)
        except asyncio.TimeoutError:
            error = f"timeout after {timeout_s}s"
            log.warning("stream %s timed out", sid)
            await _terminate(proc)
        except asyncio.CancelledError:
            aborted = True
            await _terminate(proc)
            # Re-raise only if our own task was cancelled (not the
            # internal "enough" signal which we consumed above).
        finally:
            drain_err.cancel()
            try:
                await drain_err
            except (asyncio.CancelledError, Exception):
                pass

        # Make sure proc has actually exited
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            await _terminate(proc, force=True)
            rc = proc.returncode

        return StreamResult(
            binary=Path(binary_path).name,
            argv=list(argv),
            returncode=rc,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            duration_s=time.time() - t0,
            summary=summary,
            aborted=aborted,
            error=error,
            lines_seen=lines_seen,
        )
    finally:
        try:
            so.close()
        except OSError:
            pass
        try:
            se.close()
        except OSError:
            pass
        _RUNNING_STREAMS.pop(sid, None)


async def _terminate(
    proc: asyncio.subprocess.Process, *, force: bool = False,
) -> None:
    """Best-effort subprocess shutdown."""
    if proc.returncode is not None:
        return
    try:
        if force:
            proc.kill()
        else:
            proc.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            return
        try:
            await proc.wait()
        except Exception:  # pragma: no cover - defensive
            pass


def make_early_abort_tool(default_objective_id: str = ""):
    """Build a LangGraph ``@tool`` that exposes ``early_abort`` to the agent.

    Defined as ``async def`` to honour the LangGraph async-purity rule
    in the plan's risk #12 — agents invoked via ``ainvoke()`` can call
    this without nested-event-loop risk.
    """
    from langchain_core.tools import tool  # type: ignore[import-not-found]

    @tool
    async def early_abort_stream(tool_name: str, objective_id: str = "") -> str:
        """Cancel an in-flight streaming tool when enough results are in.

        Pass the same ``tool_name`` you used to start the stream (e.g.
        "nuclei") and the current ``objective_id``. Returns "aborted"
        on success, "no-op" if the stream had already finished.
        """
        oid = objective_id or default_objective_id
        sid = stream_id_for(oid, tool_name)
        ok = early_abort(sid)
        return "aborted" if ok else "no-op"

    return early_abort_stream
