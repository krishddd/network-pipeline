"""Tests for tools.streaming — async subprocess + early_abort.

Uses ``python -c`` as a portable, deterministic line-emitting
subprocess instead of mocking. Each test exercises a real
``asyncio.create_subprocess_exec`` path so the LangGraph async-purity
constraint is actually checked end-to-end.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest


def _emit_lines_argv(n: int, sleep_ms: int = 5) -> tuple[str, list[str]]:
    """Return (binary_path, argv) that emits ``n`` JSON lines slowly."""
    code = (
        "import json,sys,time\n"
        f"for i in range({n}):\n"
        f"    sys.stdout.write(json.dumps({{'i':i}})+'\\n')\n"
        "    sys.stdout.flush()\n"
        f"    time.sleep({sleep_ms}/1000)\n"
    )
    return sys.executable, ["-c", code]


@pytest.mark.asyncio
async def test_stream_drains_all_lines(tmp_path: Path):
    from network_pipeline.tools.streaming import stream_subprocess

    bp, argv = _emit_lines_argv(5, sleep_ms=1)
    res = await stream_subprocess(
        binary_path=bp, argv=argv,
        cwd=tmp_path,
        stdout_path=tmp_path / "out", stderr_path=tmp_path / "err",
        timeout_s=5,
        objective_id="OBJ-001", tool_name="tester",
    )
    assert res.returncode == 0
    assert res.lines_seen == 5
    assert res.aborted is False
    assert (tmp_path / "out").exists()


@pytest.mark.asyncio
async def test_line_handler_can_signal_enough(tmp_path: Path):
    from network_pipeline.tools.streaming import stream_subprocess

    bp, argv = _emit_lines_argv(50, sleep_ms=10)

    def handler(line: str, summary: dict) -> bool:
        summary["seen"] = summary.get("seen", 0) + 1
        return summary["seen"] >= 3

    res = await stream_subprocess(
        binary_path=bp, argv=argv,
        cwd=tmp_path,
        stdout_path=tmp_path / "out", stderr_path=tmp_path / "err",
        timeout_s=10,
        objective_id="OBJ-002", tool_name="tester",
        line_handler=handler,
    )
    assert res.aborted is True
    assert res.summary.get("seen", 0) >= 3
    # Subprocess was terminated, not the full 50 lines drained
    assert res.lines_seen < 50


@pytest.mark.asyncio
async def test_early_abort_cancels_running_stream(tmp_path: Path):
    from network_pipeline.tools.streaming import (
        early_abort, stream_id_for, stream_subprocess,
    )

    bp, argv = _emit_lines_argv(100, sleep_ms=20)

    async def runner() -> None:
        await stream_subprocess(
            binary_path=bp, argv=argv,
            cwd=tmp_path,
            stdout_path=tmp_path / "out", stderr_path=tmp_path / "err",
            timeout_s=10,
            objective_id="OBJ-003", tool_name="tester",
        )

    task = asyncio.create_task(runner())
    # Give the subprocess time to register itself in the registry
    await asyncio.sleep(0.15)
    sid = stream_id_for("OBJ-003", "tester")
    aborted = early_abort(sid)
    assert aborted is True
    # Task completes cleanly (we caught CancelledError internally)
    try:
        await asyncio.wait_for(task, timeout=5)
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_spawn_failure_returns_typed_error(tmp_path: Path):
    from network_pipeline.tools.streaming import stream_subprocess

    res = await stream_subprocess(
        binary_path="/nonexistent/binary-xyz", argv=["arg"],
        cwd=tmp_path,
        stdout_path=tmp_path / "out", stderr_path=tmp_path / "err",
        timeout_s=2,
        objective_id="OBJ-004", tool_name="tester",
    )
    assert res.error is not None
    assert "spawn" in (res.error or "").lower()


def test_early_abort_unknown_id_returns_false():
    from network_pipeline.tools.streaming import early_abort

    assert early_abort("nonexistent:tool") is False
