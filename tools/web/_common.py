"""Shared helpers for ``tools.web.*`` wrappers.

Common patterns:

* ``run_and_summarise(runner, binary, argv, ...)`` — invokes the
  ShellRunner, returns a formatted summary string with the raw stdout
  path so the agent can ingest later. All the wrappers in this package
  share this entry point so behaviour is identical across binaries.
* ``read_stdout(...)`` — small helper that reads + truncates the
  captured output for inclusion in the agent-facing summary.
* ``host_of(url)`` — same canonicalisation as the rate limiter so
  stats line up across the two layers.

Truncation cap is ``MAX_AGENT_TEXT_BYTES`` (4 KB) — anything bigger
spills to disk and only the path is returned.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.core.logging import get_logger
from network_pipeline.core.rate_limit import host_of  # re-exported

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellResult, ShellRunner

log = get_logger("tools.web")

MAX_AGENT_TEXT_BYTES = 4 * 1024


def truncate(text: str, cap: int = MAX_AGENT_TEXT_BYTES) -> str:
    """Cap a string at ``cap`` UTF-8 bytes."""
    if len(text.encode("utf-8")) <= cap:
        return text
    return text.encode("utf-8")[:cap].decode("utf-8", errors="ignore") + "\n…[truncated]"


def read_stdout(res: "ShellResult", max_bytes: int = 64 * 1024) -> str:
    """Read up to ``max_bytes`` of a ShellResult's captured stdout."""
    if not res.stdout_path.exists():
        return ""
    try:
        with open(res.stdout_path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:  # pragma: no cover - defensive
        return ""


def run_and_summarise(
    runner: "ShellRunner",
    binary: str,
    argv: list[str],
    *,
    target: str,
    targets: list[str] | None = None,
    timeout_s: int = 600,
    agent: str = "scanner",
    objective_id: str = "",
    summary_lines: int = 30,
) -> str:
    """Generic shell-runner caller for a one-shot text-summarising tool.

    Returns a string of the form::

        <binary> against <target>: <return-code summary>
        <first N lines of stdout>
        full output: <abs path>
    """
    res = runner.run(
        binary, argv,
        targets=targets if targets is not None else [target],
        timeout_s=timeout_s,
        agent=agent,
        objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[{binary} skipped] {res.error}"
    raw = read_stdout(res)
    lines = [l for l in raw.splitlines() if l.strip()]
    head = "\n".join(lines[:summary_lines])
    summary = (
        f"{binary} against {target}: rc={res.returncode}, "
        f"{len(lines)} non-empty stdout lines, dur={res.duration_s:.1f}s\n"
        f"{head}\n"
        f"full output: {res.stdout_path}"
    )
    return truncate(summary)


__all__ = [
    "MAX_AGENT_TEXT_BYTES",
    "host_of",
    "read_stdout",
    "run_and_summarise",
    "truncate",
]
