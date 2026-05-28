"""sqlmap wrapper — SQL-injection probing in batch mode.

The argv guard already refuses ``--os-shell`` / ``--os-pwn`` / ``--os-cmd``,
so this wrapper hard-codes ``--batch --level 1 --risk 1`` and never
exposes the dangerous OS-side flags to the agent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_sqlmap(
    runner: "ShellRunner",
    target: str,
    *,
    data: str = "",
    cookie: str = "",
    level: int = 1,
    risk: int = 1,
    agent: str = "exploit",
    objective_id: str = "",
) -> str:
    """Run sqlmap against ``target`` in safe-batch mode.

    ``level`` and ``risk`` are clamped to 3 / 2 respectively — the argv
    guard refuses higher values when the RoE prohibits DoS-class actions.
    """
    out_dir = (
        runner._workspace / "tool_io" / agent
        / f"sqlmap_{objective_id or 'noobj'}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    level = max(1, min(3, int(level)))
    risk = max(1, min(2, int(risk)))
    argv = [
        "-u", target,
        "--batch",
        "--level", str(level),
        "--risk", str(risk),
        "--output-dir", str(out_dir),
        "--disable-coloring",
        "--smart",
    ]
    if data:
        argv.extend(["--data", data])
    if cookie:
        argv.extend(["--cookie", cookie])

    return run_and_summarise(
        runner, "sqlmap", argv,
        target=target, timeout_s=900,
        agent=agent, objective_id=objective_id,
        summary_lines=30,
    )
