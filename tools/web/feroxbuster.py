"""feroxbuster wrapper — recursive content discovery."""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_feroxbuster(
    runner: "ShellRunner",
    target: str,
    *,
    depth: int = 2,
    threads: int = 25,
    agent: str = "scanner",
    objective_id: str = "",
) -> str:
    """Run feroxbuster against ``target`` with sane defaults.

    Capped at depth 2 + 25 threads to keep noise + load down. The
    capability gate hides this tool when ``feroxbuster`` is not
    installed; OPSEC gate strips it at QUIET/SILENT.
    """
    argv = [
        "--url", target,
        "--depth", str(depth),
        "--threads", str(threads),
        "--no-state",
        "--silent",
        "--insecure",
        "--quiet",
    ]
    return run_and_summarise(
        runner, "feroxbuster", argv,
        target=target, timeout_s=900, agent=agent, objective_id=objective_id,
    )
