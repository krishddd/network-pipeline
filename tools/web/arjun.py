"""arjun wrapper — live parameter mining."""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_arjun(
    runner: "ShellRunner",
    target: str,
    *,
    method: str = "GET",
    agent: str = "recon",
    objective_id: str = "",
) -> str:
    """Probe ``target`` for hidden GET/POST parameters via arjun."""
    argv = [
        "-u", target,
        "-m", method,
        "-T", "10",
        "-t", "10",
        "-q",   # quiet
    ]
    return run_and_summarise(
        runner, "arjun", argv,
        target=target, timeout_s=300,
        agent=agent, objective_id=objective_id,
    )
