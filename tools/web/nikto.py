"""nikto wrapper — server misconfig + outdated software scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_nikto(
    runner: "ShellRunner",
    target: str,
    *,
    tuning: str = "1234567890b",  # all default checks except DoS
    agent: str = "scanner",
    objective_id: str = "",
) -> str:
    """Run nikto against ``target``.

    Tuning string excludes DoS-class checks by default — those are
    blocked by the argv guard anyway when RoE prohibits DoS.
    """
    out_path = (
        runner._workspace / "tool_io" / agent
        / f"nikto_{objective_id or 'noobj'}.txt"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        "-h", target,
        "-Tuning", tuning,
        "-Format", "txt",
        "-o", str(out_path),
        "-ask", "no",
        "-nointeractive",
    ]
    return run_and_summarise(
        runner, "nikto", argv,
        target=target, timeout_s=1200, agent=agent, objective_id=objective_id,
        summary_lines=25,
    )
