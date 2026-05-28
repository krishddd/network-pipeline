"""ZAP baseline wrapper — passive OWASP triage scan.

Invokes ``zap-baseline.py`` (ships with the OWASP ZAP package) which
runs the spider + passive scan in headless mode. Output goes to a JSON
report in the workspace.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_zap_baseline(
    runner: "ShellRunner",
    target: str,
    *,
    minutes: int = 5,
    agent: str = "scanner",
    objective_id: str = "",
) -> str:
    """Run a ZAP baseline scan against ``target`` capped at N minutes."""
    out_path = (
        runner._workspace / "tool_io" / agent
        / f"zap_baseline_{objective_id or 'noobj'}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        "-t", target,
        "-J", str(out_path),
        "-m", str(minutes),
        "-I",  # don't return non-zero on warnings
    ]
    return run_and_summarise(
        runner, "zap-baseline.py", argv,
        target=target, timeout_s=minutes * 60 + 120,
        agent=agent, objective_id=objective_id,
        summary_lines=20,
    )
