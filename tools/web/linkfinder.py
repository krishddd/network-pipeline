"""LinkFinder wrapper — extract endpoint paths from a JS file or URL.

LinkFinder ships as a Python script; we invoke it via ``linkfinder``
when packaged or via ``python -m linkfinder`` if not. The shell layer
expects a single binary name on PATH — operators usually create a tiny
wrapper script at ``/usr/local/bin/linkfinder``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_linkfinder(
    runner: "ShellRunner",
    target_url: str,
    *,
    agent: str = "recon",
    objective_id: str = "",
) -> str:
    """Mine ``target_url`` (typically a JS file) for endpoints."""
    argv = ["-i", target_url, "-o", "cli"]
    return run_and_summarise(
        runner, "linkfinder", argv,
        target=target_url, timeout_s=120,
        agent=agent, objective_id=objective_id,
        summary_lines=40,
    )
