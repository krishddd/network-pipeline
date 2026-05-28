"""getJS wrapper — extract every JS file referenced by a target.

The output is a deduplicated, sorted list of absolute JS URLs. The
agent typically chains this into LinkFinder to extract endpoints from
those JS files.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import truncate

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_getjs(
    runner: "ShellRunner",
    target: str,
    *,
    agent: str = "recon",
    objective_id: str = "",
) -> str:
    """Pull every JS reference under ``target`` (one URL per line)."""
    argv = ["--url", target, "--complete"]
    res = runner.run(
        "getJS", argv,
        targets=[target],
        timeout_s=180, agent=agent, objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[getJS skipped] {res.error}"
    text = ""
    if res.stdout_path.exists():
        text = res.stdout_path.read_text(errors="replace")
    urls = sorted({l.strip() for l in text.splitlines() if l.strip()})
    summary = (
        f"getJS against {target}: {len(urls)} unique JS URLs\n"
        + "\n".join(urls[:50])
        + (f"\n[+{len(urls)-50} more]" if len(urls) > 50 else "")
        + f"\nfull output: {res.stdout_path}"
    )
    return truncate(summary)
