"""paramspider wrapper — historical parameter discovery via Wayback."""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import truncate

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_paramspider(
    runner: "ShellRunner",
    domain: str,
    *,
    agent: str = "recon",
    objective_id: str = "",
) -> str:
    """Discover parameters for ``domain`` via the Wayback Machine."""
    out_dir = runner._workspace / "tool_io" / agent / f"paramspider_{objective_id or 'noobj'}"
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        "--domain", domain,
        "--output", str(out_dir / f"{domain}.txt"),
    ]
    res = runner.run(
        "paramspider", argv,
        targets=[domain], timeout_s=300,
        agent=agent, objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[paramspider skipped] {res.error}"
    out_file = out_dir / f"{domain}.txt"
    if not out_file.exists():
        return f"paramspider against {domain}: no output produced"
    lines = out_file.read_text(errors="replace").splitlines()
    summary = (
        f"paramspider against {domain}: {len(lines)} URLs with parameters\n"
        + "\n".join(lines[:30])
        + (f"\n[+{len(lines)-30} more]" if len(lines) > 30 else "")
        + f"\nfull output: {out_file}"
    )
    return truncate(summary)
