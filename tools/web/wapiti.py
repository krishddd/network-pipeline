"""wapiti wrapper — broad OWASP Top-10 scanner.

Wapiti is a Python-based scanner. We invoke it via subprocess (the
``wapiti`` console script ends up on PATH after ``pipx install
wapiti3`` or ``apt install wapiti``). XML report goes to the workspace
so the agent can grep it later without bloating the prompt.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


# Sensible default modules — exclude the heavy ones unless the agent
# asks for them. SSRF + XXE + file-include are the big A03/A05/A10 wins.
_DEFAULT_MODULES = "exec,file,sql,xss,xxe,ssrf,redirect,htaccess,backup"


def run_wapiti(
    runner: "ShellRunner",
    target: str,
    *,
    modules: str = _DEFAULT_MODULES,
    depth: int = 2,
    agent: str = "scanner",
    objective_id: str = "",
) -> str:
    out_dir = runner._workspace / "tool_io" / agent / f"wapiti_{objective_id or 'noobj'}"
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        "-u", target,
        "-m", modules,
        "-d", str(depth),
        "-f", "json",
        "-o", str(out_dir / "report.json"),
        "--flush-session",  # don't carry state between runs
        "--scope", "domain",
        "--verify-ssl", "0",
    ]
    return run_and_summarise(
        runner, "wapiti", argv,
        target=target, timeout_s=1800, agent=agent, objective_id=objective_id,
        summary_lines=20,
    )
