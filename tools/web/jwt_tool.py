"""jwt_tool wrapper — JWT alg / kid / none confusion attacks.

Operates on a captured token (typically pulled from an AuthState by
the auth_replay tool) and reports whether any standard forgery
technique succeeds. Outputs go to a text file under tool_io.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from network_pipeline.tools.web._common import run_and_summarise

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner


def run_jwt_tool(
    runner: "ShellRunner",
    token: str,
    *,
    target_url: str = "",
    mode: str = "scan",
    agent: str = "exploit",
    objective_id: str = "",
) -> str:
    """Run jwt_tool against a captured token.

    ``mode`` ∈ {"scan", "tamper", "playbook"}. The default is the
    full vulnerability scan (alg=none, weak HMAC, kid traversal,
    alg confusion). Argv guard refuses anything off-list.
    """
    if mode not in ("scan", "tamper", "playbook"):
        return f"[jwt_tool refused] unknown mode {mode!r}"
    argv: list[str] = [token]
    if mode == "scan":
        argv.append("-M")
        argv.append("at")  # all tests
    elif mode == "playbook":
        argv.extend(["-pb"])  # built-in attack playbook
    if target_url:
        argv.extend(["-t", target_url])
    return run_and_summarise(
        runner, "jwt_tool", argv,
        target=target_url or "(no-target)",
        targets=[target_url] if target_url else [],
        timeout_s=180,
        agent=agent, objective_id=objective_id,
        summary_lines=40,
    )
