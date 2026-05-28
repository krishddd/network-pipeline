"""Module-level configuration helpers and workspace validation.

The most important job here is enforcing the WSL ext4 / DrvFs guard the
plan calls out: ``filelock`` on `/mnt/c` is silently broken under
concurrency, so we refuse to use a workspace that lives there unless the
user explicitly opts in.
"""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path


class WorkspaceError(RuntimeError):
    """Raised when the workspace path is invalid or unsafe."""


def validate_workspace(path: Path) -> Path:
    """Return an absolute workspace path or raise WorkspaceError.

    Refuses paths under ``/mnt/`` (WSL DrvFs) and paths on native Windows
    unless the corresponding override env var is set.
    """
    abs_path = path.expanduser().resolve()

    # DrvFs check — flock() on the Windows mount is broken under concurrency.
    if abs_path.parts[:2] == ("/", "mnt") or str(abs_path).lower().startswith("/mnt/"):
        if os.environ.get("NETWORK_PIPELINE_ALLOW_DRVFS_WORKSPACE") != "1":
            raise WorkspaceError(
                f"Workspace {abs_path} sits under /mnt/ (WSL DrvFs). "
                "filelock cannot guarantee mutual exclusion on this filesystem "
                "and the JSON KG can corrupt under concurrent writes. "
                "Use a path inside your WSL ext4 home (e.g. ~/network_pipeline_workspace), "
                "or set NETWORK_PIPELINE_ALLOW_DRVFS_WORKSPACE=1 to override."
            )

    return abs_path


def assert_supported_platform() -> None:
    """Warn (don't block) when running on native Windows.

    The legacy pipeline shelled out to Linux-only binaries (nmap, nuclei,
    masscan, sqlmap) whose Windows builds have argv + log-format quirks
    that broke the parsers — so the gate hard-failed. After the
    Phase A–G pure-Python rewrite, every scanner is httpx + asyncio +
    cryptography and runs natively on Windows. The hard block is
    therefore obsolete; we keep the env-var as a *strict* opt-out for
    sites that still want the WSL-only invariant.

    NETWORK_PIPELINE_REQUIRE_LINUX=1 → restore the hard block.
    NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS=1 (or unset) → allow Windows.
    """
    if platform.system() == "Windows":
        if os.environ.get("NETWORK_PIPELINE_REQUIRE_LINUX") == "1":
            print(
                "[network_pipeline] NETWORK_PIPELINE_REQUIRE_LINUX=1 set; "
                "refusing to start on native Windows.",
                file=sys.stderr,
            )
            sys.exit(2)
        # Soft-warn once so operators know the platform is detected; the
        # pure-Python rewrite handles Windows fine, but a couple of
        # legacy binary tools (sqlmap subprocess) still expect a POSIX
        # process model.
        if os.environ.get("NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS") != "1":
            print(
                "[network_pipeline] Native Windows detected — pure-Python "
                "scanners run fine; sqlmap_dispatch needs `python -m sqlmap` "
                "in PATH and may differ in flag handling. To silence this "
                "notice, set NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS=1.",
                file=sys.stderr,
            )


def workspace_layout(root: Path) -> dict[str, Path]:
    """Standard subdirectory layout for one engagement workspace."""
    return {
        "root": root,
        "plan": root / "plan",
        "findings": root / "findings",
        "tool_io": root / "tool_io",
        "state_snapshots": root / "state_snapshots",
        "kg": root / "kg.json",
        "findings_jsonl": root / "findings.jsonl",
        "agent_traces": root / "agent_traces.log",
        "pipeline_log": root / "pipeline.log",
    }


def init_workspace(root: Path) -> dict[str, Path]:
    """Create the standard subdirectories under ``root`` and return the layout."""
    layout = workspace_layout(root)
    for key in ("root", "plan", "findings", "tool_io", "state_snapshots"):
        layout[key].mkdir(parents=True, exist_ok=True)
    return layout
