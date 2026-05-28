"""sqlmap deep-dive dispatcher — the ONE permitted subprocess in the redesign.

Only invoked when:
  1. sqli_scan.py detected a high-confidence SQLi candidate, AND
  2. sqlmap is pip-installed (importlib.util.find_spec("sqlmap") is not None)

Uses an explicit allowlist of safe sqlmap flags — anything not on the
allowlist is silently dropped. Never allows --os-shell, --os-pwn,
--file-read, --file-write, --reg-read, --eval, or similar.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding
from network_pipeline.core.logging import get_logger

if TYPE_CHECKING:
    pass

log = get_logger("scanners.sqlmap_dispatch")

# Explicit allowlist — only these flags may be passed to sqlmap.
# Anything not in this set is silently dropped.
_ALLOWED_FLAGS: frozenset[str] = frozenset({
    "--batch",
    "--url", "-u",
    "--level",
    "--risk",
    "--dbms",
    "--technique",
    "--output-dir",
    "--timeout",
    "--retries",
    "--threads",
    "--forms",
    "--crawl",
    "--exclude-sysdbs",
    "--no-cast",
    "--string",
    "--not-string",
    "--regexp",
})

# Hard caps on dangerous numeric flags
_FLAG_CAPS = {
    "--level": 3,
    "--risk": 2,
    "--threads": 5,
    "--retries": 3,
    "--crawl": 1,
}

_SQLMAP_TIMEOUT_S = 120


def _is_available() -> bool:
    return importlib.util.find_spec("sqlmap") is not None


def _sanitize_argv(extra_flags: list[str]) -> list[str]:
    """Filter argv to allowed flags only; cap numeric values."""
    out: list[str] = []
    i = 0
    while i < len(extra_flags):
        flag = extra_flags[i]
        # Handle --flag=value form
        if "=" in flag:
            key, val = flag.split("=", 1)
            if key in _ALLOWED_FLAGS:
                cap = _FLAG_CAPS.get(key)
                if cap is not None:
                    try:
                        val = str(min(int(val), cap))
                    except ValueError:
                        pass
                out.append(f"{key}={val}")
        # Handle --flag value form
        elif flag in _ALLOWED_FLAGS:
            out.append(flag)
            if i + 1 < len(extra_flags) and not extra_flags[i + 1].startswith("-"):
                val = extra_flags[i + 1]
                cap = _FLAG_CAPS.get(flag)
                if cap is not None:
                    try:
                        val = str(min(int(val), cap))
                    except ValueError:
                        pass
                out.append(val)
                i += 1
        i += 1
    return out


@register_scanner
class SQLMapDispatcher(Scanner):
    name = "sqlmap_dispatch"
    requires_libs = ("sqlmap",)
    opsec_min = "loud"
    loud_level = "high"

    def __init__(self, workspace: Path | None = None) -> None:
        self._workspace = workspace

    @classmethod
    def is_available(cls) -> bool:
        return _is_available()

    async def dispatch(
        self,
        url: str,
        extra_flags: list[str] | None = None,
    ) -> ScanResult:
        """Run sqlmap against url as a subprocess (the one permitted exception)."""
        if not _is_available():
            return ScanResult(
                scanner=self.name, target=url, success=False,
                error="sqlmap not installed; run: pip install sqlmap",
            )

        out_dir = (self._workspace / "tool_io" / "sqlmap") if self._workspace else Path(".")
        out_dir.mkdir(parents=True, exist_ok=True)

        base_argv = [
            sys.executable, "-m", "sqlmap",
            "-u", url,
            "--batch",
            "--output-dir", str(out_dir),
            "--level=1",
            "--risk=1",
            "--threads=3",
            "--timeout=30",
            "--retries=1",
            "--exclude-sysdbs",
        ]

        safe_extras = _sanitize_argv(extra_flags or [])
        argv = base_argv + safe_extras

        log.info("sqlmap dispatch: %s", " ".join(argv[:8]) + "...")

        try:
            import asyncio
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=_SQLMAP_TIMEOUT_S,
                    shell=False,
                ),
            )
            stdout = result.stdout[:8192]
            stderr = result.stderr[:2048]

            findings = _parse_sqlmap_output(url, stdout)

            return ScanResult(
                scanner=self.name,
                target=url,
                success=result.returncode == 0,
                data={"returncode": result.returncode, "output_dir": str(out_dir)},
                findings=findings,
                raw_text=stdout[:4096],
                error=stderr[:512] if result.returncode != 0 else "",
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner=self.name, target=url, success=False,
                error=f"sqlmap timed out after {_SQLMAP_TIMEOUT_S}s",
            )
        except Exception as e:
            return ScanResult(
                scanner=self.name, target=url, success=False,
                error=str(e),
            )


def _parse_sqlmap_output(url: str, stdout: str) -> list[ScanFinding]:
    """Extract confirmed injection points from sqlmap output."""
    findings: list[ScanFinding] = []
    if "sqlmap identified the following injection point" in stdout.lower():
        findings.append(ScanFinding(
            vuln_class="sqli-confirmed-sqlmap",
            title=f"SQLi confirmed by sqlmap on {url}",
            severity="critical",
            affected_target=url,
            description="sqlmap confirmed exploitable SQL injection.",
            cwe=["CWE-89"],
            mitre=["T1190"],
            remediation="Use parameterised queries / prepared statements. Audit all DB queries.",
            confidence="verified",
        ))
    return findings
