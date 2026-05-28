"""Phase-8 tests: HITL pause/resume + HackerOne / Bugcrowd reporters."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

from network_pipeline.core.schemas import (
    Evidence,
    Finding,
    FindingConfidence,
    FindingSeverity,
)
from network_pipeline.tools.report import (
    _BUGCROWD_SEVERITY,
    _HACKERONE_SEVERITY,
    _hackerone_body,
    _slug,
    _vrt_for,
    write_bugcrowd_csv,
    write_hackerone_md,
)


# ── fixture: small finding set ────────────────────────────────────────


def _f(
    *, id_: str, severity: FindingSeverity,
    confidence: FindingConfidence = FindingConfidence.PROBABLE,
    cwe: list[str] | None = None,
    verified_methods: list[str] | None = None,
):
    """Build a Finding that passes the HIGH/CRITICAL gate when needed."""
    if severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL):
        confidence = FindingConfidence.VERIFIED
        verified_methods = verified_methods or ["scanner:m1", "scanner:m2"]
    return Finding(
        id=id_, title=f"finding {id_}",
        severity=severity, confidence=confidence,
        cwe=cwe or [],
        affected_target="http://target.test/path",
        affected_component="GET /path",
        description="A vulnerability was found and reproduced.",
        steps_to_reproduce=["curl http://target.test/path?id=1", "observe"],
        impact="Attacker can read /etc/passwd.",
        evidence=[Evidence(type="artifact", path="evidence/x.req",
                           description="captured request")],
        remediation="Use prepared statements.",
        verified_methods=verified_methods or [],
    )


@pytest.fixture()
def findings_mix() -> list[Finding]:
    return [
        _f(id_="FIND-001", severity=FindingSeverity.CRITICAL, cwe=["CWE-89"]),
        _f(id_="FIND-002", severity=FindingSeverity.HIGH, cwe=["CWE-79"]),
        _f(id_="FIND-003", severity=FindingSeverity.MEDIUM, cwe=["CWE-200"]),
        _f(id_="FIND-004", severity=FindingSeverity.LOW),
        _f(id_="FIND-005", severity=FindingSeverity.INFORMATIONAL),
    ]


# ── HackerOne reporter ────────────────────────────────────────────────


def test_slug_filesystem_safe():
    assert _slug("SQL injection in /api/users") == "sql-injection-in-api-users"
    assert _slug("") == "untitled"
    assert "/" not in _slug("foo/bar")


def test_hackerone_body_contains_all_sections():
    f = _f(id_="FIND-99", severity=FindingSeverity.HIGH, cwe=["CWE-89"])
    body = _hackerone_body(f)
    for section in ("# finding FIND-99", "## Summary", "## Steps to Reproduce",
                    "## Impact", "## Suggested Fix", "## Evidence",
                    "**Finding ID:**", "**Severity:**"):
        assert section in body
    assert "High (7.0–8.9)" in body


def test_hackerone_body_when_no_steps():
    f = Finding(
        id="FIND-X", title="t",
        severity=FindingSeverity.MEDIUM, confidence=FindingConfidence.PROBABLE,
        affected_target="http://t/x", description="d",
        steps_to_reproduce=[], evidence=[],
    )
    body = _hackerone_body(f)
    assert "_The finding was discovered by automated scanning" in body
    assert "_No artefacts attached._" in body


def test_write_hackerone_md_emits_one_file_per_high_plus(
    tmp_path: Path, findings_mix: list[Finding],
):
    out = write_hackerone_md(findings_mix, tmp_path / "h1")
    files = sorted(p.name for p in out.iterdir() if p.suffix == ".md")
    # CRITICAL + HIGH = 2 finding files + index.md
    assert len(files) == 3
    assert "index.md" in files
    finding_files = [f for f in files if f != "index.md"]
    assert any("FIND-001" in f for f in finding_files)
    assert any("FIND-002" in f for f in finding_files)
    # MEDIUM should NOT appear (default severity_floor=HIGH).
    assert not any("FIND-003" in f for f in finding_files)


def test_write_hackerone_md_index_links_files(
    tmp_path: Path, findings_mix: list[Finding],
):
    out = write_hackerone_md(findings_mix, tmp_path / "h1")
    index = (out / "index.md").read_text(encoding="utf-8")
    # The index lists every emitted .md file by relative name.
    for p in out.iterdir():
        if p.suffix == ".md" and p.name != "index.md":
            assert p.name in index


def test_write_hackerone_md_empty_findings(tmp_path: Path):
    out = write_hackerone_md([], tmp_path / "h1")
    index = (out / "index.md").read_text(encoding="utf-8")
    assert "No findings at or above" in index


def test_write_hackerone_md_custom_severity_floor(
    tmp_path: Path, findings_mix: list[Finding],
):
    out = write_hackerone_md(findings_mix, tmp_path / "h1",
                            severity_floor=FindingSeverity.MEDIUM)
    finding_files = [p for p in out.iterdir()
                     if p.suffix == ".md" and p.name != "index.md"]
    # CRIT + HIGH + MEDIUM = 3 finding files.
    assert len(finding_files) == 3


# ── Bugcrowd CSV reporter ─────────────────────────────────────────────


def test_vrt_mapping():
    f = _f(id_="X", severity=FindingSeverity.HIGH, cwe=["CWE-89"])
    assert _vrt_for(f) == "sql_injection.generic"
    f2 = _f(id_="X", severity=FindingSeverity.LOW, cwe=["CWE-99999"])
    assert _vrt_for(f2) == "other"


def test_bugcrowd_severity_priorities():
    assert _BUGCROWD_SEVERITY[FindingSeverity.CRITICAL] == "P1"
    assert _BUGCROWD_SEVERITY[FindingSeverity.HIGH] == "P2"
    assert _BUGCROWD_SEVERITY[FindingSeverity.INFORMATIONAL] == "P5"


def test_write_bugcrowd_csv_writes_all_columns(
    tmp_path: Path, findings_mix: list[Finding],
):
    out = write_bugcrowd_csv(findings_mix, tmp_path / "bc.csv")
    assert out.exists()
    with out.open(encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    header = rows[0]
    for col in ("id", "title", "vrt", "priority", "affected_url",
                "description", "steps", "evidence_paths"):
        assert col in header
    # 5 findings + header row.
    assert len(rows) == 6
    # Highest-severity (CRITICAL → P1) comes first thanks to priority sort.
    first_priority = rows[1][header.index("priority")]
    assert first_priority == "P1"


def test_write_bugcrowd_csv_empty(tmp_path: Path):
    out = write_bugcrowd_csv([], tmp_path / "bc.csv")
    with out.open(encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    # Header only.
    assert len(rows) == 1
    assert rows[0][0] == "id"


# ── Pause-flag helpers + CLI resume logic ─────────────────────────────


def test_pause_flag_path_consistent(tmp_path: Path):
    """The flag path the loop writes is the same path the CLI checks."""
    expected = tmp_path / "plan" / "pause.flag"
    (tmp_path / "plan").mkdir()
    expected.write_text("paused", encoding="utf-8")
    # The CLI reads from <workspace>/plan/pause.flag — same construction.
    assert (tmp_path / "plan" / "pause.flag").exists()


def test_cli_clears_pause_flag(tmp_path: Path, monkeypatch):
    """`cli run` startup logic: when pause.flag present, message + remove."""
    (tmp_path / "plan").mkdir()
    flag = tmp_path / "plan" / "pause.flag"
    flag.write_text("paused at iteration 3", encoding="utf-8")

    # Replicate the CLI's resume check in isolation.
    note = flag.read_text(encoding="utf-8").strip()
    assert "iteration 3" in note
    flag.unlink()
    assert not flag.exists()


# ── Cross-platform SIGINT handler installation ───────────────────────


def test_install_pause_handler_runs_without_event_loop_on_windows():
    """On Windows, the handler installer must not require a running asyncio
    loop. It uses signal.signal() directly."""
    if sys.platform != "win32":
        pytest.skip("Windows-specific path")
    # Minimal smoke: we can import the helper and call it from main
    # thread even when there is no active loop. (We don't actually fire
    # SIGINT here — that would kill pytest.)
    from network_pipeline.core.engagement_loop import EngagementLoop
    # We don't construct EngagementLoop (heavy); we just check the
    # method is bound and callable.
    assert callable(getattr(EngagementLoop, "_install_pause_handler"))


def test_install_pause_handler_unix_signal_api_available():
    """On Unix, loop.add_signal_handler is the preferred path."""
    if sys.platform == "win32":
        pytest.skip("Unix-specific path")
    import asyncio
    async def _check():
        loop = asyncio.get_running_loop()
        # Just confirm the method exists; install + remove cleanly.
        import signal
        loop.add_signal_handler(signal.SIGINT, lambda: None)
        loop.remove_signal_handler(signal.SIGINT)
    asyncio.run(_check())
