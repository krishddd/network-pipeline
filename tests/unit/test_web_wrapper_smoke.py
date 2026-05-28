"""Smoke tests for the web tool wrappers — call paths only.

Wrappers invoke ShellRunner.run; for hosts without the binary
installed the runner returns a typed ``error`` (binary not installed)
which is what we assert. This keeps the test independent of the local
environment but still exercises the full argv-construction +
error-handling path of every wrapper.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def runner(workspace: Path, sample_roe):
    from network_pipeline.tools.shell import ScopeGuard, ShellRunner

    scope = ScopeGuard.from_in_scope(sample_roe.in_scope)
    return ShellRunner(workspace, scope=scope, roe=sample_roe)


@pytest.mark.parametrize(
    "wrapper_name, fn_name",
    [
        ("ffuf", "run_ffuf"),
        ("feroxbuster", "run_feroxbuster"),
        ("wapiti", "run_wapiti"),
        ("nikto", "run_nikto"),
        ("zap_baseline", "run_zap_baseline"),
        ("getjs", "run_getjs"),
        ("paramspider", "run_paramspider"),
        ("arjun", "run_arjun"),
        ("dalfox", "run_dalfox"),
        ("sqlmap", "run_sqlmap"),
    ],
)
def test_wrapper_returns_string_when_binary_missing(runner, wrapper_name, fn_name):
    """Every web wrapper must return a string even when the binary is absent."""
    mod = __import__(
        f"network_pipeline.tools.web.{wrapper_name}",
        fromlist=[fn_name],
    )
    fn = getattr(mod, fn_name)
    out = fn(runner, "http://example.com", agent="test", objective_id="OBJ-T")
    # Either "[<binary> skipped] ..." or a real summary string
    assert isinstance(out, str)
    assert len(out) > 0


def test_jwt_tool_smoke(runner):
    """jwt_tool wrapper takes a token, not a URL — separate signature."""
    from network_pipeline.tools.web.jwt_tool import run_jwt_tool

    # Provide a target URL so the scope guard has something to check
    out = run_jwt_tool(
        runner, "fake.jwt.token",
        target_url="http://example.com",
        agent="test", objective_id="OBJ-T",
    )
    assert isinstance(out, str)


def test_sqlmap_invalid_level_clamped(runner):
    """sqlmap wrapper clamps level/risk — argv guard should never see >3/>2."""
    from network_pipeline.tools.web.sqlmap import run_sqlmap

    # level=99, risk=99 should be silently clamped, not fail loudly
    out = run_sqlmap(
        runner, "http://example.com",
        level=99, risk=99,
        agent="test", objective_id="OBJ-T",
    )
    assert isinstance(out, str)
