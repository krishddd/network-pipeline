"""Shared pytest fixtures for the network_pipeline test suite.

Pure-python fixtures — none of these require Ollama, langchain, or
network tools to be installed. Tests that DO need those dependencies
are marked ``requires_juice_shop`` / ``requires_wsl`` / ``slow`` and
skipped by default in CI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# Make the network_pipeline package importable when pytest is invoked
# from anywhere under the Security_module root.
_THIS = Path(__file__).resolve()
_PKG_ROOT = _THIS.parents[2]  # Security_module/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))


def pytest_configure(config: pytest.Config) -> None:
    """Register markers used across the suite."""
    for marker, desc in [
        ("requires_juice_shop", "needs a juice-shop container at localhost:3000"),
        ("requires_wsl", "needs WSL2 + native Linux binaries"),
        ("slow", "slow integration tests"),
    ]:
        config.addinivalue_line("markers", f"{marker}: {desc}")


# ── workspace fixture ─────────────────────────────────────────────────


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """Initialised engagement workspace at a tmp path."""
    ws = tmp_path / "engagement"
    (ws / "plan").mkdir(parents=True, exist_ok=True)
    (ws / "tool_io").mkdir(parents=True, exist_ok=True)
    return ws


# ── RoE / OPPLAN fixtures ─────────────────────────────────────────────


@pytest.fixture()
def sample_roe():
    """A minimal RoE with one normal + one paranoid in_scope entry."""
    from network_pipeline.core.schemas import RoE, ScopeEntry

    return RoE(
        engagement_name="test-engagement",
        in_scope=[
            ScopeEntry(target="example.com", type="domain", mode="normal"),
            ScopeEntry(target="paranoid.example.com", type="domain", mode="paranoid"),
            ScopeEntry(target="10.0.0.0/24", type="cidr", mode="normal"),
        ],
        prohibited_actions=[
            "Denial of Service (DoS/DDoS) against production",
            "Modification or deletion of production data",
        ],
    )


# ── env hygiene ───────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Make sure rate-limit registries don't leak across tests."""
    from network_pipeline.core.rate_limit import GLOBAL_RATE_LIMITS

    GLOBAL_RATE_LIMITS.reset()
    yield
    GLOBAL_RATE_LIMITS.reset()


@pytest.fixture(autouse=True)
def _reset_seed():
    """Forget any seed set by a previous test."""
    from network_pipeline.core import seed as seed_mod

    seed_mod._CURRENT_SEED = None
    # PYTHONHASHSEED set by previous test should not bleed
    os.environ.pop("PYTHONHASHSEED", None)
    yield
    seed_mod._CURRENT_SEED = None
    os.environ.pop("PYTHONHASHSEED", None)
