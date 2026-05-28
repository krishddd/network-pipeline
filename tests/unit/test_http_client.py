"""Unit tests for tools/runtime.py HTTPClient.

Uses respx to mock httpx without real network calls.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

try:
    import respx
    HAS_RESPX = True
except ImportError:
    HAS_RESPX = False

from network_pipeline.tools.runtime import HTTPClient, ScopeGuard

pytestmark = pytest.mark.asyncio


@pytest.fixture
def scope():
    guard = ScopeGuard.__new__(ScopeGuard)
    guard.domains = ("example.com",)
    guard.networks = ()
    guard.raw_targets = ("http://example.com/",)
    return guard


@pytest.fixture
def tmp_workspace(tmp_path: Path) -> Path:
    return tmp_path


@pytest.mark.skipif(not HAS_RESPX, reason="respx not installed")
async def test_get_in_scope(scope, tmp_workspace):
    async with respx.mock:
        respx.get("http://example.com/test").mock(return_value=httpx.Response(200, text="hello"))
        client = HTTPClient(scope=scope, workspace=tmp_workspace)
        resp = await client.get("http://example.com/test")
        assert resp is not None
        assert resp.status_code == 200
        await client.aclose()


@pytest.mark.skipif(not HAS_RESPX, reason="respx not installed")
async def test_get_out_of_scope(scope, tmp_workspace):
    client = HTTPClient(scope=scope, workspace=tmp_workspace)
    resp = await client.get("http://other.com/test")
    assert resp is None
    await client.aclose()


@pytest.mark.skipif(not HAS_RESPX, reason="respx not installed")
async def test_evidence_capture(scope, tmp_workspace):
    async with respx.mock:
        respx.get("http://example.com/evidence").mock(
            return_value=httpx.Response(200, text="evidence test")
        )
        chain_mock = MagicMock()
        chain_mock.add_sidecar_leaf = MagicMock()

        client = HTTPClient(scope=scope, workspace=tmp_workspace, evidence_chain=chain_mock)
        resp = await client.get("http://example.com/evidence", agent="test_agent")
        assert resp is not None
        # tool_io dir should have been created
        assert (tmp_workspace / "tool_io").exists()
        await client.aclose()


@pytest.mark.skipif(not HAS_RESPX, reason="respx not installed")
async def test_context_manager(scope, tmp_workspace):
    async with respx.mock:
        respx.get("http://example.com/cm").mock(return_value=httpx.Response(204))
        async with HTTPClient(scope=scope, workspace=tmp_workspace) as client:
            resp = await client.get("http://example.com/cm")
            assert resp.status_code == 204


async def test_scope_guard_allows():
    g = ScopeGuard(domains=("example.com",), networks=(), raw_targets=())
    assert g.allows("http://example.com/path")
    assert g.allows("sub.example.com")
    assert not g.allows("http://other.com/")


async def test_scope_guard_cidr():
    import ipaddress
    g = ScopeGuard(
        domains=(),
        networks=(ipaddress.ip_network("10.0.0.0/24"),),
        raw_targets=(),
    )
    assert g.allows("10.0.0.1")
    assert not g.allows("10.0.1.1")


async def test_cookie_snapshot_restore(scope, tmp_workspace):
    client = HTTPClient(scope=scope, workspace=tmp_workspace)
    client._client.cookies.set("session", "abc123")
    snap = client.snapshot_cookies()
    assert "session" in snap
    client._client.cookies.clear()
    client.restore_cookies(snap)
    assert client._client.cookies.get("session") == "abc123"
    await client.aclose()
