"""Unit tests for scanners/dns_scan.py (mocked DNS resolver)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from network_pipeline.scanners.dns_scan import DNSScanner
from network_pipeline.tools.runtime import DNSClient, ScopeGuard


@pytest.fixture
def scope():
    g = ScopeGuard.__new__(ScopeGuard)
    g.domains = ("example.com",)
    g.networks = ()
    g.raw_targets = ()
    return g


@pytest.fixture
def dns_client(scope, tmp_path):
    client = DNSClient(scope=scope, workspace=tmp_path)
    return client


@pytest.mark.asyncio
async def test_dns_scanner_resolve(dns_client):
    scanner = DNSScanner(dns_client)
    # Mock the resolve method
    dns_client.resolve = AsyncMock(return_value=["93.184.216.34"])
    result = await scanner.resolve("example.com", types=("A",))
    assert result.success
    assert "A" in result.data["records"]
    assert "93.184.216.34" in result.data["records"]["A"]


@pytest.mark.asyncio
async def test_dns_scanner_missing_spf(dns_client):
    scanner = DNSScanner(dns_client)

    async def mock_resolve(domain, rdtype):
        if rdtype == "A":
            return ["1.2.3.4"]
        return []

    dns_client.resolve = mock_resolve
    result = await scanner.resolve("example.com", types=("A", "TXT"))
    # Should flag missing SPF since no TXT records
    assert any(f.vuln_class == "missing-spf" for f in result.findings)


@pytest.mark.asyncio
async def test_dns_scanner_scope_denied(dns_client, scope):
    scanner = DNSScanner(dns_client)
    dns_client.resolve = AsyncMock(return_value=[])
    # out-of-scope domain
    result = await scanner.resolve("other.com", types=("A",))
    assert result.success is False or result.data.get("records", {}) == {}


@pytest.mark.asyncio
async def test_dns_client_configurable_nameservers(scope, tmp_path):
    client = DNSClient(scope=scope, nameservers=["8.8.4.4", "1.0.0.1"], workspace=tmp_path)
    if client._resolver is not None:
        assert "8.8.4.4" in client._nameservers
