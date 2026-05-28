"""Unit tests for scanners/port_scan.py (localhost TCP echo server)."""

from __future__ import annotations

import asyncio
import socket

import pytest

from network_pipeline.scanners.port_scan import PortScanner, _parse_port_range
from network_pipeline.tools.runtime import ScopeGuard


def test_parse_port_range_common():
    ports = _parse_port_range("common")
    assert 80 in ports
    assert 443 in ports
    assert len(ports) > 10


def test_parse_port_range_range():
    ports = _parse_port_range("1-5")
    assert ports == [1, 2, 3, 4, 5]


def test_parse_port_range_list():
    ports = _parse_port_range("80,443,8080")
    assert ports == [80, 443, 8080]


@pytest.mark.asyncio
async def test_port_scanner_finds_open_port():
    """Start a local TCP echo server and verify PortScanner detects it."""
    # Find a free port
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]

    server = await asyncio.start_server(
        lambda r, w: w.close(), "127.0.0.1", free_port
    )

    scope = ScopeGuard.__new__(ScopeGuard)
    scope.domains = ()
    scope.networks = ()
    scope.raw_targets = ("127.0.0.1",)

    scanner = PortScanner(scope=scope, timeout=1.0)
    try:
        result = await scanner.scan("127.0.0.1", ports=str(free_port))
        open_ports = result.data.get("open_ports", [])
        assert any(p["port"] == free_port for p in open_ports), \
            f"Expected port {free_port} to be open; got {open_ports}"
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_port_scanner_closed_port():
    """Verify PortScanner reports nothing on a closed port."""
    # Use a very high port that's almost certainly closed
    scope = ScopeGuard.__new__(ScopeGuard)
    scope.domains = ()
    scope.networks = ()
    scope.raw_targets = ("127.0.0.1",)

    scanner = PortScanner(scope=scope, timeout=0.5)
    result = await scanner.scan("127.0.0.1", ports="19999")
    open_ports = result.data.get("open_ports", [])
    assert all(p["port"] != 19999 for p in open_ports)
