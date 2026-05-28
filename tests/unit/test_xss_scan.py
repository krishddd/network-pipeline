"""Unit tests for scanners/xss_scan.py — context-aware canary detection."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from network_pipeline.scanners.xss_scan import XSSScanner, _inject_param


def make_mock_client():
    client = MagicMock()
    return client


@pytest.mark.asyncio
async def test_xss_reflected_html_body():
    """Detect HTML body context reflection."""
    client = MagicMock()

    async def mock_get(url, **kwargs):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        q = qs.get("q", [""])[0]
        # Reflect the payload back in the body
        resp = MagicMock()
        resp.text = f"<html><body>{q}</body></html>"
        return resp

    client.get = mock_get
    scanner = XSSScanner(client)
    result = await scanner.scan("http://example.com/search?q=test", params=["q"])
    # Should have found at least one XSS
    assert any("xss-reflected" in f.vuln_class for f in result.findings)


@pytest.mark.asyncio
async def test_xss_no_reflection():
    """No XSS when payload is not reflected."""
    client = MagicMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.text = "<html><body>safe output</body></html>"
        return resp

    client.get = mock_get
    scanner = XSSScanner(client)
    result = await scanner.scan("http://example.com/search?q=test", params=["q"])
    assert len(result.findings) == 0


def test_inject_param():
    url = "http://example.com/search?q=existing&page=1"
    injected = _inject_param(url, "q", "payload")
    parsed = urlparse(injected)
    qs = parse_qs(parsed.query)
    assert qs["q"] == ["payload"]
    assert qs["page"] == ["1"]


@pytest.mark.asyncio
async def test_xss_no_params_returns_error():
    client = MagicMock()
    scanner = XSSScanner(client)
    result = await scanner.scan("http://example.com/page")
    assert not result.success
    assert "no parameters" in result.error


@pytest.mark.asyncio
async def test_xss_dom_mode_skipped_without_browser():
    """DOM path is skipped when browser=None."""
    client = MagicMock()

    async def mock_get(url, **kwargs):
        resp = MagicMock()
        resp.text = "<html>no reflection</html>"
        return resp

    client.get = mock_get
    scanner = XSSScanner(client, browser=None)
    result = await scanner.scan("http://example.com/page?q=1", params=["q"])
    assert result.data.get("mode") == "reflected-only"
