"""Unit tests for tools/request_guard.py."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock


def _make_roe(prohibited: list[str] = (), in_scope: list = ()):
    roe = MagicMock()
    roe.prohibited_actions = list(prohibited)
    roe.in_scope = list(in_scope)
    return roe


from network_pipeline.tools.request_guard import (
    check_request,
    is_paranoid_target,
    is_scanner_blocked_paranoid,
)


def test_check_request_no_roe_allows_all():
    assert check_request("GET", "http://example.com/test", None, None) is None


def test_check_request_blocks_file_scheme():
    result = check_request("GET", "file:///etc/passwd", None, None)
    assert result is not None
    assert "blocked" in result.lower()


def test_check_request_modification_blocked():
    roe = _make_roe(prohibited=["No modification of production data"])
    result = check_request("POST", "http://example.com/admin/users", None, roe)
    assert result is not None


def test_check_request_no_violation():
    roe = _make_roe(prohibited=["No Denial of Service"])
    result = check_request("GET", "http://example.com/api/data", None, roe)
    assert result is None


def test_is_paranoid_target_none_roe():
    assert not is_paranoid_target("example.com", None)


def test_is_paranoid_target_with_normal_entry():
    entry = MagicMock()
    entry.target = "example.com"
    entry.type = "domain"
    entry.mode = "normal"
    roe = _make_roe()
    roe.in_scope = [entry]
    assert not is_paranoid_target("example.com", roe)


def test_is_paranoid_target_with_paranoid_entry():
    entry = MagicMock()
    entry.target = "paranoid.example.com"
    entry.type = "domain"
    entry.mode = "paranoid"
    roe = _make_roe()
    roe.in_scope = [entry]
    assert is_paranoid_target("paranoid.example.com", roe)


def test_scanner_blocked_paranoid():
    entry = MagicMock()
    entry.target = "target.example.com"
    entry.type = "domain"
    entry.mode = "paranoid"
    roe = _make_roe()
    roe.in_scope = [entry]
    assert is_scanner_blocked_paranoid("ContentScanner", "target.example.com", roe)
    assert not is_scanner_blocked_paranoid("DNSScanner", "target.example.com", roe)
