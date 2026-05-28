"""Unit tests for scanners/jwt_scan.py — JWT attacks."""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from network_pipeline.scanners.jwt_scan import (
    JWTScanner,
    _craft_jwt,
    _decode_jwt_parts,
    _b64_encode,
)


def _make_jwt(header: dict, payload: dict, secret: str = "secret") -> str:
    """Create a test JWT signed with HS256."""
    try:
        import jwt as pyjwt
        return pyjwt.encode(payload, secret, algorithm=header.get("alg", "HS256"))
    except ImportError:
        # Manual craft if pyjwt not installed
        return _craft_jwt(header, payload, secret.encode())


def test_decode_jwt_parts_valid():
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "user1"})
    header, payload = _decode_jwt_parts(token)
    assert header is not None
    assert payload is not None
    assert header.get("alg") == "HS256"
    assert payload.get("sub") == "user1"


def test_decode_jwt_parts_invalid():
    header, payload = _decode_jwt_parts("not.a.jwt")
    # Should handle gracefully


def test_craft_jwt_alg_none():
    token = _craft_jwt({"alg": "none", "typ": "JWT"}, {"sub": "test"}, None)
    parts = token.split(".")
    assert len(parts) == 3
    assert parts[2] == ""  # no signature


@pytest.mark.asyncio
async def test_jwt_scan_weak_secret():
    """Weak HMAC secret should be detected."""
    try:
        import jwt as pyjwt
    except ImportError:
        pytest.skip("pyjwt not installed")

    client = MagicMock()
    scanner = JWTScanner(client)
    token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "admin"}, "secret")
    result = await scanner.scan(token)
    assert any(f.vuln_class == "jwt-weak-secret" for f in result.findings)


@pytest.mark.asyncio
async def test_jwt_scan_kid_traversal():
    """kid path traversal should be flagged."""
    client = MagicMock()
    scanner = JWTScanner(client)
    token = _craft_jwt(
        {"alg": "HS256", "typ": "JWT", "kid": "../../../dev/null"},
        {"sub": "test"},
        b"key"
    )
    result = await scanner.scan(token)
    assert any(f.vuln_class == "jwt-kid-traversal" for f in result.findings)


@pytest.mark.asyncio
async def test_jwt_scan_rsh_confusion_flagged():
    """RS→HS confusion should be flagged for RSA tokens."""
    client = MagicMock()
    scanner = JWTScanner(client)
    token = _craft_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "test"},
        b"fake-rsa-key"
    )
    result = await scanner.scan(token)
    assert any(f.vuln_class == "jwt-rs-hs-confusion" for f in result.findings)
