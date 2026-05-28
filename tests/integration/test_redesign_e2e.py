"""Integration tests against the vulnerable Flask fixture.

Runs real scanners against a locally-hosted intentionally-vulnerable app.
Does not require internet access. CI-safe.

Run: pytest tests/integration/test_redesign_e2e.py -v
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

# Add fixtures plugin
pytest_plugins = ["network_pipeline.tests.fixtures.vuln_app"]


@pytest.fixture
def http_client(vuln_app_url):
    from network_pipeline.tools.runtime import HTTPClient, ScopeGuard
    from urllib.parse import urlparse
    parsed = urlparse(vuln_app_url)
    host = parsed.hostname
    scope = ScopeGuard.__new__(ScopeGuard)
    scope.domains = ()
    scope.networks = ()
    scope.raw_targets = (vuln_app_url, f"{parsed.scheme}://{parsed.netloc}")
    client = HTTPClient(scope=scope)
    yield client
    asyncio.get_event_loop().run_until_complete(client.aclose())


def run(coro):
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestSQLiScanner:
    def test_detects_error_based_sqli(self, vuln_app_url, http_client):
        from network_pipeline.scanners.sqli_scan import SQLiScanner
        scanner = SQLiScanner(http_client)
        result = run(scanner.scan(vuln_app_url + "/products", params=["id"]))
        sqli_findings = [f for f in result.findings if "sqli" in f.vuln_class]
        assert len(sqli_findings) >= 1, f"Expected SQLi finding, got: {result.findings}"


class TestXSSScanner:
    def test_detects_reflected_xss(self, vuln_app_url, http_client):
        from network_pipeline.scanners.xss_scan import XSSScanner
        scanner = XSSScanner(http_client)
        result = run(scanner.scan(vuln_app_url + "/search", params=["q"]))
        xss_findings = [f for f in result.findings if "xss-reflected" in f.vuln_class]
        assert len(xss_findings) >= 1, f"Expected XSS finding, got: {result.findings}"


class TestWebAuditScanner:
    def test_detects_git_exposure(self, vuln_app_url, http_client):
        from network_pipeline.scanners.web_audit import WebAuditScanner
        scanner = WebAuditScanner(http_client)
        result = run(scanner.audit(vuln_app_url))
        git_findings = [f for f in result.findings if "git" in f.vuln_class]
        assert len(git_findings) >= 1, f"Expected .git finding, got: {result.findings}"

    def test_detects_cors_misconfiguration(self, vuln_app_url, http_client):
        from network_pipeline.scanners.web_audit import WebAuditScanner
        scanner = WebAuditScanner(http_client)
        result = run(scanner.audit(vuln_app_url))
        cors_findings = [f for f in result.findings if "cors" in f.vuln_class]
        assert len(cors_findings) >= 1, f"Expected CORS finding, got: {result.findings}"


class TestHTTPProbeScanner:
    def test_probe_detects_missing_security_headers(self, vuln_app_url, http_client):
        from network_pipeline.scanners.http_probe import HTTPProbeScanner
        scanner = HTTPProbeScanner(http_client)
        result = run(scanner.probe([vuln_app_url + "/"]))
        header_findings = [f for f in result.findings if "security-headers" in f.vuln_class]
        assert len(header_findings) >= 1, f"Expected missing-headers finding, got: {result.findings}"


class TestAuthAuditScanner:
    def test_detects_default_credentials(self, vuln_app_url, http_client):
        from network_pipeline.scanners.auth_audit import AuthAuditScanner
        scanner = AuthAuditScanner(http_client)
        result = run(scanner.audit(vuln_app_url))
        cred_findings = [f for f in result.findings if "default-credentials" in f.vuln_class]
        assert len(cred_findings) >= 1, f"Expected default-creds finding, got: {result.findings}"


@pytest.mark.skipif(
    pytest.importorskip("jwt", reason="pyjwt not installed") is None,
    reason="pyjwt not installed"
)
class TestJWTScanner:
    def test_detects_weak_jwt_secret(self, vuln_app_url, http_client):
        import jwt as pyjwt
        from network_pipeline.scanners.jwt_scan import JWTScanner

        # Get a token from the app
        resp = asyncio.get_event_loop().run_until_complete(
            http_client.post(vuln_app_url + "/login", scanner_tool="test")
        )
        if resp is None:
            pytest.skip("Could not reach /login")
        data = resp.json()
        token = data.get("token", "")
        if not token:
            pytest.skip("No token returned")

        scanner = JWTScanner(http_client)
        result = run(scanner.scan(token, verify_url=vuln_app_url + "/profile"))
        weak_findings = [f for f in result.findings if f.vuln_class == "jwt-weak-secret"]
        assert len(weak_findings) >= 1, f"Expected jwt-weak-secret, got: {result.findings}"
