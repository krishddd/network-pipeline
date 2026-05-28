"""External smoke test — opt-in only, requires internet access.

Skipped in CI by default. Run manually before tagging a release:
  pytest tests/integration/test_external_smoke.py -v -m requires_internet

Target: testphp.vulnweb.com (Acunetix maintained test site).
"""

from __future__ import annotations

import asyncio
import pytest

pytestmark = pytest.mark.requires_internet


def run(coro):
    loop = asyncio.get_event_loop()
    if loop.is_closed():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


TARGET = "http://testphp.vulnweb.com"


@pytest.fixture(scope="module")
def http_client():
    from network_pipeline.tools.runtime import HTTPClient, ScopeGuard
    scope = ScopeGuard.__new__(ScopeGuard)
    scope.domains = ("testphp.vulnweb.com",)
    scope.networks = ()
    scope.raw_targets = (TARGET,)
    client = HTTPClient(scope=scope)
    yield client
    asyncio.get_event_loop().run_until_complete(client.aclose())


def test_subdomain_enum_returns_subdomains(http_client):
    from network_pipeline.tools.runtime import DNSClient, ScopeGuard
    from network_pipeline.scanners.subdomains import SubdomainScanner
    scope = ScopeGuard.__new__(ScopeGuard)
    scope.domains = ("vulnweb.com",)
    scope.networks = ()
    scope.raw_targets = ()
    dns = DNSClient(scope=scope)
    scanner = SubdomainScanner(http_client, dns)
    result = run(scanner.enumerate("vulnweb.com"))
    assert result.data.get("total_found", 0) > 0, "Expected at least 1 subdomain"


def test_content_discovery_finds_paths(http_client):
    from network_pipeline.scanners.content_discovery import ContentScanner
    scanner = ContentScanner(http_client)
    result = run(scanner.discover(TARGET, wordlist="common"))
    assert result.data.get("total_hits", 0) >= 1, "Expected content-discovery hits"


def test_web_audit_finds_issues(http_client):
    from network_pipeline.scanners.web_audit import WebAuditScanner
    scanner = WebAuditScanner(http_client)
    result = run(scanner.audit(TARGET))
    assert len(result.findings) >= 1, "Expected at least one web-audit finding"


def test_sqli_scan_finds_sqli(http_client):
    from network_pipeline.scanners.sqli_scan import SQLiScanner
    scanner = SQLiScanner(http_client)
    result = run(scanner.scan(TARGET + "/listproducts.php", params=["cat"]))
    assert any("sqli" in f.vuln_class for f in result.findings), \
        f"Expected SQLi finding on testphp.vulnweb.com; got: {result.findings}"
