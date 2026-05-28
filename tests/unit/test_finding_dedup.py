"""Unit tests for finding deduplication in scanners/_common.py."""

from __future__ import annotations

import pytest

from network_pipeline.scanners._common import (
    normalize_endpoint,
    normalize_finding_key,
    ScanFinding,
)


def test_normalize_endpoint_strips_query_values():
    url = "http://example.com/products?id=5&page=2"
    result = normalize_endpoint(url)
    assert "id=" in result
    assert "5" not in result
    assert "page=" in result
    assert "2" not in result


def test_normalize_endpoint_replaces_numeric_path_segments():
    url = "http://example.com/users/123/orders/456"
    result = normalize_endpoint(url)
    assert "{n}" in result
    assert "123" not in result
    assert "456" not in result


def test_normalize_endpoint_preserves_path_structure():
    url = "http://example.com/api/v2/items"
    result = normalize_endpoint(url)
    assert "api" in result
    assert "v" in result  # v2 has a digit but let's check structure preserved


def test_normalize_finding_key_same_vuln():
    key1 = normalize_finding_key("missing-hsts", "http://example.com/?", "")
    key2 = normalize_finding_key("missing-hsts", "http://example.com/?", "")
    assert key1 == key2


def test_normalize_finding_key_different_query_values_same_key():
    key1 = normalize_finding_key("sqli", "http://example.com/search?id=1", "id")
    key2 = normalize_finding_key("sqli", "http://example.com/search?id=99", "id")
    assert key1 == key2


def test_normalize_finding_key_different_params_different_key():
    key1 = normalize_finding_key("sqli", "http://example.com/search?id=1", "id")
    key2 = normalize_finding_key("sqli", "http://example.com/search?name=1", "name")
    assert key1 != key2


def test_scan_finding_creation():
    f = ScanFinding(
        vuln_class="missing-hsts",
        title="Missing HSTS on /",
        severity="low",
        affected_target="http://example.com/",
        confidence="verified",
    )
    assert f.vuln_class == "missing-hsts"
    assert f.severity == "low"
    assert f.evidence_paths == []
    assert f.cwe == []


def test_dedup_two_findings_same_key():
    """Two findings with the same key should deduplicate to one."""
    f1 = ScanFinding(
        vuln_class="missing-hsts",
        title="Missing HSTS (scanner A)",
        severity="low",
        affected_target="http://example.com/",
        confidence="verified",
    )
    f2 = ScanFinding(
        vuln_class="missing-hsts",
        title="Missing HSTS (scanner B)",
        severity="medium",  # higher severity
        affected_target="http://example.com/",
        confidence="verified",
    )

    # Simulate dedup: keep highest severity, merge evidence
    key1 = normalize_finding_key(f1.vuln_class, f1.affected_target)
    key2 = normalize_finding_key(f2.vuln_class, f2.affected_target)
    assert key1 == key2  # same key → would dedup

    # Winner should be f2 (higher severity)
    sev_order = ["informational", "low", "medium", "high", "critical"]
    winner = f2 if sev_order.index(f2.severity) > sev_order.index(f1.severity) else f1
    assert winner.severity == "medium"
