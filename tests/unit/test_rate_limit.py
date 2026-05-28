"""Tests for core.rate_limit — token-bucket per (binary, host)."""

from __future__ import annotations

import time


def test_no_rate_set_is_noop():
    from network_pipeline.core.rate_limit import RateLimitRegistry

    reg = RateLimitRegistry()
    assert reg.acquire("nmap", "10.0.0.1") == 0.0


def test_burst_exhausted_then_throttled():
    from network_pipeline.core.rate_limit import RateLimitRegistry

    reg = RateLimitRegistry()
    reg.set_rate("nmap", rps=10.0, burst=2)
    # Burst of 2 — first two calls don't sleep
    assert reg.acquire("nmap", "10.0.0.1") == 0.0
    assert reg.acquire("nmap", "10.0.0.1") == 0.0
    # Third must wait roughly 1/10 s
    t0 = time.monotonic()
    reg.acquire("nmap", "10.0.0.1")
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.05  # generous lower bound for slow CI


def test_different_hosts_have_separate_buckets():
    from network_pipeline.core.rate_limit import RateLimitRegistry

    reg = RateLimitRegistry()
    reg.set_rate("nmap", rps=1.0, burst=1)
    # Two different hosts — neither should sleep
    assert reg.acquire("nmap", "10.0.0.1") == 0.0
    assert reg.acquire("nmap", "10.0.0.2") == 0.0


def test_host_extraction_from_url():
    from network_pipeline.core.rate_limit import host_of

    assert host_of("https://example.com/path") == "example.com"
    assert host_of("http://10.0.0.1:8080/x") == "10.0.0.1"
    assert host_of("example.com:443") == "example.com"
    assert host_of("EXAMPLE.com") == "example.com"


def test_parse_rate_flag():
    import pytest

    from network_pipeline.core.rate_limit import parse_rate_flag

    assert parse_rate_flag("nuclei:0.5") == ("nuclei", 0.5)
    assert parse_rate_flag("nmap:10") == ("nmap", 10.0)
    with pytest.raises(ValueError):
        parse_rate_flag("nmap")
    with pytest.raises(ValueError):
        parse_rate_flag(":1.0")
    with pytest.raises(ValueError):
        parse_rate_flag("nmap:abc")
    with pytest.raises(ValueError):
        parse_rate_flag("nmap:-1")
