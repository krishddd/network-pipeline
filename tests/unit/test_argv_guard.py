"""Tests for core.argv_guard — argv vs RoE checks + paranoid override."""

from __future__ import annotations


def test_no_roe_means_permitted():
    from network_pipeline.core.argv_guard import check_argv

    assert check_argv("nmap", ["-sV", "10.0.0.1"], roe=None) is None


def test_dos_argv_refused_when_dos_prohibited(sample_roe):
    from network_pipeline.core.argv_guard import check_argv

    reason = check_argv(
        "nmap", ["-T5", "--max-rate=10000", "example.com"],
        roe=sample_roe, targets=["example.com"],
    )
    assert reason is not None
    assert "denial of service" in reason.lower()


def test_innocent_nmap_argv_permitted(sample_roe):
    from network_pipeline.core.argv_guard import check_argv

    assert (
        check_argv(
            "nmap", ["-sV", "-p", "1-100", "example.com"],
            roe=sample_roe, targets=["example.com"],
        )
        is None
    )


def test_sqlmap_os_shell_blocked(sample_roe):
    from network_pipeline.core.argv_guard import check_argv

    reason = check_argv(
        "sqlmap", ["-u", "https://example.com", "--os-shell"],
        roe=sample_roe, targets=["https://example.com"],
    )
    assert reason is not None


def test_paranoid_target_blocks_offensive_binary(sample_roe):
    from network_pipeline.core.argv_guard import check_argv

    reason = check_argv(
        "nuclei", ["-u", "https://paranoid.example.com"],
        roe=sample_roe, targets=["https://paranoid.example.com"],
    )
    assert reason is not None
    assert "paranoid" in reason.lower()


def test_paranoid_target_allows_passive_binary(sample_roe):
    from network_pipeline.core.argv_guard import check_argv

    # curl/dig/whois are not in the paranoid block-list
    assert (
        check_argv(
            "curl", ["https://paranoid.example.com"],
            roe=sample_roe, targets=["https://paranoid.example.com"],
        )
        is None
    )


def test_normal_target_unaffected_by_paranoid_flag(sample_roe):
    from network_pipeline.core.argv_guard import check_argv

    # Same nuclei call against the NORMAL example.com is fine
    assert (
        check_argv(
            "nuclei", ["-u", "https://example.com"],
            roe=sample_roe, targets=["https://example.com"],
        )
        is None
    )
