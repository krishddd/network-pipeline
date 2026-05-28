"""Phase-2 unit tests: SIRAJ structured reasoning."""

from __future__ import annotations

import json

import pytest

from network_pipeline.core.structured_reasoning import (
    REASONING_CONTRACT_BLOCK,
    SIRAJ_MAX_REASONING_TOKENS,
    SIRAJReasoning,
    annotate_message,
    estimate_reasoning_tokens,
    parse_reasoning_block,
)


# ── parse_reasoning_block ──────────────────────────────────────────────


def _block(payload: dict) -> str:
    return f"```json\n{json.dumps(payload)}\n```\n\n[tool calls follow]"


def test_valid_block_parses():
    payload = {
        "understand": "Enumerate open ports on 10.0.0.5.",
        "prior_failures": "none",
        "strategy_shift": "Start with top-1000 then expand if quiet.",
        "implementation": "port_scan(target='10.0.0.5', ports='top-1000')",
    }
    out = parse_reasoning_block(_block(payload))
    assert out.valid
    assert isinstance(out.reasoning, SIRAJReasoning)
    assert out.reasoning.understand.startswith("Enumerate")
    assert out.reason == "ok"


def test_block_without_language_tag_still_parses():
    payload = {
        "understand": "x", "prior_failures": "y",
        "strategy_shift": "z", "implementation": "w",
    }
    text = f"```\n{json.dumps(payload)}\n```\nnext..."
    assert parse_reasoning_block(text).valid


def test_free_form_prose_is_rejected():
    out = parse_reasoning_block(
        "Let me think about this. I should start by scanning the host..."
    )
    assert not out.valid
    assert "no leading" in out.reason


def test_malformed_json_is_rejected():
    text = "```json\n{not real json}\n```"
    out = parse_reasoning_block(text)
    assert not out.valid
    assert "json decode error" in out.reason


def test_missing_required_field_is_rejected():
    text = "```json\n" + json.dumps({"understand": "x"}) + "\n```"
    out = parse_reasoning_block(text)
    assert not out.valid
    assert "schema mismatch" in out.reason


def test_empty_message_rejected():
    out = parse_reasoning_block("")
    assert not out.valid


# ── estimate_reasoning_tokens ──────────────────────────────────────────


def test_token_estimate_grows_with_text():
    short = estimate_reasoning_tokens("hello")
    long = estimate_reasoning_tokens("hello " * 200)
    assert long > short
    assert short >= 1


def test_empty_returns_zero():
    assert estimate_reasoning_tokens("") == 0


# ── annotate_message ───────────────────────────────────────────────────


def test_annotate_compliant_message():
    payload = {
        "understand": "u", "prior_failures": "p",
        "strategy_shift": "s", "implementation": "i",
    }
    out = annotate_message(_block(payload))
    assert out["reasoning_valid"] is True
    assert out["reasoning_tokens"] > 0
    assert out["reasoning_over_budget"] is False
    assert out["reasoning_diagnosis"] == "ok"


def test_annotate_non_compliant_message():
    out = annotate_message("just talking, no JSON here")
    assert out["reasoning_valid"] is False
    assert out["reasoning_tokens"] == 0  # no block to measure
    assert "no leading" in out["reasoning_diagnosis"]


def test_annotate_over_budget_block():
    payload = {
        "understand": "u " * 800,
        "prior_failures": "p " * 800,
        "strategy_shift": "s " * 800,
        "implementation": "i " * 800,
    }
    out = annotate_message(_block(payload))
    assert out["reasoning_valid"] is True
    assert out["reasoning_tokens"] > SIRAJ_MAX_REASONING_TOKENS
    assert out["reasoning_over_budget"] is True


# ── contract block is appended only when enabled ──────────────────────


def test_contract_block_constant_is_well_formed():
    """The contract block must mention 'json' fencing and all 4 fields."""
    assert "```json" in REASONING_CONTRACT_BLOCK
    for field in ("understand", "prior_failures", "strategy_shift", "implementation"):
        assert field in REASONING_CONTRACT_BLOCK


def test_engagement_config_default_is_on():
    from network_pipeline.core.engagement import EngagementConfig

    cfg = EngagementConfig(target="example.com", workspace="/tmp/x")
    assert cfg.structured_reasoning is True


def test_engagement_config_can_toggle_off():
    from network_pipeline.core.engagement import EngagementConfig

    cfg = EngagementConfig(
        target="example.com",
        workspace="/tmp/x",
        structured_reasoning=False,
    )
    assert cfg.structured_reasoning is False
