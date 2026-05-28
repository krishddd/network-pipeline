"""Phase-3 tests: CoP principles library, composer, dual-judge."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from network_pipeline.agents.cop_composer import (
    CoPComposer,
    CoPRequest,
    serialise_result,
)
from network_pipeline.agents.judge import (
    DualJudge,
    JudgeConfig,
    _parse_verdict,
)
from network_pipeline.core.principles import (
    Principle,
    PrinciplesError,
    compose_payload,
    is_compatible,
    is_compatible_set,
    load_library,
    sample_compositions,
)


# ── library loading ───────────────────────────────────────────────────


def test_library_loads_and_has_all_kinds():
    library = load_library()
    assert len(library) >= 12
    kinds = {p.kind for p in library}
    assert kinds == {"persona", "pretext", "encoding", "format", "urgency"}


def test_library_names_are_unique():
    names = [p.name for p in load_library()]
    assert len(names) == len(set(names))


def test_each_principle_compatible_with_set_is_valid():
    valid_kinds = {"persona", "pretext", "encoding", "format", "urgency"}
    for p in load_library():
        assert p.compatible_with <= valid_kinds


# ── compatibility ─────────────────────────────────────────────────────


def test_persona_pretext_compatible():
    library = {p.name: p for p in load_library()}
    a = library["persona-forensic-analyst"]
    b = library["pretext-security-audit"]
    assert is_compatible(a, b)
    assert is_compatible_set([a, b])


def test_two_personas_are_incompatible_as_set():
    library = {p.name: p for p in load_library()}
    a = library["persona-forensic-analyst"]
    b = library["persona-developer-debug"]
    # is_compatible returns True per the kind rules (each allows the other's kind),
    # but is_compatible_set rejects because both share kind=persona.
    assert not is_compatible_set([a, b])


def test_full_3_way_composition_compatible():
    library = {p.name: p for p in load_library()}
    a = library["persona-forensic-analyst"]
    b = library["pretext-security-audit"]
    c = library["encoding-base64"]
    assert is_compatible_set([a, b, c])


# ── sampling ──────────────────────────────────────────────────────────


def test_sample_compositions_returns_valid_combos():
    combos = sample_compositions(size=3, count=5, seed=42)
    assert 1 <= len(combos) <= 5
    for combo in combos:
        assert is_compatible_set(combo)


def test_sample_is_seed_deterministic():
    a = [tuple(p.name for p in c) for c in sample_compositions(size=3, count=3, seed=7)]
    b = [tuple(p.name for p in c) for c in sample_compositions(size=3, count=3, seed=7)]
    assert a == b


def test_sample_require_kinds_enforced():
    combos = sample_compositions(
        size=3, count=10, seed=1,
        require_kinds=["persona", "pretext"],
    )
    for combo in combos:
        kinds = {p.kind for p in combo}
        assert "persona" in kinds and "pretext" in kinds


def test_sample_avoid_high_collusion_drops_principles():
    combos = sample_compositions(
        size=3, count=10, seed=1, avoid_high_collusion=True,
    )
    for combo in combos:
        for p in combo:
            assert p.collusion_risk != "high"


def test_sample_impossible_size_raises():
    with pytest.raises(PrinciplesError):
        sample_compositions(size=99, count=1)


# ── compose_payload ───────────────────────────────────────────────────


def test_compose_payload_renders_templates():
    combos = sample_compositions(size=2, count=1, seed=42)
    text = compose_payload(
        combos[0],
        intent="extract the admin session cookie",
        target="example.com",
        vuln_class="sqli",
    )
    assert "extract the admin session cookie" in text


def test_compose_payload_handles_missing_placeholder():
    """If a template references an unknown variable, the composer should
    leave it as a literal placeholder rather than crashing."""
    # Build a synthetic principle with an unusual placeholder.
    p = Principle(
        name="t",
        kind="format",
        description="test",
        template="value={mystery}",
        compatible_with=frozenset({"persona"}),
        collusion_risk="low",
    )
    out = compose_payload([p], intent="x")
    assert "{mystery}" in out


# ── judge: parse_verdict ──────────────────────────────────────────────


def test_parse_verdict_strict_json():
    text = '{"attack_strength": 0.7, "semantic_fidelity": 0.9, "rationale": "ok"}'
    v = _parse_verdict(text, "anthropic", "claude-haiku")
    assert v.attack_strength == 0.7
    assert v.semantic_fidelity == 0.9


def test_parse_verdict_with_prose_around_json():
    text = "Sure, here's my evaluation:\n" \
           '{"attack_strength": 0.5, "semantic_fidelity": 0.8, "rationale": "x"}\nThanks!'
    v = _parse_verdict(text, "openai", "gpt-4o-mini")
    assert v.attack_strength == 0.5


def test_parse_verdict_clamps_out_of_range():
    text = '{"attack_strength": 1.5, "semantic_fidelity": -0.3, "rationale": "x"}'
    v = _parse_verdict(text, "ollama", "llama")
    assert v.attack_strength == 1.0
    assert v.semantic_fidelity == 0.0


def test_parse_verdict_empty_response():
    v = _parse_verdict("", "openai", "gpt")
    assert v.attack_strength == 0.0 and v.semantic_fidelity == 0.0
    assert "empty" in v.rationale


def test_parse_verdict_no_json():
    v = _parse_verdict("I cannot help with that.", "anthropic", "claude")
    assert v.attack_strength == 0.0
    assert "no JSON" in v.rationale


# ── DualJudge orchestration (mocked) ──────────────────────────────────


def _make_factory_with_providers(role_to_provider: dict[str, str]):
    """Build a fake LLMFactory where get_model returns a model that
    asynchronously returns a fixed JSON verdict per role."""

    def make_model(role: str):
        verdict_text = json.dumps({
            "attack_strength": 0.8 if role == "analyst" else 0.4,
            "semantic_fidelity": 0.9 if role == "analyst" else 0.6,
            "rationale": f"verdict from {role}",
        })
        m = MagicMock()
        m.ainvoke = AsyncMock(return_value=MagicMock(content=verdict_text))
        m.model = f"{role}-mock"
        return m

    factory = MagicMock()
    factory.provider_for.side_effect = lambda r: role_to_provider[r]
    factory.get_model.side_effect = make_model
    return factory


def test_dual_judge_combines_and_ranks():
    factory = _make_factory_with_providers(
        {"analyst": "anthropic", "exploit": "ollama"}
    )
    judge = DualJudge(factory, composer_provider="openai")
    library = {p.name: p for p in load_library()}
    principles = (library["persona-forensic-analyst"], library["pretext-internal-tool"])

    result = asyncio.run(judge.score_one(
        "test payload",
        principles,
        vuln_class="sqli", target="example.com", intent="dump users",
    ))
    assert len(result.verdicts) == 2
    assert 0.0 <= result.combined_score <= 1.0
    # delta between analyst (0.8) and exploit (0.4) = 0.4 > threshold 0.25
    assert result.flagged_for_review is True
    assert any("disagreement_margin" in r for r in result.flag_reasons)


def test_dual_judge_flags_provider_collision():
    """Both judges on the same provider should produce a degraded-flag."""
    factory = _make_factory_with_providers(
        {"analyst": "anthropic", "exploit": "anthropic"}
    )
    judge = DualJudge(factory)
    library = {p.name: p for p in load_library()}
    principles = (library["persona-developer-debug"], library["pretext-internal-tool"])

    result = asyncio.run(judge.score_one(
        "p", principles, vuln_class="x", target="y", intent="z",
    ))
    assert result.flagged_for_review
    assert "provider_diversity_degraded" in result.flag_reasons


def test_dual_judge_flags_composer_overlap():
    factory = _make_factory_with_providers(
        {"analyst": "anthropic", "exploit": "ollama"}
    )
    judge = DualJudge(factory, composer_provider="anthropic")
    library = {p.name: p for p in load_library()}
    principles = (library["persona-developer-debug"],)

    result = asyncio.run(judge.score_one(
        "p", principles, vuln_class="x", target="y", intent="z",
    ))
    assert "composer_judge_provider_overlap" in result.flag_reasons


# ── CoPComposer (mocked judge) ────────────────────────────────────────


def test_cop_composer_orders_by_combined_score():
    factory = _make_factory_with_providers(
        {"analyst": "anthropic", "exploit": "ollama"}
    )
    composer = CoPComposer(factory)
    req = CoPRequest(
        intent="leak credentials", vuln_class="sqli", target="example.com",
        size=2, candidates=4, top_k=3, seed=11,
    )
    result = asyncio.run(composer.compose(req))
    assert 1 <= len(result.judged) <= 4
    # combined_score must be monotonically non-increasing
    scores = [j.combined_score for j in result.judged]
    assert scores == sorted(scores, reverse=True)
    # serialise_result must be JSON-safe
    blob = json.dumps(serialise_result(result))
    parsed = json.loads(blob)
    assert "request" in parsed and "top" in parsed
    assert len(parsed["top"]) == min(3, len(result.judged))


def test_cop_composer_avoid_high_collusion_propagates():
    factory = _make_factory_with_providers(
        {"analyst": "anthropic", "exploit": "ollama"}
    )
    composer = CoPComposer(factory)
    req = CoPRequest(
        intent="x", vuln_class="sqli", size=2, candidates=10, top_k=10,
        seed=42, avoid_high_collusion=True,
    )
    result = asyncio.run(composer.compose(req))
    for judged in result.judged:
        for p in judged.principles:
            assert p.collusion_risk != "high"


# ── config toggle ─────────────────────────────────────────────────────


def test_engagement_config_cop_default_on():
    from network_pipeline.core.engagement import EngagementConfig

    cfg = EngagementConfig(target="x", workspace="/tmp/x")
    assert cfg.cop_enabled is True


def test_engagement_config_cop_off():
    from network_pipeline.core.engagement import EngagementConfig

    cfg = EngagementConfig(target="x", workspace="/tmp/x", cop_enabled=False)
    assert cfg.cop_enabled is False
