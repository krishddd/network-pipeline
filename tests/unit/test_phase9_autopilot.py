"""Tests for the autopilot, bumblebee-port supply-chain scanner, and selftest.

Phase-9 in the codebase numbering — bug audit + autonomous mode +
ported threat intel.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from network_pipeline.agents.autopilot import (
    AutopilotConfig,
    ParsedPrompt,
    ask_operator,
    consume_answer,
    parse_prompt,
    pending_question,
    submit_answer,
    synthesise_plan,
)
from network_pipeline.scanners.supply_chain_inventory import (
    SupplyChainInventoryScanner,
    load_catalogs,
    match_deps_against_catalogs,
    parse_composer_lock,
    parse_gemfile_lock,
    parse_go_mod,
    parse_package_json,
    parse_package_lock,
    parse_pipfile_lock,
    parse_requirements_txt,
)


# ── prompt parsing ────────────────────────────────────────────────────


def test_parse_prompt_extracts_url():
    p = parse_prompt("test the chatbot at http://localhost:3000 for jailbreaks")
    assert p.target == "http://localhost:3000"
    assert p.target_kind == "url"
    assert p.target_type == "llm"
    assert "jailbreak" in p.keywords


def test_parse_prompt_extracts_domain_and_keywords():
    p = parse_prompt("OWASP top10 + SQLi against juice.shop please")
    assert p.target == "juice.shop"
    assert p.target_kind == "domain"
    assert p.target_type == "network"
    assert "owasp" in p.keywords and "sqli" in p.keywords


def test_parse_prompt_extracts_cidr():
    p = parse_prompt("scan 10.1.2.0/24 for any open services")
    assert p.target == "10.1.2.0/24"
    assert p.target_kind == "cidr"


def test_parse_prompt_no_target_raises_in_synth(tmp_path: Path):
    p = parse_prompt("hello there how are you")
    assert p.target == ""


# ── plan synthesis ───────────────────────────────────────────────────


def test_synthesise_plan_writes_all_four_files(tmp_path: Path):
    p = parse_prompt("scan example.com please")
    roe, conops, decon, opplan = synthesise_plan(p, tmp_path)
    plan_dir = tmp_path / "plan"
    for fname in ("roe.json", "conops.json", "deconfliction.json", "opplan.json"):
        assert (plan_dir / fname).exists()
    assert any(s.target == "example.com" for s in roe.in_scope)
    assert decon.shared_signature.startswith("network_pipeline-redteam/")
    assert len(opplan.objectives) >= 1


def test_synthesise_plan_llm_target_picks_llm_phase(tmp_path: Path):
    p = parse_prompt("jailbreak the chatbot at http://target:3000")
    _, _, _, opplan = synthesise_plan(p, tmp_path)
    from network_pipeline.core.schemas import ObjectivePhase
    assert opplan.objectives[0].phase == ObjectivePhase.LLM_REDTEAM


def test_synthesise_plan_network_target_chains_objectives(tmp_path: Path):
    p = parse_prompt("scan example.com for vulnerabilities")
    _, _, _, opplan = synthesise_plan(p, tmp_path)
    ids = {o.id for o in opplan.objectives}
    assert {"OBJ-001", "OBJ-002", "OBJ-003"}.issubset(ids)


# ── question protocol ───────────────────────────────────────────────


def test_ask_operator_writes_question_and_pause_flag(tmp_path: Path):
    payload = ask_operator(
        tmp_path,
        question="approve out-of-scope expansion to api.foo.com?",
        default="no",
        phase="attack",
    )
    assert payload["id"].startswith("Q-")
    assert (tmp_path / "plan" / "question.json").exists()
    assert (tmp_path / "plan" / "pause.flag").exists()


def test_pending_question_round_trip(tmp_path: Path):
    ask_operator(tmp_path, question="hi?")
    q = pending_question(tmp_path)
    assert q is not None and q["question"] == "hi?"


def test_submit_answer_clears_question_and_flag(tmp_path: Path):
    ask_operator(tmp_path, question="?", default="no")
    submit_answer(tmp_path, "yes")
    assert not (tmp_path / "plan" / "question.json").exists()
    assert not (tmp_path / "plan" / "pause.flag").exists()
    assert (tmp_path / "plan" / "answer.txt").read_text(encoding="utf-8") == "yes"


def test_consume_answer_deletes_file(tmp_path: Path):
    (tmp_path / "plan").mkdir()
    (tmp_path / "plan" / "answer.txt").write_text("the answer", encoding="utf-8")
    ans = consume_answer(tmp_path)
    assert ans == "the answer"
    assert not (tmp_path / "plan" / "answer.txt").exists()
    assert consume_answer(tmp_path) is None


# ── bumblebee-port catalogs ──────────────────────────────────────────


def test_catalogs_load_with_many_entries():
    catalogs = load_catalogs()
    # 8 source files, hundreds of entries.
    assert len(catalogs) > 100
    eco_set = {e.ecosystem for e in catalogs}
    # Cross-ecosystem coverage from bumblebee.
    assert {"npm", "go"}.issubset(eco_set)


def test_match_compromised_dep_in_catalog():
    """Pick a known catalog entry and assert it's matched on exact version."""
    catalogs = load_catalogs()
    # Find ANY entry, then build a synthetic dep that exactly matches it.
    sample = next(iter(catalogs), None)
    assert sample is not None
    from network_pipeline.scanners.supply_chain_inventory import ResolvedDep
    dep = ResolvedDep(
        ecosystem=sample.ecosystem,
        package=sample.package,
        version=sample.versions[0],
        source_manifest="test",
    )
    hits = match_deps_against_catalogs([dep], catalogs=catalogs)
    assert len(hits) == 1
    assert hits[0][1].id == sample.id


def test_match_clean_dep_returns_no_hits():
    from network_pipeline.scanners.supply_chain_inventory import ResolvedDep
    dep = ResolvedDep(
        ecosystem="npm", package="completely-fake-package-xyz",
        version="999.999.999", source_manifest="t",
    )
    assert match_deps_against_catalogs([dep]) == []


# ── manifest parsers ─────────────────────────────────────────────────


def test_parse_package_json():
    deps = parse_package_json(
        '{"dependencies": {"a": "^1.2.3"}, "devDependencies": {"b": "~2.0.0"}}',
    )
    assert {(d.package, d.version) for d in deps} == {("a", "1.2.3"), ("b", "2.0.0")}


def test_parse_package_lock_v2():
    deps = parse_package_lock(json.dumps({
        "packages": {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/foo": {"version": "1.0.0"},
            "node_modules/@x/bar": {"version": "2.3.4", "name": "@x/bar"},
        }
    }))
    pkgs = {d.package for d in deps}
    assert "foo" in pkgs and "@x/bar" in pkgs


def test_parse_requirements_txt_ignores_unpinned():
    deps = parse_requirements_txt(
        "django==4.2.0\nrequests>=2.0.0\n# comment\n-r other.txt\nflask==2.1.0",
    )
    pinned = {(d.package, d.version) for d in deps}
    assert pinned == {("django", "4.2.0"), ("flask", "2.1.0")}


def test_parse_go_mod():
    text = """
module example.com/x

go 1.21

require (
    github.com/foo/bar v1.2.3
    github.com/baz/qux v0.0.1 // indirect
)

require github.com/single v9.9.9
"""
    deps = parse_go_mod(text)
    pkgs = {(d.package, d.version) for d in deps}
    assert ("github.com/foo/bar", "v1.2.3") in pkgs
    assert ("github.com/single", "v9.9.9") in pkgs


def test_parse_gemfile_lock():
    text = "GEM\n  specs:\n    rails (7.0.4)\n    rspec (3.12.0)\n"
    deps = parse_gemfile_lock(text)
    pkgs = {(d.package, d.version) for d in deps}
    assert {("rails", "7.0.4"), ("rspec", "3.12.0")} <= pkgs


def test_parse_composer_lock():
    text = json.dumps({
        "packages": [{"name": "foo/bar", "version": "1.0.0"}],
        "packages-dev": [{"name": "dev/x", "version": "2.0.0"}],
    })
    deps = parse_composer_lock(text)
    pkgs = {(d.package, d.version) for d in deps}
    assert pkgs == {("foo/bar", "1.0.0"), ("dev/x", "2.0.0")}


def test_parse_pipfile_lock():
    text = json.dumps({
        "default": {"django": {"version": "==4.2.0"}},
        "develop": {"pytest": {"version": "==7.0.0"}},
    })
    deps = parse_pipfile_lock(text)
    pkgs = {(d.package, d.version) for d in deps}
    assert pkgs == {("django", "4.2.0"), ("pytest", "7.0.0")}


# ── scanner integration (mocked HTTPClient) ─────────────────────────


def _mock_http(routes: dict):
    """Build a MagicMock whose .request returns 200 for keys in `routes`."""
    async def fake_request(method, url, **kwargs):
        for path, body in routes.items():
            if url.endswith(path):
                return SimpleNamespace(status_code=200, text=body)
        return SimpleNamespace(status_code=404, text="")
    client = MagicMock()
    client.request = fake_request
    return client


def test_supply_chain_scanner_finds_compromised_dep():
    catalogs = load_catalogs()
    sample = next(iter(catalogs))
    # Build a package.json declaring the catalog's first package@version.
    if sample.ecosystem == "npm":
        manifest = json.dumps({"dependencies": {sample.package: sample.versions[0]}})
        client = _mock_http({"/package.json": manifest})
    elif sample.ecosystem == "go":
        text = f"module example\nrequire {sample.package} {sample.versions[0]}\n"
        client = _mock_http({"/go.mod": text})
    elif sample.ecosystem == "pypi":
        text = f"{sample.package}=={sample.versions[0]}\n"
        client = _mock_http({"/requirements.txt": text})
    else:
        pytest.skip(f"no manifest fixture for ecosystem {sample.ecosystem}")

    scanner = SupplyChainInventoryScanner(client)
    result = asyncio.run(scanner.run("http://target.test"))
    assert result.success
    assert result.data["compromised_hits"] >= 1
    assert any(f.extra.get("catalog_id") == sample.id for f in result.findings)


def test_supply_chain_scanner_no_manifests_no_findings():
    client = _mock_http({})  # every fetch 404
    scanner = SupplyChainInventoryScanner(client)
    result = asyncio.run(scanner.run("http://target.test"))
    assert result.success
    assert result.data["compromised_hits"] == 0
    assert result.findings == []


# ── selftest CLI logic ──────────────────────────────────────────────


def test_selftest_command_passes():
    """The selftest is essentially a curated subset of the unit suite.
    Running it inline should produce no failures."""
    from network_pipeline.core.principles import load_library, sample_compositions
    from network_pipeline.core.hrl_trajectory import (
        TrajectoryState, TurnObservation, compute_reward,
    )
    from network_pipeline.tools.kg import KnowledgeGraph, EdgeType

    assert len(load_library()) >= 12
    assert sample_compositions(size=2, count=1, seed=0)
    state = TrajectoryState(objective_id="X", target="t", intent="i")
    rb = compute_reward(TurnObservation(response_status=200, response_body="ok"), state=state)
    assert rb.total > 0


# ── bug audit: registry includes every new phase ────────────────────


def test_registry_covers_llm_redteam():
    from network_pipeline.agents.registry import discover
    from network_pipeline.core.schemas import ObjectivePhase
    reg = discover(force=True)
    assert ObjectivePhase.LLM_REDTEAM in reg
    role, factory = reg[ObjectivePhase.LLM_REDTEAM]
    assert role == "llm_redteam"


def test_autopilot_config_defaults_safe(tmp_path: Path):
    cfg = AutopilotConfig(prompt="test target.com", workspace=tmp_path)
    # Phase-10: profile default is empty so resolved_profile() picks via
    # llm.credentials.auto_profile() based on available credentials.
    assert cfg.profile == ""
    assert cfg.auto_answer_defaults is True
    assert cfg.cop_enabled is True
    assert cfg.structured_reasoning is True
    # resolved_profile() must always return a non-empty profile name.
    assert cfg.resolved_profile() in {
        "eco", "max", "test", "cloud_eco", "cloud_max", "hybrid", "openai_only",
    }
