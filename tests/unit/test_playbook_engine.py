"""Tests for core.playbook — Playbook YAML loader + PlaybookEngine."""

from __future__ import annotations

from pathlib import Path

import pytest


def _write_yaml(p: Path, body: str) -> Path:
    p.write_text(body, encoding="utf-8")
    return p


def test_load_builtin_owasp_top10():
    pytest.importorskip("yaml")
    from network_pipeline.core.playbook import load_playbook

    pb = load_playbook("owasp_top10")
    assert pb.name == "owasp_top10"
    assert len(pb.steps) >= 5
    # Step ids must be unique
    ids = [s.step_id for s in pb.steps]
    assert len(ids) == len(set(ids))


def test_propose_emits_only_when_preconditions_hold(tmp_path: Path):
    pytest.importorskip("yaml")
    from network_pipeline.core.playbook import PlaybookEngine, load_playbook

    yaml_body = """
name: t
description: tiny
steps:
  - id: t-recon
    mitre_id: T1
    phase: recon
    title: Recon
    description: d
    preconditions: []
    acceptance_criteria: [a]
  - id: t-scan
    mitre_id: T2
    phase: scan
    title: Scan
    description: d
    preconditions:
      - "host"
    acceptance_criteria: [a]
"""
    p = _write_yaml(tmp_path / "tiny.yaml", yaml_body)
    pb = load_playbook(p)
    eng = PlaybookEngine(pb)

    # Empty KG → only the precondition-free step fires
    objs = eng.propose_next([])
    assert len(objs) == 1
    assert objs[0].synthesized_from == "playbook:t-recon"

    # Now KG has a host node — second step fires
    objs2 = eng.propose_next([{"id": "host:1", "type": "host", "properties": {}}])
    assert len(objs2) == 1
    assert objs2[0].synthesized_from == "playbook:t-scan"


def test_dedup_via_emitted_set(tmp_path: Path):
    pytest.importorskip("yaml")
    from network_pipeline.core.playbook import PlaybookEngine, load_playbook

    yaml_body = """
name: t
description: tiny
steps:
  - id: t-recon
    mitre_id: T1
    phase: recon
    title: Recon
    description: d
    preconditions: []
    acceptance_criteria: [a]
"""
    p = _write_yaml(tmp_path / "tiny.yaml", yaml_body)
    pb = load_playbook(p)
    eng = PlaybookEngine(pb)
    a = eng.propose_next([])
    b = eng.propose_next([])
    assert len(a) == 1 and len(b) == 0


def test_remember_skips_already_emitted_steps(tmp_path: Path):
    pytest.importorskip("yaml")
    from network_pipeline.core.playbook import PlaybookEngine, load_playbook

    yaml_body = """
name: t
description: tiny
steps:
  - id: t-recon
    mitre_id: T1
    phase: recon
    title: Recon
    description: d
    preconditions: []
    acceptance_criteria: [a]
"""
    p = _write_yaml(tmp_path / "tiny.yaml", yaml_body)
    pb = load_playbook(p)
    eng = PlaybookEngine(pb)
    eng.remember(["t-recon"])
    assert eng.propose_next([]) == []


def test_opsec_filter_drops_loud_step_at_quiet(tmp_path: Path):
    pytest.importorskip("yaml")
    from network_pipeline.core.playbook import PlaybookEngine, load_playbook
    from network_pipeline.core.schemas import OpsecLevel

    yaml_body = """
name: t
description: tiny
steps:
  - id: t-loud
    mitre_id: T1
    phase: scan
    title: Loud
    description: d
    preconditions: []
    acceptance_criteria: [a]
    opsec_max: standard
"""
    p = _write_yaml(tmp_path / "tiny.yaml", yaml_body)
    pb = load_playbook(p)
    eng = PlaybookEngine(pb)
    # opsec_max=standard means QUIET is too restrictive → step suppressed
    assert eng.propose_next([], opsec=OpsecLevel.QUIET) == []
    eng2 = PlaybookEngine(pb)
    assert len(eng2.propose_next([], opsec=OpsecLevel.STANDARD)) == 1


def test_predicate_with_kv_match(tmp_path: Path):
    pytest.importorskip("yaml")
    from network_pipeline.core.playbook import PlaybookEngine, load_playbook

    yaml_body = """
name: t
description: tiny
steps:
  - id: t-step
    mitre_id: T1
    phase: scan
    title: Scan
    description: d
    preconditions:
      - "service where service=http"
    acceptance_criteria: [a]
"""
    p = _write_yaml(tmp_path / "tiny.yaml", yaml_body)
    pb = load_playbook(p)
    # Wrong service type — no fire
    e1 = PlaybookEngine(pb)
    assert e1.propose_next([
        {"id": "svc:1", "type": "service", "properties": {"service": "ssh"}},
    ]) == []
    # Right service — fires
    e2 = PlaybookEngine(pb)
    objs = e2.propose_next([
        {"id": "svc:2", "type": "service", "properties": {"service": "http"}},
    ])
    assert len(objs) == 1
