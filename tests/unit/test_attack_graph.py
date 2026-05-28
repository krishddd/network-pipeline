"""Phase-7 tests: attack-graph upgrade (typed KG + Mermaid reporter)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from network_pipeline.tools.kg import (
    EdgeType,
    KGEdge,
    KGNode,
    KnowledgeGraph,
    NodeType,
)
from network_pipeline.tools.report import (
    _mermaid_safe_id,
    _mermaid_safe_label,
    write_mermaid_attack_chain,
)


# ── typed vocabulary constants ───────────────────────────────────────


def test_node_type_constants_match_plan():
    assert NodeType.HOST == "host"
    assert NodeType.DEFENSE_ACTION == "defense_action"
    assert NodeType.VULNERABILITY == "vulnerability"
    assert NodeType.FINDING == "finding"


def test_edge_type_constants_match_plan():
    assert EdgeType.MITIGATES == "mitigates"
    assert EdgeType.RESPONDS_TO == "responds_to"
    assert EdgeType.VERIFIED == "verified"
    assert EdgeType.CHAINS_TO == "chains_to"
    assert EdgeType.EXPLOITS == "exploits"


# ── KG attack-graph writers ──────────────────────────────────────────


def _kg(tmp_path: Path) -> KnowledgeGraph:
    return KnowledgeGraph(tmp_path / "kg.json")


def test_add_defense_action_emits_node_and_edges(tmp_path: Path):
    kg = _kg(tmp_path)
    kg.add_defense_action(
        action_id="REC-001",
        title="Patch SQLi in /search",
        finding_ids=["FIND-001", "FIND-002"],
        root_cause="unparameterised SQL",
        patch="use prepared statements",
        detection="alert on UNION SELECT",
        hardening="enable WAF",
    )
    data = kg.snapshot()
    node_ids = {n["id"] for n in data["nodes"]}
    assert "defense:REC-001" in node_ids
    # Both finding stubs created.
    assert "finding:FIND-001" in node_ids
    assert "finding:FIND-002" in node_ids

    relations = [(e["src"], e["dst"], e["relation"]) for e in data["edges"]]
    assert ("defense:REC-001", "finding:FIND-001", "mitigates") in relations
    assert ("defense:REC-001", "finding:FIND-001", "responds_to") in relations
    assert ("defense:REC-001", "finding:FIND-002", "mitigates") in relations


def test_add_defense_action_preserves_existing_finding_node(tmp_path: Path):
    """When a finding node already exists with richer properties, the
    defender's stub must NOT overwrite the properties (add_node merges)."""
    kg = _kg(tmp_path)
    kg.add_node(KGNode(
        id="finding:FIND-001", type="finding",
        properties={"severity": "high", "title": "Original finding"},
    ))
    kg.add_defense_action(
        action_id="REC-001", title="x", finding_ids=["FIND-001"],
    )
    data = kg.snapshot()
    finding_node = next(n for n in data["nodes"] if n["id"] == "finding:FIND-001")
    assert finding_node["properties"]["severity"] == "high"
    assert finding_node["properties"]["title"] == "Original finding"


def test_add_verification_emits_verified_edge(tmp_path: Path):
    kg = _kg(tmp_path)
    kg.add_defense_action(
        action_id="REC-1", title="t", finding_ids=["FIND-001"],
    )
    kg.add_verification(
        action_id="REC-1", finding_id="FIND-001",
        verified=True, notes="re-attack blocked",
    )
    data = kg.snapshot()
    verifies = [e for e in data["edges"]
                if e["relation"] == "verified"
                and e["src"] == "defense:REC-1"
                and e["dst"] == "finding:FIND-001"]
    assert len(verifies) == 1
    assert verifies[0]["properties"]["verified"] is True
    assert verifies[0]["properties"]["notes"] == "re-attack blocked"


def test_add_verification_records_failed_attempts(tmp_path: Path):
    """verified=False is still recorded so the report shows attempted-but-failed."""
    kg = _kg(tmp_path)
    kg.add_verification(
        action_id="REC-2", finding_id="FIND-002",
        verified=False, notes="re-attack still succeeded",
    )
    data = kg.snapshot()
    v = next(e for e in data["edges"] if e["relation"] == "verified")
    assert v["properties"]["verified"] is False


# ── NetworkX view ────────────────────────────────────────────────────


def test_as_networkx_returns_multidigraph(tmp_path: Path):
    nx = pytest.importorskip("networkx")
    kg = _kg(tmp_path)
    kg.add_node(KGNode(id="host:1.2.3.4", type="host", properties={"address": "1.2.3.4"}))
    kg.add_node(KGNode(id="port:1.2.3.4:443/tcp", type="port", properties={}))
    kg.add_edge(KGEdge(src="host:1.2.3.4", dst="port:1.2.3.4:443/tcp", relation="exposes"))
    g = kg.as_networkx()
    assert isinstance(g, nx.MultiDiGraph)
    assert g.has_node("host:1.2.3.4")
    assert g.nodes["host:1.2.3.4"]["type"] == "host"
    assert g.has_edge("host:1.2.3.4", "port:1.2.3.4:443/tcp")


def test_as_networkx_carries_multiple_edge_relations(tmp_path: Path):
    pytest.importorskip("networkx")
    kg = _kg(tmp_path)
    kg.add_defense_action(action_id="R1", title="t", finding_ids=["F1"])
    g = kg.as_networkx()
    # Both mitigates + responds_to between the same node pair.
    edge_keys = set()
    for u, v, k in g.edges(keys=True):
        if u == "defense:R1" and v == "finding:F1":
            edge_keys.add(k)
    assert {"mitigates", "responds_to"} <= edge_keys


# ── defender + verifier integration ─────────────────────────────────


def test_defender_write_emits_kg_nodes(tmp_path: Path, monkeypatch):
    """write_defense_brief tool — exercised by writing brief + KG directly.

    The agent factory needs LangChain, so we test the *write logic*
    by invoking the inner closure path: replicate what the @tool does.
    """
    kg_path = tmp_path / "kg.json"
    kg = KnowledgeGraph(kg_path)
    # Simulate the write_defense_brief inner behaviour:
    brief = tmp_path / "defense_brief.json"
    recs = [
        {"id": "REC-001", "title": "Patch SQLi",
         "finding_ids": ["F1", "F2"], "root_cause": "no prepare"},
        {"id": "REC-002", "title": "Block dir traversal",
         "finding_ids": ["F3"], "patch": "normalise path"},
    ]
    brief.write_text(json.dumps({"recommendations": recs}), encoding="utf-8")
    for idx, rec in enumerate(recs, start=1):
        kg.add_defense_action(
            action_id=rec.get("id", f"REC-{idx:03d}"),
            title=rec.get("title", ""),
            finding_ids=rec.get("finding_ids") or [],
            root_cause=rec.get("root_cause", ""),
            patch=rec.get("patch", ""),
        )

    data = kg.snapshot()
    assert any(n["id"] == "defense:REC-001" for n in data["nodes"])
    assert any(n["id"] == "defense:REC-002" for n in data["nodes"])
    relations = {(e["src"], e["dst"], e["relation"]) for e in data["edges"]}
    assert ("defense:REC-001", "finding:F2", "mitigates") in relations
    assert ("defense:REC-002", "finding:F3", "responds_to") in relations


def test_verifier_emit_verified_edges_helper(tmp_path: Path):
    """_emit_verified_edges happy-path: reads brief, finds matching defense,
    emits a VERIFIED edge."""
    from network_pipeline.agents.verifier import _emit_verified_edges

    kg = _kg(tmp_path)
    # Seed defender side
    kg.add_defense_action(action_id="REC-001", title="t",
                          finding_ids=["F1", "F2"])
    (tmp_path / "defense_brief.json").write_text(
        json.dumps({"recommendations": [
            {"id": "REC-001", "finding_ids": ["F1", "F2"]},
        ]}),
        encoding="utf-8",
    )

    n = _emit_verified_edges(
        tmp_path, kg,
        blocked_ids={"F1"},
        results=[{"id": "F1", "reproducible": False, "notes": "blocked"}],
    )
    assert n == 1
    data = kg.snapshot()
    v_edges = [e for e in data["edges"] if e["relation"] == "verified"]
    assert any(e["dst"] == "finding:F1" for e in v_edges)
    assert not any(e["dst"] == "finding:F2" for e in v_edges)


def test_verifier_emit_verified_edges_skips_missing_brief(tmp_path: Path):
    from network_pipeline.agents.verifier import _emit_verified_edges
    kg = _kg(tmp_path)
    assert _emit_verified_edges(tmp_path, kg, {"F1"}, []) == 0


# ── Mermaid reporter ─────────────────────────────────────────────────


def test_mermaid_safe_id_slugifies():
    assert _mermaid_safe_id("defense:REC-001").startswith("defense_REC_001"[:60])
    assert _mermaid_safe_id("").startswith("n_")
    # Always starts with a letter
    out = _mermaid_safe_id("123-abc")
    assert out[0].isalpha()


def test_mermaid_safe_label_caps_and_escapes():
    s = _mermaid_safe_label("a\"b\nc")
    assert '"' not in s
    assert "\n" not in s
    long = _mermaid_safe_label("x" * 200, cap=20)
    assert len(long) <= 20


def test_write_mermaid_attack_chain_renders_basic_graph(tmp_path: Path):
    kg = _kg(tmp_path)
    kg.add_defense_action(action_id="REC-1", title="Block SQLi",
                          finding_ids=["FIND-001"])
    kg.add_verification(action_id="REC-1", finding_id="FIND-001",
                        verified=True)
    out = write_mermaid_attack_chain(tmp_path, tmp_path / "chain.mmd")
    text = out.read_text(encoding="utf-8")
    assert text.startswith("flowchart LR")
    # Defense node hexagon syntax
    assert "{{" in text and "}}" in text
    # mitigates + verified arrows
    assert "mitigates" in text
    assert "verified" in text
    # classDef styling block present
    assert "classDef defense" in text


def test_write_mermaid_attack_chain_handles_empty_workspace(tmp_path: Path):
    out = write_mermaid_attack_chain(tmp_path, tmp_path / "chain.mmd")
    text = out.read_text(encoding="utf-8")
    assert text.startswith("flowchart LR")
    assert "no kg.json" in text


def test_write_mermaid_uses_finding_severity_class(tmp_path: Path):
    kg = _kg(tmp_path)
    kg.add_defense_action(action_id="REC-1", title="t",
                          finding_ids=["FIND-001"])
    # findings.jsonl with one HIGH finding
    findings_line = json.dumps({
        "id": "FIND-001", "severity": "high", "title": "x",
        "confidence": "verified", "verified_methods": ["m1", "m2"],
        "affected_target": "t", "description": "d",
    })
    (tmp_path / "findings.jsonl").write_text(findings_line + "\n", encoding="utf-8")
    out = write_mermaid_attack_chain(tmp_path, tmp_path / "chain.mmd")
    text = out.read_text(encoding="utf-8")
    assert "sev_high" in text
