"""Causal KG edges (Plan B.2.3).

The Phase-1 KG is a flat property graph — host nodes, port nodes,
service nodes, finding nodes, credential nodes. It captures *what
exists* but not *what enables what*: real attack-chain reasoning needs
edges of the form "host:1.2.3.4 has port:8080 → service:tomcat → CVE
node → enables RCE finding".

This module adds the ``enables`` edge type. Callers are:

* ``infer_causal_edges_heuristic(kg)`` — pure-Python rules over the
  current KG state. Cheap, runs every iteration. Examples:
    - host → port (when port.host_id == host.id)
    - port → service (service.port_id == port.id)
    - service → finding (finding.affected_target startswith service host:port)
    - finding → finding (CVE chains: an "RCE on tomcat" finding
      enables "lateral movement to db-server" finding when the latter
      is on a host reachable from the former).
* ``infer_causal_edges_llm(kg, llm)`` — calls an LLM with the KG node
  list and asks it to propose ``enables`` edges. Plan risk #10
  mitigation: only emits an edge when BOTH endpoints already have ≥1
  tool-emitted finding (we don't trust the LLM to fabricate causal
  chains over LLM-only nodes).

Edges are added through the existing ``KnowledgeGraph.add_edge`` so
they go through the filelock + atomic write path.
"""

from __future__ import annotations

import json
from typing import Any

from network_pipeline.core.logging import get_logger
from network_pipeline.tools.kg import KGEdge, KnowledgeGraph

log = get_logger("core.causal_kg")


CAUSAL_RELATION = "enables"


def _node_index(nodes: list[dict]) -> dict[str, dict]:
    return {n["id"]: n for n in nodes}


def _has_tool_evidence(node: dict) -> bool:
    """Return True if a node carries non-LLM-only evidence.

    Heuristic: tool-emitted nodes have ``properties.source`` set to one
    of the binary names from the allowlist. LLM-only nodes default to
    ``source="agent"`` or absent.
    """
    src = (node.get("properties") or {}).get("source", "")
    return bool(src) and src not in ("agent", "analyst", "llm")


# ── Heuristic pass ───────────────────────────────────────────────────


def infer_causal_edges_heuristic(kg: KnowledgeGraph) -> int:
    """Add deterministic structural ``enables`` edges. Returns count added.

    Idempotent: ``KnowledgeGraph.add_edge`` appends; we check the
    existing edge list to avoid duplicate edges between the same pair.
    """
    nodes = kg.query()
    if not nodes:
        return 0
    by_id = _node_index(nodes)
    # Bug-fix B: the prior comprehension shadowed `e` and never built
    # the set correctly, so structural edges were re-added every
    # iteration without dedup. Walk neighbors per node and collect
    # ``enables`` edge pairs once.
    existing: set[tuple[str, str]] = set()
    for n in nodes:
        try:
            nbrs = kg.neighbors(n["id"]) or []
        except Exception:
            nbrs = []
        for nbr in nbrs:
            if nbr.get("relation") == CAUSAL_RELATION:
                existing.add((nbr.get("src", ""), nbr.get("dst", "")))

    added = 0
    for node in nodes:
        n_id = node["id"]
        n_type = node.get("type", "")
        props = node.get("properties") or {}

        # host → port (when port lists its host_id)
        if n_type == "port":
            host_id = props.get("host_id") or props.get("host")
            if host_id and host_id in by_id and (host_id, n_id) not in existing:
                kg.add_edge(KGEdge(
                    src=host_id, dst=n_id, relation=CAUSAL_RELATION,
                    properties={"reason": "host hosts port"},
                ))
                existing.add((host_id, n_id))
                added += 1

        # port → service (service lists port_id)
        if n_type == "service":
            port_id = props.get("port_id") or props.get("port")
            if port_id and port_id in by_id and (port_id, n_id) not in existing:
                kg.add_edge(KGEdge(
                    src=port_id, dst=n_id, relation=CAUSAL_RELATION,
                    properties={"reason": "port exposes service"},
                ))
                existing.add((port_id, n_id))
                added += 1

        # service → finding (finding affects this service's host:port)
        if n_type == "finding":
            target = (props.get("affected_target") or "").lower()
            if target:
                for cand in nodes:
                    if cand.get("type") != "service":
                        continue
                    cand_id = cand["id"]
                    cand_host = (cand.get("properties") or {}).get("host", "").lower()
                    cand_port = str((cand.get("properties") or {}).get("port", ""))
                    if cand_host and cand_host in target:
                        if cand_port and f":{cand_port}" not in target and cand_port not in target:
                            continue
                        if (cand_id, n_id) not in existing:
                            kg.add_edge(KGEdge(
                                src=cand_id, dst=n_id, relation=CAUSAL_RELATION,
                                properties={"reason": "service hosts finding"},
                            ))
                            existing.add((cand_id, n_id))
                            added += 1
                            break

        # finding → credential (a finding that exposes creds enables
        # those creds to be used downstream)
        if n_type == "credential":
            originating = props.get("from_finding")
            if (originating and originating in by_id
                    and (originating, n_id) not in existing):
                kg.add_edge(KGEdge(
                    src=originating, dst=n_id, relation=CAUSAL_RELATION,
                    properties={"reason": "finding exposed credential"},
                ))
                existing.add((originating, n_id))
                added += 1

    if added:
        log.info("causal_kg heuristic added %d enables edges", added)
    return added


# ── LLM-judged pass (plan risk #10 — gated behind tool-evidence rule) ─


_LLM_SYSTEM = """You are a causal-chain analyst for an autonomous pentest pipeline.

Given a list of KG nodes (host / port / service / finding / credential)
propose ``enables`` edges that represent real attack-chain causality:
"if I have node A I can reach / exploit node B".

Output STRICT JSON:

{
  "edges": [
    {"src": "<src node id>", "dst": "<dst node id>", "reason": "one sentence"},
    ...
  ]
}

Rules:
1. ONLY propose edges between nodes that EXIST in the supplied list.
2. NEVER propose an edge unless the causality is clearly implied by
   the node properties (e.g. service:tomcat → finding:CVE-2024-12345
   when the finding cites tomcat).
3. Skip pairs already linked by structural edges (host→port, port→service).
4. Return ONLY the JSON.
"""


def _parse_llm_edges(text: str) -> list[dict]:
    if not text:
        return []
    body = text.strip()
    if body.startswith("```"):
        body = body.strip("`")
        if body.lstrip().lower().startswith("json"):
            body = body.split("\n", 1)[-1]
    a = body.find("{")
    b = body.rfind("}")
    if a == -1 or b == -1:
        return []
    try:
        data = json.loads(body[a:b + 1])
    except json.JSONDecodeError:
        return []
    out = data.get("edges") or []
    return [e for e in out if isinstance(e, dict) and "src" in e and "dst" in e]


def infer_causal_edges_llm(kg: KnowledgeGraph, llm: Any, *, max_nodes: int = 50) -> int:
    """LLM-judged ``enables`` pass with the tool-evidence guard.

    Plan risk #10: an edge is only persisted when both endpoints have
    ≥1 tool-emitted property (``properties.source`` != "agent"/"llm").
    Prevents the LLM from fabricating attack chains over hypothetical
    nodes.
    """
    nodes = kg.query()[:max_nodes]
    if len(nodes) < 2:
        return 0
    by_id = _node_index(nodes)
    try:
        from langchain_core.messages import (  # type: ignore[import-not-found]
            HumanMessage, SystemMessage,
        )
        compact = [
            {
                "id": n["id"],
                "type": n["type"],
                "props": {
                    k: v for k, v in (n.get("properties") or {}).items()
                    if k in (
                        "host", "port", "service", "product", "version",
                        "cve", "title", "severity", "from_finding",
                    )
                },
            }
            for n in nodes
        ]
        messages = [
            SystemMessage(content=_LLM_SYSTEM),
            HumanMessage(content=json.dumps({"nodes": compact}, indent=2)),
        ]
        resp = llm.invoke(messages)
        text = getattr(resp, "content", "") or ""
    except Exception as e:  # pragma: no cover - defensive
        log.warning("causal_kg LLM call failed: %r", e)
        return 0

    proposals = _parse_llm_edges(text)
    if not proposals:
        return 0

    added = 0
    skipped_unsupported = 0
    skipped_no_evidence = 0
    for p in proposals:
        src = p.get("src")
        dst = p.get("dst")
        if src not in by_id or dst not in by_id:
            skipped_unsupported += 1
            continue
        if not (_has_tool_evidence(by_id[src]) and _has_tool_evidence(by_id[dst])):
            skipped_no_evidence += 1
            continue
        kg.add_edge(KGEdge(
            src=src, dst=dst, relation=CAUSAL_RELATION,
            properties={"reason": p.get("reason", "")[:200], "judge": "llm"},
        ))
        added += 1

    log.info(
        "causal_kg LLM added %d edges (skipped %d unsupported, %d no-evidence)",
        added, skipped_unsupported, skipped_no_evidence,
    )
    return added


__all__ = [
    "CAUSAL_RELATION",
    "infer_causal_edges_heuristic",
    "infer_causal_edges_llm",
]
