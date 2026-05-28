"""KG-driven dynamic objective synthesis.

After each engagement iteration, compare the knowledge graph before and
after to spot newly-discovered assets (hosts, ports, services) and turn
them into follow-up objectives. Appended to the OPPLAN so the next loop
tick picks them up automatically — no human replanning required.

Rules are intentionally conservative:

* Only emit objectives when ``synthesized_from`` doesn't already exist
  for the same target, so we never create duplicates on re-discovery.
* Use a high ``priority`` number (lower priority than seeded objectives)
  so auto-generated work runs after human-authored plan items.
* Every synthesised objective carries ``synthesized_from=<kg_node_id>``
  for auditability.

The engagement loop calls ``synthesize_from_kg_delta`` at the end of
each attack iteration.
"""

from __future__ import annotations

from typing import Iterable

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    OPPLAN,
    Objective,
    ObjectivePhase,
    OpsecLevel,
)

log = get_logger("core.synthesis")


# Base priority for auto-objectives: starts well below seeded (10/20/30)
# so planned work executes first. Each new synthesised objective
# increments by 1 to preserve insertion order within the batch.
_AUTO_PRIORITY_BASE = 500


def _existing_synth_ids(opplan: OPPLAN) -> set[str]:
    return {o.synthesized_from for o in opplan.objectives if o.synthesized_from}


def _next_obj_id(opplan: OPPLAN, offset: int = 0) -> str:
    n = len(opplan.objectives) + 1 + offset
    return f"OBJ-{n:03d}"


def synthesize_from_kg_delta(
    opplan: OPPLAN,
    new_nodes: Iterable[dict],
    *,
    default_opsec: OpsecLevel = OpsecLevel.STANDARD,
    playbook_engine: "object | None" = None,
    all_kg_nodes: list[dict] | None = None,
    c2_tier: "object | None" = None,
) -> list[Objective]:
    """Append follow-up objectives for newly-discovered KG nodes.

    ``new_nodes`` is the list of node dicts that appeared in the KG since
    the last iteration. Returns the list of objectives that were actually
    appended (may be empty). Caller is responsible for persisting the
    mutated OPPLAN.

    Phase-2: when a ``playbook_engine`` is provided, also asks it for
    new MITRE-mapped objectives whose preconditions hold in the FULL
    KG (``all_kg_nodes``). Playbook objectives are appended at priority
    band 300, KG-delta at 500+ — playbook work runs first within the
    auto-synthesised pool.
    """
    existing_synth = _existing_synth_ids(opplan)
    appended: list[Objective] = []
    offset = 0

    # ── Playbook engine pass (priority 300+) ──────────────────────
    if playbook_engine is not None:
        try:
            kg_nodes = all_kg_nodes if all_kg_nodes is not None else []
            # Re-seed the engine's emitted set from the OPPLAN so a
            # resumed engagement doesn't re-emit playbook steps.
            already = [
                str(s).split(":", 1)[1] for s in existing_synth
                if isinstance(s, str) and s.startswith("playbook:")
            ]
            if already and hasattr(playbook_engine, "remember"):
                playbook_engine.remember(already)
            pb_objs = playbook_engine.propose_next(  # type: ignore[attr-defined]
                kg_nodes,
                opsec=default_opsec,
                c2_tier=c2_tier,
            )
            for obj in pb_objs:
                # Renumber to avoid clashing with seeded OBJ-NNN ids
                obj.id = _next_obj_id(opplan, offset=offset)
                opplan.objectives.append(obj)
                appended.append(obj)
                offset += 1
            if pb_objs:
                log.info(
                    "playbook engine appended %d objective(s)",
                    len(pb_objs),
                )
        except Exception as e:  # pragma: no cover - defensive
            log.warning("playbook engine failed: %r", e)

    for node in new_nodes:
        node_id = node.get("id", "")
        node_type = node.get("type", "")
        props = node.get("properties", {}) or {}

        if not node_id or node_id in existing_synth:
            continue

        spec = _rule_for_node(node_id, node_type, props)
        if spec is None:
            continue

        phase, title, description, acceptance, hints = spec
        obj = Objective(
            id=_next_obj_id(opplan, offset=offset),
            phase=phase,
            title=title,
            description=description,
            acceptance_criteria=acceptance,
            priority=_AUTO_PRIORITY_BASE + offset,
            opsec=default_opsec,
            synthesized_from=node_id,
            retry_hints=list(hints),
        )
        opplan.objectives.append(obj)
        appended.append(obj)
        offset += 1
        log.info(
            "synthesised %s from KG node %s (%s)",
            obj.id, node_id, node_type,
        )

    return appended


def _rule_for_node(
    node_id: str, node_type: str, props: dict,
) -> tuple[ObjectivePhase, str, str, list[str], list[str]] | None:
    """Return (phase, title, description, acceptance_criteria, hints) or None.

    Encodes the static heuristics: new host → scan, new HTTP service →
    web exploit audit, new TLS service → TLS audit, new credential →
    post-exploit reuse check.
    """
    # Host: schedule a broad scan. Skip if scan is already planned for
    # this host (heuristic — callers can over-schedule but dedup happens
    # at acceptance via ``synthesized_from``).
    if node_type == "host":
        target = props.get("address") or node_id.split(":", 1)[-1]
        return (
            ObjectivePhase.SCAN,
            f"Scan newly discovered host {target}",
            f"KG reported a new host node ({node_id}). Enumerate ports, "
            "services, and HTTP metadata. Feed findings back into the KG.",
            [
                "All TCP ports in 1-1024 probed.",
                "Service banners captured for open ports.",
                "KG updated with port/service nodes.",
            ],
            ["auto-generated: narrow scope to this host only"],
        )

    # HTTP/HTTPS service: schedule a web-layer exploit sweep.
    if node_type in ("service", "port"):
        svc = (props.get("service") or props.get("name") or "").lower()
        port = str(props.get("port", ""))
        scheme = None
        if "https" in svc or port == "443" or port == "8443":
            scheme = "https"
        elif "http" in svc or port == "80" or port == "8080":
            scheme = "http"
        if scheme:
            host = props.get("host") or node_id
            return (
                ObjectivePhase.INITIAL_ACCESS,
                f"Web audit of {scheme}://{host}:{port}",
                (
                    f"KG now has an {scheme.upper()} service at {host}:{port}. "
                    "Run nuclei tech-detection + CVE templates and inspect "
                    "default paths. Avoid intrusive exploitation."
                ),
                [
                    "At least one nuclei pass against the URL.",
                    "Response headers captured.",
                    "Any CVE matches recorded as findings.",
                ],
                [
                    "auto-generated: limit nuclei severity to medium+",
                    "if OPSEC=silent this objective will self-skip",
                ],
            )

    # Credential node: try to reuse the cred on nearby hosts.
    if node_type == "credential":
        return (
            ObjectivePhase.POST_EXPLOIT,
            f"Reuse credential {node_id}",
            (
                "A new credential node appeared in the KG. Attempt reuse "
                "across services already in the graph (SSH, HTTP auth, "
                "admin panels) — STRICTLY within RoE scope."
            ),
            [
                "Credential tested against ≥2 services.",
                "Success/failure recorded as findings with evidence.",
            ],
            ["auto-generated: stop at first success; do not brute force"],
        )

    return None
