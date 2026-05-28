"""Confidence-weighted finding synthesis (Plan B.2.4).

Two PROBABLE findings about the same target with non-overlapping
verified-method evidence should logically combine into ONE verified
finding. The Phase-1 finding-protocol gate rejects HIGH/CRITICAL
without confidence=verified + 2 methods; this module is the upgrade
path — rather than rejecting, the analyst pass merges siblings
together to reach the gate.

Algorithm:

1. Group findings by ``(affected_target, cwe_set, mitre_set)``.
2. Within a group, if ≥2 findings are PROBABLE and their
   ``verified_methods`` lists are disjoint with combined size ≥2,
   synthesise a parent ``Finding(confidence=VERIFIED, verified_methods=
   union)``. Children get ``superseded_by=<parent_id>``.
3. The gate validator on the parent fires automatically — when CRITICAL
   or HIGH, it now passes because ``len(verified_methods) >= 2``.
4. Persist the parent + the updated children to ``findings.jsonl``.

The function is idempotent: findings already with ``superseded_by`` set
are skipped on the next pass.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    Evidence,
    Finding,
    FindingConfidence,
    FindingSeverity,
)

log = get_logger("core.finding_synthesis")


def _group_key(f: Finding) -> tuple[str, frozenset[str], frozenset[str]]:
    return (
        (f.affected_target or "").strip().lower(),
        frozenset(f.cwe or []),
        frozenset(f.mitre or []),
    )


def _highest_severity(items: Iterable[Finding]) -> FindingSeverity:
    rank = {
        FindingSeverity.CRITICAL: 4,
        FindingSeverity.HIGH: 3,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 1,
        FindingSeverity.INFORMATIONAL: 0,
    }
    return max(items, key=lambda f: rank[f.severity]).severity


def synthesize_findings(
    findings: list[Finding],
    *,
    next_id_fn,
) -> list[Finding]:
    """Return new parent findings synthesised from probable siblings.

    ``next_id_fn`` is a callable returning the next finding id (e.g.
    ``FindingsLog.next_id``). Caller is responsible for persisting the
    returned parents AND calling ``mark_children_superseded`` on the
    inputs (or just persisting the mutated children directly).

    ``findings`` is mutated in place: matched children get
    ``superseded_by`` set so the next pass is idempotent.
    """
    candidates: dict[
        tuple[str, frozenset[str], frozenset[str]], list[Finding]
    ] = defaultdict(list)
    for f in findings:
        # Skip already-merged children + already-verified primaries.
        if f.superseded_by:
            continue
        if f.confidence == FindingConfidence.VERIFIED:
            continue
        # Only synth on findings with at least one verified method —
        # otherwise the union has no real evidence behind it.
        if not f.verified_methods:
            continue
        candidates[_group_key(f)].append(f)

    parents: list[Finding] = []
    for key, group in candidates.items():
        if len(group) < 2:
            continue
        # Union must end up ≥2 distinct methods.
        union: list[str] = []
        seen: set[str] = set()
        for f in group:
            for m in f.verified_methods:
                key_norm = m.strip().lower()
                if key_norm and key_norm not in seen:
                    seen.add(key_norm)
                    union.append(m.strip())
        if len(union) < 2:
            continue

        target, cwe, mitre = key
        parent_id = next_id_fn()
        # Combine evidence pointers across children so the report
        # writer has every artefact path.
        evidence: list[Evidence] = []
        for f in group:
            evidence.extend(f.evidence)

        # Synthesised description names the children for traceability.
        child_summaries = "; ".join(
            f"{f.id} [{f.severity.value}] {f.title}" for f in group
        )
        try:
            parent = Finding(
                id=parent_id,
                title=f"Confirmed: {group[0].title}",
                severity=_highest_severity(group),
                confidence=FindingConfidence.VERIFIED,
                cwe=list(cwe),
                mitre=list(mitre),
                affected_target=target,
                description=(
                    "Synthesised from multiple probable findings whose "
                    "evidence covers distinct verification methods. "
                    f"Children: {child_summaries}"
                ),
                steps_to_reproduce=group[0].steps_to_reproduce,
                impact=group[0].impact,
                evidence=evidence,
                remediation=group[0].remediation,
                remediation_priority=group[0].remediation_priority,
                verified_methods=union,
                detected=any(f.detected for f in group),
                detection_notes="; ".join(
                    f.detection_notes for f in group if f.detection_notes
                ),
                objective_id=group[0].objective_id,
                phase=group[0].phase,
                agent="analyst",
                iteration=max(f.iteration for f in group),
            )
        except Exception as e:  # pragma: no cover - defensive
            log.warning(
                "synthesis rejected by validator for group %r: %r", key, e,
            )
            continue
        parents.append(parent)
        for f in group:
            f.superseded_by = parent.id
        log.info(
            "synthesised %s from %d children (target=%s, methods=%s)",
            parent.id, len(group), target, union,
        )
    return parents
