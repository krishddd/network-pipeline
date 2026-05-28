"""MITRE ATT&CK playbook engine (Plan B.3.2).

A playbook is a YAML file that encodes a deterministic chain of
techniques the orchestrator should pursue. Each step has:

* ``mitre_id`` — ATT&CK technique reference (e.g. T1595.002)
* ``phase`` — ObjectivePhase the step belongs to
* ``title`` / ``description`` — used as the synthesised Objective
* ``preconditions`` — KG predicates that must hold before the step
  becomes a candidate. Each predicate is a tiny DSL string of the form
  ``"<node_type> [where <key>=<value>]"``. Examples:
    - ``host``                       # any host node exists
    - ``service where service=http`` # any HTTP service node
* ``tool_hint`` — recommended binary (e.g. "ffuf"); injected into the
  retry-hint stack so the agent picks it up.
* ``c2_tier_min`` — minimum C2 tier (interactive / short-haul /
  long-haul) the step may run under. Below that, the engine skips.
* ``opsec_max`` — most-restrictive OPSEC the step still runs at
  (loud > standard > careful > quiet > silent). Steps marked
  ``opsec_max: careful`` are dropped at QUIET / SILENT.
* ``priority_bump`` — relative priority within the playbook (lower = first).
* ``severity_hint`` — what the agent should expect to find.

Playbook objectives sit at ``priority=300`` band (between seeded 10/20/
30 and KG-delta 500+) so playbook work runs after the operator's hand-
authored seeds but before generic asset-discovery follow-ups.

The engine is consumed by ``core.synthesis.synthesize_from_kg_delta``
(Phase 2 wiring): on each iteration, after the KG delta is computed, we
also ask the playbook engine for new candidate steps.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    C2Tier,
    Objective,
    ObjectivePhase,
    OpsecLevel,
)

log = get_logger("core.playbook")


# YAML loader is optional — pyyaml is in many install profiles already.
try:
    import yaml  # type: ignore[import-untyped]
    _YAML_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised when pyyaml missing
    yaml = None  # type: ignore[assignment]
    _YAML_AVAILABLE = False


_OPSEC_RANK = {
    OpsecLevel.LOUD: 0,
    OpsecLevel.STANDARD: 1,
    OpsecLevel.CAREFUL: 2,
    OpsecLevel.QUIET: 3,
    OpsecLevel.SILENT: 4,
}

_C2_RANK = {
    C2Tier.INTERACTIVE: 0,
    C2Tier.SHORT_HAUL: 1,
    C2Tier.LONG_HAUL: 2,
}


# ── Step + Playbook dataclasses ──────────────────────────────────────


class PlaybookStep:
    """One technique chain link. Constructed from a YAML mapping."""

    __slots__ = (
        "step_id", "mitre_id", "phase", "title", "description",
        "preconditions", "acceptance_criteria",
        "tool_hint", "c2_tier_min", "opsec_max", "priority_bump",
    )

    def __init__(
        self,
        *,
        step_id: str,
        mitre_id: str,
        phase: ObjectivePhase,
        title: str,
        description: str,
        preconditions: list[str],
        acceptance_criteria: list[str],
        tool_hint: str = "",
        c2_tier_min: C2Tier | None = None,
        opsec_max: OpsecLevel | None = None,
        priority_bump: int = 0,
    ) -> None:
        self.step_id = step_id
        self.mitre_id = mitre_id
        self.phase = phase
        self.title = title
        self.description = description
        self.preconditions = preconditions
        self.acceptance_criteria = acceptance_criteria
        self.tool_hint = tool_hint
        self.c2_tier_min = c2_tier_min
        self.opsec_max = opsec_max
        self.priority_bump = priority_bump


class Playbook:
    """A loaded playbook — collection of steps + metadata."""

    def __init__(
        self, *, name: str, description: str, steps: list[PlaybookStep],
    ) -> None:
        self.name = name
        self.description = description
        self.steps = steps


# ── Loaders ──────────────────────────────────────────────────────────


_BUILTIN_PLAYBOOK_DIR = (
    Path(__file__).resolve().parent.parent / "skills" / "playbooks"
)


def builtin_playbook_dir() -> Path:
    return _BUILTIN_PLAYBOOK_DIR


def load_playbook(path_or_name: str | Path) -> Playbook:
    """Load a playbook by absolute path OR by built-in name.

    Built-in names look up files in ``network_pipeline/skills/playbooks``.
    """
    if not _YAML_AVAILABLE:
        raise RuntimeError(
            "PyYAML is required to load playbooks. "
            "`pip install pyyaml` or install the [network] extra."
        )
    p = Path(path_or_name)
    if not p.is_absolute() and not p.exists():
        # Resolve as a built-in name; allow ``owasp_top10`` shorthand
        candidate = _BUILTIN_PLAYBOOK_DIR / f"{p}.yaml"
        if candidate.exists():
            p = candidate
        else:
            candidate = _BUILTIN_PLAYBOOK_DIR / p
            if candidate.exists():
                p = candidate
    if not p.exists():
        raise FileNotFoundError(f"playbook not found: {path_or_name!r}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"playbook {p} root must be a mapping")
    return _build_playbook(raw, p)


def _build_playbook(raw: dict[str, Any], src: Path) -> Playbook:
    name = str(raw.get("name") or src.stem)
    description = str(raw.get("description", ""))
    steps_raw = raw.get("steps") or []
    if not isinstance(steps_raw, list):
        raise ValueError(f"{src}: steps must be a list")
    steps: list[PlaybookStep] = []
    for i, s in enumerate(steps_raw):
        if not isinstance(s, dict):
            raise ValueError(f"{src}: step #{i} must be a mapping")
        try:
            phase = ObjectivePhase(s.get("phase", ""))
        except ValueError as e:
            raise ValueError(f"{src}: step #{i} bad phase: {e}") from e
        c2_raw = s.get("c2_tier_min")
        c2_tier_min = C2Tier(c2_raw) if c2_raw else None
        op_raw = s.get("opsec_max")
        opsec_max = OpsecLevel(op_raw) if op_raw else None
        steps.append(
            PlaybookStep(
                step_id=str(s.get("id", f"{name}-{i+1:02d}")),
                mitre_id=str(s.get("mitre_id", "")),
                phase=phase,
                title=str(s.get("title", "")),
                description=str(s.get("description", "")),
                preconditions=[str(p) for p in (s.get("preconditions") or [])],
                acceptance_criteria=[
                    str(c) for c in (s.get("acceptance_criteria") or [])
                ],
                tool_hint=str(s.get("tool_hint", "")),
                c2_tier_min=c2_tier_min,
                opsec_max=opsec_max,
                priority_bump=int(s.get("priority_bump", 0)),
            )
        )
    return Playbook(name=name, description=description, steps=steps)


# ── Engine ───────────────────────────────────────────────────────────


def _parse_predicate(pred: str) -> tuple[str, dict[str, str]]:
    """Parse ``"node_type [where k=v[, k=v]]"`` → (node_type, {k:v}).

    Examples:
        "host"                          → ("host", {})
        "service where service=http"    → ("service", {"service": "http"})
        "port where port=443"           → ("port", {"port": "443"})
    """
    pred = pred.strip()
    if " where " not in pred:
        return pred, {}
    head, _, tail = pred.partition(" where ")
    parts = [p.strip() for p in tail.split(",") if "=" in p]
    return head.strip(), {p.split("=", 1)[0].strip(): p.split("=", 1)[1].strip()
                          for p in parts}


def _node_matches(node: dict[str, Any], node_type: str, kv: dict[str, str]) -> bool:
    if node.get("type") != node_type:
        return False
    if not kv:
        return True
    props = node.get("properties") or {}
    for k, v in kv.items():
        if str(props.get(k, "")).lower() != v.lower():
            return False
    return True


def _preconditions_satisfied(
    step: PlaybookStep, kg_nodes: list[dict[str, Any]],
) -> bool:
    """Return True iff every precondition has at least one matching KG node.

    Empty preconditions ⇒ trivially satisfied (e.g. recon entry steps).
    """
    if not step.preconditions:
        return True
    for pred in step.preconditions:
        node_type, kv = _parse_predicate(pred)
        if not any(_node_matches(n, node_type, kv) for n in kg_nodes):
            return False
    return True


def _step_compatible_with_opsec(
    step: PlaybookStep, opsec: OpsecLevel | None,
) -> bool:
    if step.opsec_max is None or opsec is None:
        return True
    # opsec_max=careful means the step won't run AT or above QUIET.
    return _OPSEC_RANK[opsec] <= _OPSEC_RANK[step.opsec_max]


def _step_compatible_with_c2(
    step: PlaybookStep, c2_tier: C2Tier | None,
) -> bool:
    if step.c2_tier_min is None or c2_tier is None:
        return True
    return _C2_RANK[c2_tier] <= _C2_RANK[step.c2_tier_min]


class PlaybookEngine:
    """Stateful engine that proposes Objectives from a Playbook + KG.

    The engine is consulted by ``core.synthesis`` after every iteration's
    KG delta. It returns Objective candidates whose preconditions match
    the CURRENT KG state and whose ``mitre_id`` hasn't been emitted yet
    (deduped via ``Objective.synthesized_from`` on the OPPLAN side).
    """

    # Priority band — between seeded (10/20/30) and KG-delta (500+).
    BASE_PRIORITY = 300

    def __init__(self, playbook: Playbook) -> None:
        self._playbook = playbook
        self._emitted_step_ids: set[str] = set()

    @property
    def name(self) -> str:
        return self._playbook.name

    def already_emitted_ids(self) -> set[str]:
        return set(self._emitted_step_ids)

    def remember(self, step_ids: list[str]) -> None:
        """Record step ids that have already been turned into objectives.

        Called when an OPPLAN reload reveals existing objectives whose
        ``synthesized_from`` field starts with ``"playbook:<step_id>"``.
        Lets the engine survive resume.
        """
        self._emitted_step_ids.update(step_ids)

    def propose_next(
        self,
        kg_nodes: list[dict[str, Any]],
        *,
        opsec: OpsecLevel | None = None,
        c2_tier: C2Tier | None = None,
        offset: int = 0,
    ) -> list[Objective]:
        """Return new Objectives whose preconditions hold + filters pass.

        ``offset`` is added to ``BASE_PRIORITY`` so the caller can
        interleave playbook objectives with other synthesised ones
        without colliding on priority.
        """
        out: list[Objective] = []
        for i, step in enumerate(self._playbook.steps):
            if step.step_id in self._emitted_step_ids:
                continue
            if not _step_compatible_with_opsec(step, opsec):
                continue
            if not _step_compatible_with_c2(step, c2_tier):
                continue
            if not _preconditions_satisfied(step, kg_nodes):
                continue
            obj_id = f"OBJ-PB{i+1:03d}"
            sid_tag = f"playbook:{step.step_id}"
            description = step.description
            if step.mitre_id:
                description = f"[{step.mitre_id}] {description}"
            hints = []
            if step.tool_hint:
                hints.append(f"playbook hint: prefer tool '{step.tool_hint}'")
            obj = Objective(
                id=obj_id,
                phase=step.phase,
                title=step.title,
                description=description,
                acceptance_criteria=step.acceptance_criteria,
                priority=self.BASE_PRIORITY + offset + step.priority_bump,
                mitre=[step.mitre_id] if step.mitre_id else [],
                opsec=opsec or OpsecLevel.STANDARD,
                c2_tier=c2_tier,
                synthesized_from=sid_tag,
                retry_hints=hints,
            )
            out.append(obj)
            self._emitted_step_ids.add(step.step_id)
            offset += 1
            log.info(
                "playbook proposed %s (mitre=%s, priority=%d)",
                obj.id, step.mitre_id, obj.priority,
            )
        return out
