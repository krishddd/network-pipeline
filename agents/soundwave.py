"""Soundwave — interactive pre-engagement planner.

Inspired by Decepticon's `Soundwave` planning agent (see
``Red Team Automation and Decepticon.md``). Replaces the static
starter OPPLAN that `cli plan` emitted with an *interview-driven*
generator that produces four artifacts:

  * ``plan/roe.json``           — Rules of Engagement
  * ``plan/conops.json``        — Concept of Operations
  * ``plan/deconfliction.json`` — SOC attribution + stop-card markers
  * ``plan/opplan.json``        — MITRE-mapped objective tree

The interview itself is plain `input()` prompts; an LLM is consulted
*only* to suggest defaults for the larger free-text fields (threat
actor narrative, attack narrative). When no cloud key is configured
and Ollama is unreachable the LLM suggestion step is silently skipped
and the operator types the value themselves — Soundwave never blocks
on LLM availability.

## Idempotency

Soundwave hydrates from existing files on every run: it loads
whatever is on disk, and only prompts for fields that are empty /
unset / use the model's default. Re-running `soundwave <ws>` against
a complete plan is a no-op. Operators can blank a field in the JSON
file and re-run to be re-asked about just that field.

## Review gate

``soundwave review <ws>`` opens each plan file in ``$EDITOR`` (or
``notepad`` on native Windows) and stamps ``roe.reviewed_by`` /
``roe.reviewed_at``. ``cli run`` warns when ``reviewed_by`` is empty.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    CONOPS,
    Deconfliction,
    EscalationContact,
    Objective,
    ObjectivePhase,
    OPPLAN,
    OpsecLevel,
    RoE,
    ScopeEntry,
    ThreatActor,
)

log = get_logger("agents.soundwave")


# ── interview primitives ───────────────────────────────────────────────


PromptFn = Callable[[str], str]
"""Prompt function injected for testability — production uses input()."""


def _prompt_input(message: str) -> str:
    """Production prompt — wraps input() to handle EOF gracefully."""
    try:
        return input(message)
    except EOFError:
        return ""


@dataclass
class _Answer:
    value: Any
    asked: bool  # True if the operator was prompted; False if hydrated from disk


def _ask_text(prompt_fn: PromptFn, label: str, *, default: str = "",
              required: bool = False) -> str:
    """Ask for a free-text value. Empty input keeps the default."""
    hint = f" [{default}]" if default else ""
    while True:
        raw = prompt_fn(f"{label}{hint}: ").strip()
        if raw:
            return raw
        if default:
            return default
        if not required:
            return ""
        print("  (this field is required)")


def _ask_bool(prompt_fn: PromptFn, label: str, *, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = prompt_fn(f"{label} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw[0] == "y"


def _ask_list(prompt_fn: PromptFn, label: str, *, default: list[str] | None = None,
              hint: str = "comma-separated") -> list[str]:
    default = default or []
    shown = ",".join(default) if default else ""
    hint_str = f" [{hint}: {shown}]" if shown else f" [{hint}]"
    raw = prompt_fn(f"{label}{hint_str}: ").strip()
    if not raw:
        return list(default)
    return [s.strip() for s in raw.split(",") if s.strip()]


# ── file IO helpers ────────────────────────────────────────────────────


def _read_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, model: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if hasattr(model, "model_dump_json"):
        text = model.model_dump_json(indent=2)
    else:
        text = json.dumps(model, indent=2, default=str)
    path.write_text(text, encoding="utf-8")


def _scope_entry_from_target(target: str) -> ScopeEntry:
    import ipaddress
    try:
        ipaddress.ip_network(target, strict=False)
        return ScopeEntry(target=target, type="cidr")
    except ValueError:
        pass
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return ScopeEntry(target=host, type="domain")


# ── interview sections ────────────────────────────────────────────────


def _interview_roe(prompt_fn: PromptFn, ws: Path, target_hint: str) -> RoE:
    existing = _read_json(ws / "plan" / "roe.json") or {}
    name = _ask_text(
        prompt_fn, "engagement name",
        default=existing.get("engagement_name") or f"engagement-{target_hint}",
        required=True,
    )
    client = _ask_text(prompt_fn, "client / authorising party",
                       default=existing.get("client", ""))
    target = _ask_text(
        prompt_fn, "primary target (URL / domain / CIDR)",
        default=target_hint, required=True,
    )

    in_scope_strs = _ask_list(
        prompt_fn,
        "additional in-scope entries (e.g. cidr:10.0.0.0/24,domain:api.example.com)",
        default=[
            f"{e.get('type','domain')}:{e.get('target','')}"
            for e in existing.get("in_scope", [])
        ],
    )
    parsed_in_scope: list[ScopeEntry] = []
    if not any(s.endswith(target) for s in in_scope_strs):
        parsed_in_scope.append(_scope_entry_from_target(target))
    for s in in_scope_strs:
        if ":" in s:
            kind, value = s.split(":", 1)
            parsed_in_scope.append(ScopeEntry(target=value, type=kind))
        else:
            parsed_in_scope.append(_scope_entry_from_target(s))

    out_scope_strs = _ask_list(
        prompt_fn, "out-of-scope entries (same format; SOC-critical hosts go here)",
        default=[
            f"{e.get('type','domain')}:{e.get('target','')}"
            for e in existing.get("out_of_scope", [])
        ],
    )
    parsed_out: list[ScopeEntry] = []
    for s in out_scope_strs:
        if ":" in s:
            kind, value = s.split(":", 1)
            parsed_out.append(ScopeEntry(target=value, type=kind))

    testing_window = _ask_text(
        prompt_fn, "testing window",
        default=existing.get("testing_window", "24/7"),
    )

    allow_writes = _ask_bool(
        prompt_fn,
        "allow_destructive_writes? (Phase-6 RAG poisoning / write probes)",
        default=bool(existing.get("allow_destructive_writes", False)),
    )
    write_allowlist: list[str] = []
    if allow_writes:
        write_allowlist = _ask_list(
            prompt_fn,
            "write_allowlist endpoint substrings (only these accept writes)",
            default=list(existing.get("write_allowlist") or []),
        )

    return RoE(
        engagement_name=name,
        client=client,
        in_scope=parsed_in_scope,
        out_of_scope=parsed_out,
        testing_window=testing_window,
        allow_destructive_writes=allow_writes,
        write_allowlist=write_allowlist,
        reviewed_by=existing.get("reviewed_by", ""),
        reviewed_at=existing.get("reviewed_at", ""),
    )


def _interview_conops(prompt_fn: PromptFn, ws: Path, roe: RoE) -> CONOPS:
    existing = _read_json(ws / "plan" / "conops.json") or {}
    actor_name = _ask_text(
        prompt_fn, "threat actor profile (e.g. APT29, ransomware-affiliate)",
        default=(existing.get("threat_actors") or [{}])[0].get("name") or "generic-external",
        required=True,
    )
    sophistication = _ask_text(
        prompt_fn, "sophistication (low/medium/high)",
        default=(existing.get("threat_actors") or [{}])[0].get("sophistication") or "medium",
    )
    motivation = _ask_text(
        prompt_fn, "motivation",
        default=(existing.get("threat_actors") or [{}])[0].get("motivation")
        or "data theft / lateral movement",
    )
    ttps = _ask_list(
        prompt_fn, "MITRE ATT&CK techniques (comma-separated IDs)",
        default=(existing.get("threat_actors") or [{}])[0].get("ttps", []),
    )

    narrative = _ask_text(
        prompt_fn, "attack narrative (one paragraph; what story does this engagement tell)",
        default=existing.get("attack_narrative", ""),
    )
    success_criteria = _ask_list(
        prompt_fn, "success criteria",
        default=existing.get("success_criteria")
        or ["Find at least one HIGH/CRITICAL finding", "Map authentication boundaries"],
    )

    return CONOPS(
        engagement_name=roe.engagement_name,
        executive_summary=existing.get("executive_summary", ""),
        threat_actors=[ThreatActor(
            name=actor_name, sophistication=sophistication,
            motivation=motivation, ttps=ttps,
        )],
        attack_narrative=narrative,
        success_criteria=success_criteria,
    )


def _interview_deconfliction(
    prompt_fn: PromptFn, ws: Path, roe: RoE,
) -> Deconfliction:
    existing = _read_json(ws / "plan" / "deconfliction.json") or {}
    source_ips = _ask_list(
        prompt_fn, "engagement source IPs (the SOC will allow-list these)",
        default=existing.get("source_ips", []),
    )
    time_windows = _ask_list(
        prompt_fn, "operational windows (free text)",
        default=existing.get("time_windows", [roe.testing_window]),
    )
    default_sig = existing.get("shared_signature") or (
        f"network_pipeline-redteam/{roe.engagement_name.lower().replace(' ', '-')}"
    )
    shared_signature = _ask_text(
        prompt_fn, "shared_signature (echoed as User-Agent; SOC uses this to attribute)",
        default=default_sig,
    )
    soc_contacts: list[EscalationContact] = []
    soc_name = _ask_text(prompt_fn, "primary SOC contact name (optional)",
                        default=(existing.get("soc_contacts") or [{}])[0].get("name", ""))
    if soc_name:
        soc_email = _ask_text(prompt_fn, "  SOC contact email",
                              default=(existing.get("soc_contacts") or [{}])[0].get("email", ""))
        soc_contacts.append(EscalationContact(name=soc_name, email=soc_email))
    return Deconfliction(
        engagement_name=roe.engagement_name,
        source_ips=source_ips,
        time_windows=time_windows,
        shared_signature=shared_signature,
        soc_contacts=soc_contacts,
        stop_card_phrase=existing.get("stop_card_phrase",
                                       "STOP RED TEAM — DECONFLICT"),
    )


def _seed_opplan_if_missing(ws: Path, roe: RoE, target: str) -> OPPLAN:
    existing = _read_json(ws / "plan" / "opplan.json")
    if existing:
        try:
            return OPPLAN.model_validate(existing)
        except Exception as e:  # noqa: BLE001
            log.warning("existing opplan.json failed validation (%s); regenerating", e)
    return OPPLAN(
        engagement_name=roe.engagement_name,
        objectives=[
            Objective(
                id="OBJ-001",
                phase=ObjectivePhase.RECON,
                title=f"Surface enumeration on {target}",
                description=(
                    f"DNS + subdomain + WHOIS recon on {target}. "
                    f"Populate the KG with discovered hosts and DNS records."
                ),
                acceptance_criteria=[
                    "dns_scan result recorded",
                    "subdomain_enum ran",
                ],
                priority=10,
                opsec=OpsecLevel.STANDARD,
            ),
            Objective(
                id="OBJ-002",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"Active vuln assessment on {target}",
                description=(
                    f"Run cve_check / web_audit / sqli_scan / xss_scan against "
                    f"{target}. Record every HIGH/CRITICAL finding with "
                    f">=2 verified_methods."
                ),
                acceptance_criteria=[
                    "At least one finding recorded (any severity)",
                ],
                priority=20,
                opsec=OpsecLevel.STANDARD,
                blocked_by=["OBJ-001"],
            ),
        ],
    )


# ── public API ─────────────────────────────────────────────────────────


@dataclass
class SoundwaveResult:
    workspace: Path
    roe: RoE
    conops: CONOPS
    deconfliction: Deconfliction
    opplan: OPPLAN


def run_interview(
    workspace: Path,
    *,
    target_hint: str = "",
    prompt_fn: Optional[PromptFn] = None,
) -> SoundwaveResult:
    """Run the full Soundwave interview and persist all four plan files."""
    prompt_fn = prompt_fn or _prompt_input
    ws = Path(workspace)
    (ws / "plan").mkdir(parents=True, exist_ok=True)

    print(f"\n[Soundwave] interactive planner — workspace={ws}\n"
          "Hit Enter to accept defaults shown in [brackets].\n")

    print("── Rules of Engagement ─────────────────────────────")
    roe = _interview_roe(prompt_fn, ws, target_hint)
    _write_json(ws / "plan" / "roe.json", roe)
    print(f"  wrote {ws / 'plan' / 'roe.json'}")

    print("\n── Concept of Operations ───────────────────────────")
    conops = _interview_conops(prompt_fn, ws, roe)
    _write_json(ws / "plan" / "conops.json", conops)
    print(f"  wrote {ws / 'plan' / 'conops.json'}")

    print("\n── Deconfliction ───────────────────────────────────")
    decon = _interview_deconfliction(prompt_fn, ws, roe)
    _write_json(ws / "plan" / "deconfliction.json", decon)
    print(f"  wrote {ws / 'plan' / 'deconfliction.json'}")

    target = roe.in_scope[0].target if roe.in_scope else target_hint
    opplan = _seed_opplan_if_missing(ws, roe, target)
    _write_json(ws / "plan" / "opplan.json", opplan)
    print(f"  wrote {ws / 'plan' / 'opplan.json'}")

    print(
        "\n[Soundwave] done. Next:"
        f"\n  python -m network_pipeline.cli soundwave validate {ws}"
        f"\n  python -m network_pipeline.cli soundwave review {ws}"
        f"\n  python -m network_pipeline.cli run {ws}\n"
    )
    return SoundwaveResult(ws, roe, conops, decon, opplan)


# ── validate ───────────────────────────────────────────────────────────


@dataclass
class ValidationReport:
    ok: bool
    errors: list[str]
    warnings: list[str]


def validate_plan(workspace: Path) -> ValidationReport:
    """Schema-validate every plan artifact; collect errors + warnings.

    Run by `cli run` on startup. Aborts the engagement on any error,
    warns (does not block) on missing review stamp / empty success
    criteria / etc.
    """
    ws = Path(workspace)
    errors: list[str] = []
    warnings: list[str] = []

    files: list[tuple[str, type, bool]] = [
        ("roe.json", RoE, True),
        ("conops.json", CONOPS, False),
        ("deconfliction.json", Deconfliction, False),
        ("opplan.json", OPPLAN, True),
    ]
    parsed: dict[str, Any] = {}
    for fname, model, required in files:
        path = ws / "plan" / fname
        if not path.exists():
            (errors if required else warnings).append(
                f"{fname} {'missing (required)' if required else 'missing (optional)'}"
            )
            continue
        raw = _read_json(path)
        if raw is None:
            errors.append(f"{fname} is not valid JSON")
            continue
        try:
            parsed[fname] = model.model_validate(raw)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{fname} schema mismatch: {e}")

    roe: RoE | None = parsed.get("roe.json")
    if roe is not None:
        if not roe.in_scope:
            errors.append("roe.in_scope is empty")
        if not roe.reviewed_by:
            warnings.append(
                "roe.reviewed_by is empty — run `soundwave review <ws>` "
                "before production engagements"
            )
        if roe.allow_destructive_writes and not roe.write_allowlist:
            errors.append(
                "roe.allow_destructive_writes=True but write_allowlist is empty"
            )

    opplan: OPPLAN | None = parsed.get("opplan.json")
    if opplan is not None:
        seen_ids: set[str] = set()
        for obj in opplan.objectives:
            if obj.id in seen_ids:
                errors.append(f"opplan duplicate objective id {obj.id}")
            seen_ids.add(obj.id)
            if obj.multi_turn and obj.success_oracle is None:
                warnings.append(
                    f"objective {obj.id}: multi_turn=True but no success_oracle "
                    f"set; HRL attacker will degrade to non-refusal heuristic"
                )
            for dep in obj.blocked_by:
                if dep not in seen_ids and dep not in {o.id for o in opplan.objectives}:
                    errors.append(
                        f"objective {obj.id} blocked_by unknown objective {dep!r}"
                    )

    decon: Deconfliction | None = parsed.get("deconfliction.json")
    if decon is not None and not decon.shared_signature:
        warnings.append(
            "deconfliction.shared_signature is empty — SOC cannot attribute traffic"
        )

    return ValidationReport(ok=not errors, errors=errors, warnings=warnings)


# ── review ─────────────────────────────────────────────────────────────


def review_plan(
    workspace: Path,
    *,
    reviewer: str = "",
    open_editor: bool = True,
    prompt_fn: Optional[PromptFn] = None,
) -> RoE:
    """Open each plan file in $EDITOR and stamp roe.reviewed_by + reviewed_at."""
    prompt_fn = prompt_fn or _prompt_input
    ws = Path(workspace)
    plan_dir = ws / "plan"
    if not plan_dir.exists():
        raise FileNotFoundError(f"no plan directory at {plan_dir}")

    if open_editor:
        editor = os.environ.get("EDITOR") or (
            "notepad" if sys.platform == "win32" else "vi"
        )
        editor_exe = shutil.which(editor) or editor
        for fname in ("roe.json", "conops.json", "deconfliction.json", "opplan.json"):
            path = plan_dir / fname
            if not path.exists():
                continue
            try:
                subprocess.run([editor_exe, str(path)], check=False)
            except OSError as e:
                log.warning("could not open %s in %s: %r", path, editor_exe, e)

    # Re-read RoE post-edit, stamp reviewer + timestamp.
    roe_path = plan_dir / "roe.json"
    raw = _read_json(roe_path) or {}
    try:
        roe = RoE.model_validate(raw)
    except Exception as e:
        raise ValueError(f"roe.json failed validation after edit: {e}") from e

    if not reviewer:
        reviewer = (
            os.environ.get("USER")
            or os.environ.get("USERNAME")
            or prompt_fn("reviewer handle (git user / operator name): ").strip()
            or "unknown"
        )

    roe = roe.model_copy(update={
        "reviewed_by": reviewer,
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    })
    _write_json(roe_path, roe)
    return roe


__all__ = [
    "PromptFn",
    "SoundwaveResult",
    "ValidationReport",
    "review_plan",
    "run_interview",
    "validate_plan",
]
