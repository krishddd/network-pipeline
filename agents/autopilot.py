"""Autopilot — one-prompt autonomous engagement.

The user gives a single sentence ("test the LLM chatbot at
http://localhost:3000, my scope is anything on that host"); autopilot
synthesises the full pre-engagement package (RoE / CONOPS /
Deconfliction / OPPLAN), runs `cli auto` end-to-end, and only stops
to ask a question when the loop hits an *ambiguity it can't resolve
on its own*.

## Human-in-the-loop question protocol

When the autopilot or any sub-agent needs an answer, the agent writes
``plan/question.json``::

    {
      "id": "Q-001",
      "phase": "planning|attack|vaccine",
      "asked_at": "2026-05-26T13:00:00Z",
      "question": "...",
      "default": "...",        # optional, applied if no answer in N seconds
      "timeout_seconds": 0     # 0 = wait forever
    }

…and triggers a pause (same `plan/pause.flag` machinery as Phase-8).
The autopilot CLI loop polls for ``plan/answer.txt``; once present
(or the timeout fires) it deletes both files and resumes via the
existing pause-resume path. No other agent code changes are needed —
the question file is metadata for the operator and the autopilot's
console.

The autopilot is intentionally a *runtime orchestrator*, not a new
agent: it composes the existing `soundwave`, `run`, `report` paths
so we get all phase 1-8 features for free.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    CONOPS,
    Deconfliction,
    Objective,
    ObjectivePhase,
    OPPLAN,
    OpsecLevel,
    RoE,
    ScopeEntry,
    ThreatActor,
)

log = get_logger("agents.autopilot")


# ── prompt parsing (heuristics, no LLM required) ──────────────────────


# Regex shortlist for picking a target out of free text.
_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_DOMAIN_RE = re.compile(
    r"\b(?=.{1,253}\b)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b",
)


@dataclass
class ParsedPrompt:
    target: str = ""
    target_kind: str = "domain"   # url | domain | cidr
    target_type: str = "network"  # network | llm
    extra_in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    name_hint: str = ""
    keywords: set[str] = field(default_factory=set)


def parse_prompt(text: str) -> ParsedPrompt:
    """Best-effort extraction of target + intent from a single sentence."""
    out = ParsedPrompt()
    lower = text.lower()

    # Target detection — URL beats CIDR beats domain.
    url_match = _URL_RE.search(text)
    if url_match:
        out.target = url_match.group(0).rstrip(".,;)")
        out.target_kind = "url"
    else:
        cidr_match = _CIDR_RE.search(text)
        if cidr_match:
            out.target = cidr_match.group(0)
            out.target_kind = "cidr" if "/" in out.target else "ip"
        else:
            dom_match = _DOMAIN_RE.search(text)
            if dom_match:
                out.target = dom_match.group(0).rstrip(".")
                out.target_kind = "domain"

    # LLM vs network.
    llm_markers = (
        "llm", "chatbot", "chat-bot", "assistant", "rag", "ai app",
        "gen-ai", "genai", "prompt injection", "jailbreak",
    )
    if any(m in lower for m in llm_markers):
        out.target_type = "llm"

    # Naming hint from the prompt's leading nouns.
    leading = text.strip().split(".", 1)[0]
    out.name_hint = re.sub(r"[^A-Za-z0-9_\- ]", "", leading)[:60].strip() or "autopilot-engagement"

    # Simple keyword extraction for downstream prompts.
    for kw in (
        "owasp", "sqli", "xss", "auth", "rag", "jailbreak", "prompt-injection",
        "supply-chain", "rce", "ssrf", "idor", "graphql",
    ):
        if kw.replace("-", " ") in lower or kw.replace("-", "") in lower:
            out.keywords.add(kw)

    return out


# ── default plan synthesis (no-LLM fallback) ──────────────────────────


def _default_roe(parsed: ParsedPrompt) -> RoE:
    entries: list[ScopeEntry] = []
    if parsed.target:
        if parsed.target_kind in ("url", "domain"):
            # URL → bare host.
            host = parsed.target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            entries.append(ScopeEntry(target=host, type="domain"))
        elif parsed.target_kind in ("cidr", "ip"):
            entries.append(ScopeEntry(target=parsed.target, type="cidr"))
    for extra in parsed.extra_in_scope:
        if ":" in extra:
            kind, value = extra.split(":", 1)
            entries.append(ScopeEntry(target=value, type=kind))
    return RoE(
        engagement_name=f"autopilot-{parsed.name_hint}",
        in_scope=entries,
        out_of_scope=[
            ScopeEntry(target=v.split(":", 1)[-1],
                       type=v.split(":", 1)[0] if ":" in v else "domain")
            for v in parsed.out_of_scope
        ],
        # Defaults safe for unattended use; ops can edit the JSON after.
        allow_destructive_writes=False,
        write_allowlist=[],
    )


def _default_conops(parsed: ParsedPrompt, roe: RoE) -> CONOPS:
    actor = ThreatActor(
        name="autopilot-blackbox-external" if parsed.target_type == "network"
        else "autopilot-prompt-injection-attacker",
        sophistication="medium",
        motivation="discover and verify the highest-impact weakness",
        ttps=sorted(parsed.keywords) or ["T1190", "T1059"],
    )
    return CONOPS(
        engagement_name=roe.engagement_name,
        attack_narrative=(
            f"Autopilot run against {roe.in_scope[0].target if roe.in_scope else parsed.target!r}. "
            f"Target type: {parsed.target_type}. "
            f"Mission: identify and verify the highest-confidence finding "
            f"the available scanners can produce, escalating from passive recon "
            f"to active exploit only after the prior phase succeeds."
        ),
        threat_actors=[actor],
        success_criteria=[
            "At least one verified finding (any severity) is recorded.",
            "All planned objectives completed or marked BLOCKED with a reason.",
        ],
    )


def _default_deconfliction(roe: RoE) -> Deconfliction:
    sig = f"network_pipeline-redteam/{roe.engagement_name.lower().replace(' ', '-')}"
    return Deconfliction(
        engagement_name=roe.engagement_name,
        source_ips=[],
        time_windows=["24/7"],
        shared_signature=sig,
        soc_contacts=[],
    )


def _default_opplan(parsed: ParsedPrompt, roe: RoE) -> OPPLAN:
    target = roe.in_scope[0].target if roe.in_scope else parsed.target
    target_url = parsed.target if parsed.target_kind == "url" else f"http://{target}"

    if parsed.target_type == "llm":
        return OPPLAN(
            engagement_name=roe.engagement_name,
            objectives=[
                Objective(
                    id="OBJ-001", phase=ObjectivePhase.LLM_REDTEAM,
                    title=f"LLM-target probe + jailbreak chain against {target_url}",
                    description=(
                        f"Run prompt_injection corpus, persona_probe, then "
                        f"jailbreak_cop against {target_url}. Skip rag_poisoning "
                        f"unless the operator set allow_destructive_writes."
                    ),
                    acceptance_criteria=[
                        "data.attempts > 0 across the LLM scanners",
                        "asr_score recorded",
                    ],
                    priority=10,
                    opsec=OpsecLevel.STANDARD,
                ),
            ],
        )

    return OPPLAN(
        engagement_name=roe.engagement_name,
        objectives=[
            Objective(
                id="OBJ-001", phase=ObjectivePhase.RECON,
                title=f"Surface enumeration on {target}",
                description=(
                    f"DNS + subdomain + WHOIS + supply-chain inventory on "
                    f"{target}. Populate KG with hosts, DNS records, and any "
                    f"exposed dependency manifests."
                ),
                acceptance_criteria=[
                    "dns_scan or subdomain_enum recorded",
                    "supply_chain_inventory attempted",
                ],
                priority=10,
            ),
            Objective(
                id="OBJ-002", phase=ObjectivePhase.SCAN,
                title=f"Port + HTTP probing on {target}",
                description=(
                    f"Run port_scan + http_probe + tls_audit against "
                    f"{target} to map the active attack surface."
                ),
                acceptance_criteria=[
                    "≥1 service discovered (port or HTTP)",
                ],
                priority=20,
                blocked_by=["OBJ-001"],
            ),
            Objective(
                id="OBJ-003", phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"Active vulnerability assessment on {target}",
                description=(
                    f"Run cve_check / web_audit / sqli_scan / xss_scan / "
                    f"auth_audit against {target}. Record every finding."
                ),
                acceptance_criteria=[
                    "≥1 finding recorded (any severity)",
                ],
                priority=30,
                blocked_by=["OBJ-002"],
            ),
        ],
    )


# ── LLM-assisted enrichment (optional) ────────────────────────────────


# Soundwave already produces all four files via interactive prompts;
# the autopilot calls it with a script that takes every default. When
# a cloud key is configured we ALSO tweak the CONOPS narrative + the
# OPPLAN objective titles with a one-shot LLM call so the report reads
# like a human authored it. Falls back silently when no provider is
# available.


def _llm_polish_narrative(conops: CONOPS, parsed: ParsedPrompt) -> CONOPS:
    """Best-effort: ask an LLM to rewrite the narrative in two sentences.

    No-op when no providers are configured — autopilot stays useful
    on a totally-offline machine.
    """
    try:
        from network_pipeline.llm.credentials import available_providers
        statuses = available_providers("http://localhost:11434")
        if not any(s.available for s in statuses.values()):
            return conops
    except Exception:
        return conops
    # Conservative: keep the default narrative. A network-touching call
    # here would slow autopilot on every run; the narrative is metadata.
    return conops


# ── plan synthesis entry point ────────────────────────────────────────


def synthesise_plan(
    parsed: ParsedPrompt,
    workspace: Path,
) -> tuple[RoE, CONOPS, Deconfliction, OPPLAN]:
    """Produce all four plan artifacts deterministically from a parsed prompt."""
    ws = Path(workspace)
    (ws / "plan").mkdir(parents=True, exist_ok=True)

    roe = _default_roe(parsed)
    conops = _llm_polish_narrative(_default_conops(parsed, roe), parsed)
    decon = _default_deconfliction(roe)
    opplan = _default_opplan(parsed, roe)

    (ws / "plan" / "roe.json").write_text(roe.model_dump_json(indent=2), encoding="utf-8")
    (ws / "plan" / "conops.json").write_text(conops.model_dump_json(indent=2), encoding="utf-8")
    (ws / "plan" / "deconfliction.json").write_text(decon.model_dump_json(indent=2), encoding="utf-8")
    (ws / "plan" / "opplan.json").write_text(opplan.model_dump_json(indent=2), encoding="utf-8")
    return roe, conops, decon, opplan


# ── question protocol ────────────────────────────────────────────────


def pending_question(workspace: Path) -> Optional[dict]:
    """Return the contents of ``plan/question.json`` or None."""
    q = Path(workspace) / "plan" / "question.json"
    if not q.exists():
        return None
    try:
        return json.loads(q.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def submit_answer(workspace: Path, answer: str) -> None:
    """Write the operator's answer + clear the question + pause flag."""
    ws = Path(workspace)
    (ws / "plan" / "answer.txt").write_text(answer, encoding="utf-8")
    for fname in ("question.json", "pause.flag"):
        p = ws / "plan" / fname
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass


def consume_answer(workspace: Path) -> Optional[str]:
    """Sub-agent helper — read + delete the answer file."""
    p = Path(workspace) / "plan" / "answer.txt"
    if not p.exists():
        return None
    try:
        ans = p.read_text(encoding="utf-8")
        p.unlink()
        return ans
    except OSError:
        return None


def ask_operator(
    workspace: Path,
    *,
    question: str,
    default: str = "",
    timeout_seconds: int = 0,
    phase: str = "planning",
) -> dict:
    """Sub-agents call this to surface a question + trigger a pause.

    The autopilot CLI loop is responsible for polling, prompting the
    operator, and writing ``answer.txt``. Returns the question dict
    that was written so the caller has the id for correlation.
    """
    ws = Path(workspace)
    (ws / "plan").mkdir(parents=True, exist_ok=True)
    qpath = ws / "plan" / "question.json"
    qid = f"Q-{int(time.time())}"
    payload = {
        "id": qid,
        "phase": phase,
        "asked_at": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "default": default,
        "timeout_seconds": timeout_seconds,
    }
    qpath.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    # Trigger the pause mechanism so the engagement loop checkpoints.
    (ws / "plan" / "pause.flag").write_text(
        f"question {qid} pending operator answer\n", encoding="utf-8",
    )
    return payload


# ── autopilot driver ─────────────────────────────────────────────────


@dataclass
class AutopilotConfig:
    prompt: str
    workspace: Path
    # Empty profile → auto-pick via llm.credentials.auto_profile(). The
    # operator only needs to set OPENAI_API_KEY (in .env or shell) and
    # the autopilot will resolve to openai_only on its own.
    profile: str = ""
    budget_usd: Optional[float] = None
    max_iterations: int = 20
    iteration_timeout: int = 600
    structured_reasoning: bool = True
    cop_enabled: bool = True
    auto_answer_defaults: bool = True
    """When True the autopilot answers questions with the default after the timeout."""

    def resolved_profile(self) -> str:
        """Pick a sensible default when ``profile`` is empty."""
        if self.profile:
            return self.profile
        from network_pipeline.llm.credentials import auto_profile
        return auto_profile()


@dataclass
class AutopilotResult:
    parsed: ParsedPrompt
    workspace: Path
    plan: tuple[RoE, CONOPS, Deconfliction, OPPLAN]
    engagement_summary: dict
    questions_answered: int = 0


async def _run_engagement_with_question_loop(
    cfg: AutopilotConfig,
    on_question: Optional[Callable[[dict], str]] = None,
) -> dict:
    """Run the engagement loop; whenever a question.json appears, hand
    it to ``on_question`` (or auto-answer with the default), write
    answer.txt, and let the next ``cli run`` pick up via pause/resume."""
    from network_pipeline.core.engagement import EngagementConfig
    from network_pipeline.core.engagement_loop import EngagementLoop

    ws = Path(cfg.workspace)
    config = EngagementConfig(
        target="",  # filled in by RoE-derived target inside loop
        workspace=ws,
        max_iterations=cfg.max_iterations,
        iteration_max_seconds=cfg.iteration_timeout,
        profile=cfg.resolved_profile(),
        budget_usd=cfg.budget_usd,
        structured_reasoning=cfg.structured_reasoning,
        cop_enabled=cfg.cop_enabled,
    )
    # Hydrate config.target as a fully-qualified URL — scheme AND port
    # preserved. Bug-fix history:
    #   - First bug: scanners need a scheme (http://) or httpx 0.28
    #     raises UnsupportedProtocol on every call.
    #   - Second bug: stripping the port (split(":", 1)[0]) turned
    #     "http://localhost:3000" into "http://localhost" so every
    #     scanner ConnectError-failed against Juice Shop.
    #
    # Priority: parsed URL from the prompt (preserves scheme+port)
    # → RoE in_scope[0].target (bare host) wrapped in http:// fallback.
    try:
        parsed_prompt = parse_prompt(cfg.prompt)
        if parsed_prompt.target_kind == "url" and parsed_prompt.target:
            # Parsed URL keeps scheme + port; use it verbatim.
            config.target = parsed_prompt.target
        else:
            roe = RoE.model_validate_json(
                (ws / "plan" / "roe.json").read_text(encoding="utf-8"),
            )
            if roe.in_scope:
                raw = roe.in_scope[0].target
                config.target = (
                    raw if raw.startswith(("http://", "https://"))
                    else f"http://{raw.lstrip('/')}"
                )
    except Exception:
        pass

    questions_answered = 0
    while True:
        try:
            loop = EngagementLoop(config)
            state = await loop.run()
        except Exception as e:  # noqa: BLE001
            log.warning("engagement loop raised: %r — checking for question", e)
            state = None

        question = pending_question(ws)
        if question is None:
            return state.summary if state else {"phase": "error"}

        # A question is pending — resolve it.
        log.info("autopilot: question %s requires an answer", question.get("id"))
        if on_question is not None:
            answer = on_question(question)
        elif cfg.auto_answer_defaults:
            answer = str(question.get("default", ""))
            log.warning("autopilot: auto-answering with default %r", answer)
        else:
            log.error("question pending and no handler / default — stopping")
            return state.summary if state else {"phase": "blocked", "reason": "question_unanswered"}

        submit_answer(ws, answer)
        questions_answered += 1
        # Loop iterates → engagement resumes from pause checkpoint.


async def run_autopilot(
    cfg: AutopilotConfig,
    on_question: Optional[Callable[[dict], str]] = None,
) -> AutopilotResult:
    """Full autonomous flow: parse → plan → run → answer-loop → return."""
    parsed = parse_prompt(cfg.prompt)
    if not parsed.target:
        raise ValueError(
            "could not extract a target from the prompt; include a URL, "
            "domain, or CIDR explicitly."
        )
    plan = synthesise_plan(parsed, cfg.workspace)
    summary = await _run_engagement_with_question_loop(cfg, on_question)
    return AutopilotResult(
        parsed=parsed,
        workspace=cfg.workspace,
        plan=plan,
        engagement_summary=summary,
    )


__all__ = [
    "AutopilotConfig",
    "AutopilotResult",
    "ParsedPrompt",
    "ask_operator",
    "consume_answer",
    "parse_prompt",
    "pending_question",
    "run_autopilot",
    "submit_answer",
    "synthesise_plan",
]
