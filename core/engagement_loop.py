"""Ralph-mode async engagement loop.

System-level while-loop that drives the engagement across objectives.
Each iteration invokes a fresh sub-agent (selected by the objective's
phase) with its own context, preventing message-history bloat across
iterations. Filesystem state (``opplan.json``, ``kg.json``,
``findings.jsonl``) is the durable memory.

Two autonomous phases (planning is handled out-of-band by the CLI
calling the orchestrator interactively):
    ATTACK  — iterate OPPLAN objectives until done
    VACCINE — defender reviews findings, emits defense_brief.json
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from network_pipeline.agents.defender import create_defender_agent
from network_pipeline.agents.orchestrator import load_opplan, save_opplan
from network_pipeline.agents.registry import discover as discover_agents
from network_pipeline.agents.verifier import create_verifier_agent
from network_pipeline.core.config import init_workspace
from network_pipeline.core.engagement import (
    EngagementConfig,
    EngagementPhase,
    EngagementState,
    IterationResult,
    snapshot_state,
)
from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import (
    Objective,
    ObjectiveStatus,
)
from network_pipeline.core.synthesis import synthesize_from_kg_delta
from network_pipeline.llm import OllamaLLMFactory
from network_pipeline.tools.kg import FindingsLog, KnowledgeGraph
from network_pipeline.tools.runtime import HTTPClient, DNSClient, ScopeGuard

log = get_logger("core.engagement_loop")


# Discovered once at import time: ObjectivePhase → (role, factory).
# Any module in ``network_pipeline.agents`` that exposes AGENT_ROLE +
# SUPPORTED_PHASES + create_<role>_agent is picked up automatically,
# including third-party drop-ins. See ``agents/registry.py``.
_AGENT_FACTORIES = discover_agents()


class EngagementLoop:
    def __init__(self, config: EngagementConfig) -> None:
        self._config = config
        self._workspace = config.workspace
        layout = init_workspace(self._workspace)
        self._kg = KnowledgeGraph(layout["kg"])
        self._findings = FindingsLog(layout["findings_jsonl"])
        # Multi-provider factory (Ollama / OpenAI / Anthropic). Provider
        # selection is driven by the profile; `provider_overrides` pins a
        # specific role to a specific provider when the operator wants to
        # force the assignment (e.g. exploit → local ollama qwen-coder
        # even when running --profile cloud_max).
        self._factory = OllamaLLMFactory(
            base_url=config.ollama_base_url,
            profile=config.profile,
            provider_overrides=config.provider_overrides or None,
            openai_base_url=config.openai_base_url,
            anthropic_base_url=config.anthropic_base_url,
        )
        # Wire the cost tracker's budget cap and a stderr live-emit hook.
        # The CLI swaps the emit hook for a rich.live renderer when it's
        # running attached to a TTY; otherwise we print to stderr so log
        # captures still see the running total.
        from network_pipeline.llm.cost import configure as _configure_cost

        def _emit(line: str) -> None:
            import sys
            print(line, file=sys.stderr, flush=True)

        _configure_cost(budget_usd=config.budget_usd, live_emit=_emit)
        # RoE in_scope drives the shell scope guard. The full RoE is also
        # passed through to the runner so argv_guard can enforce
        # prohibited-action and paranoid-target rules per Plan B.4.3+B.4.4.
        roe_path = self._workspace / "plan" / "roe.json"
        scope = ScopeGuard()
        roe_obj = None
        if roe_path.exists():
            try:
                from network_pipeline.core.migrations import (
                    load_json_with_migration,
                )
                from network_pipeline.core.schemas import RoE
                payload = load_json_with_migration(roe_path, "roe")
                if payload is not None:
                    roe_obj = RoE.model_validate(payload)
                    scope = ScopeGuard.from_in_scope(roe_obj.in_scope)
            except Exception as e:
                log.warning("could not parse RoE: %s", e)
        self._roe = roe_obj
        # Phase-3: callback profile + adaptive router are opt-in via
        # marker files written by the CLI flags (so resume picks them
        # up automatically). Marker files live next to playbook.txt.
        self._callback_profile = self._load_callback_profile()
        # Phase-4: evidence chain — opt-in when ``hmac_key.txt`` marker
        # exists. The chain attaches to HTTPClient and the FindingsLog.
        self._evidence_chain = self._load_evidence_chain()
        # Pure-Python HTTP/DNS clients (one per engagement, shared across all agents)
        dns_ns = self._read_str_marker("dns_resolver.txt", default="")
        self._dns_client = DNSClient(
            scope=scope,
            evidence_chain=self._evidence_chain,
            nameservers=[s.strip() for s in dns_ns.split(",") if s.strip()] or None,
            workspace=self._workspace,
        )
        proxy = self._read_str_marker("proxy.txt", default="")
        # Phase-5: hydrate CONOPS + Deconfliction (if Soundwave produced
        # them) so the engagement loop can inject the threat-actor
        # profile into the orchestrator prompt and use
        # `shared_signature` as the default User-Agent (SOC attribution).
        self._conops, self._deconfliction = self._load_conops_and_deconfliction()
        user_agents: list[str] | None = None
        if self._deconfliction and self._deconfliction.shared_signature:
            user_agents = [self._deconfliction.shared_signature]
        # Persist the rendered block to a marker file so build_agent can
        # append it to the orchestrator's system prompt without
        # threading the string through every factory signature.
        block = self.conops_context_block()
        block_marker = self._workspace / "plan" / ".conops_context.txt"
        try:
            if block:
                block_marker.parent.mkdir(parents=True, exist_ok=True)
                block_marker.write_text(block, encoding="utf-8")
            elif block_marker.exists():
                block_marker.unlink()
        except OSError as e:
            log.warning("could not write conops context marker: %r", e)
        self._http_client = HTTPClient(
            scope=scope,
            roe=roe_obj,
            callback_profile=self._callback_profile,
            evidence_chain=self._evidence_chain,
            workspace=self._workspace,
            proxy=proxy or None,
            user_agents=user_agents,
        )
        # Keep a _runner=None for any legacy callers that expect the attribute
        self._runner = None
        self._state: EngagementState | None = None
        # Budget governor is created lazily once OPPLAN is loaded (it
        # owns the BudgetState that lives on the OPPLAN doc).
        self._budget = None
        # Playbook engine is opt-in. The CLI ``--playbook <name>`` flag
        # writes the chosen playbook path into ``workspace/plan/
        # playbook.txt`` so resume picks it up.
        self._playbook_engine = self._load_playbook_engine()
        # Phase-3 cognitive features
        self._adaptive_router = self._load_adaptive_router()
        self._tot_enabled = self._is_flag_set("tot.flag")
        self._critic_enabled = not self._is_flag_set("nocritic.flag")
        # Episodic + scratchpad memory tiers
        from network_pipeline.core.episodic import EpisodicMemory, Scratchpad
        self._episodic = EpisodicMemory(self._workspace)
        self._scratchpad = Scratchpad(self._workspace)
        # Phase-4: parallel supervisor + cross-engagement RAG + blue
        # telemetry directory. All opt-in via marker files written by
        # the CLI flags so resume picks them up.
        self._parallelism = self._read_int_marker("parallel.txt", default=1)
        self._rag = self._load_rag()
        self._blue_telemetry_dir = self._load_blue_dir()
        # Wire HMAC + chain into the FindingsLog so every appended
        # finding gets signed + leafed transparently.
        if self._evidence_chain is not None:
            self._findings.attach_chain(
                self._evidence_chain, hmac_key=self._evidence_chain.key,
            )

    def _is_flag_set(self, name: str) -> bool:
        """Return True when a marker file ``plan/<name>`` exists + is non-empty.

        The CLI writes one-line marker files for opt-in toggles so the
        engagement loop honours them on resume.
        """
        p = self._workspace / "plan" / name
        try:
            return p.exists() and p.read_text(encoding="utf-8").strip() == "1"
        except OSError:
            return False

    def _load_callback_profile(self):
        marker = self._workspace / "plan" / "c2_profile.txt"
        if not marker.exists():
            return None
        try:
            spec = marker.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not spec:
            return None
        try:
            from network_pipeline.core.c2_profile import load_callback_profile
            prof = load_callback_profile(spec)
            log.info(
                "c2_profile loaded: %s (sleep=%.1fs, jitter=%.0f%%)",
                prof.name, prof.sleep_s, prof.jitter_pct * 100,
            )
            return prof
        except Exception as e:
            log.warning("could not load c2_profile %r: %r", spec, e)
            return None

    def _read_int_marker(self, name: str, *, default: int) -> int:
        p = self._workspace / "plan" / name
        if not p.exists():
            return default
        try:
            v = int(p.read_text(encoding="utf-8").strip() or default)
            return max(1, min(8, v))
        except (OSError, ValueError):
            return default

    def _read_str_marker(self, name: str, *, default: str) -> str:
        p = self._workspace / "plan" / name
        if not p.exists():
            return default
        try:
            return p.read_text(encoding="utf-8").strip()
        except OSError:
            return default

    # ── Phase-8: HITL pause / resume ──────────────────────────────

    def _pause_flag_path(self) -> Path:
        return self._workspace / "plan" / "pause.flag"

    def _install_pause_handler(self) -> None:
        """Install a cross-platform SIGINT handler.

        On Unix we use ``loop.add_signal_handler`` (cleanest — runs in
        the asyncio loop). On Windows that API is unavailable, so we
        fall back to ``signal.signal`` which fires in the main thread
        — good enough since the pause check is a between-iteration
        poll, not a mid-task interrupt.

        The handler is idempotent: a second Ctrl+C while already
        paused does nothing (no infinite loop, no exception escape).
        """
        import signal
        import sys

        def _set_paused() -> None:
            if self._paused:
                # Second Ctrl+C — let the default handler raise so the
                # operator can force-kill. Restore default for SIGINT.
                signal.signal(signal.SIGINT, signal.default_int_handler)
                return
            self._paused = True
            log.warning("SIGINT received; will pause at next iteration boundary")

        if sys.platform == "win32":
            try:
                signal.signal(signal.SIGINT, lambda *_: _set_paused())
            except (ValueError, OSError):
                # Not in main thread — fall through silently.
                pass
            return

        # Unix path
        try:
            loop = asyncio.get_running_loop()
            loop.add_signal_handler(signal.SIGINT, _set_paused)
        except (NotImplementedError, RuntimeError, ValueError):
            # add_signal_handler isn't supported (Windows-style loop on
            # alt platforms, or signal cannot be set from this thread).
            try:
                signal.signal(signal.SIGINT, lambda *_: _set_paused())
            except (ValueError, OSError):
                pass

    def _load_conops_and_deconfliction(self):
        """Phase-5: read conops.json + deconfliction.json if Soundwave
        produced them. Returns (CONOPS|None, Deconfliction|None).

        Errors are non-fatal — a misshapen plan file produces a None and
        a warning, never a crash. ``soundwave validate`` is the gate
        that catches malformed files; this loader is best-effort.
        """
        from network_pipeline.core.schemas import CONOPS, Deconfliction

        conops_path = self._workspace / "plan" / "conops.json"
        decon_path = self._workspace / "plan" / "deconfliction.json"
        conops_obj = None
        decon_obj = None
        if conops_path.exists():
            try:
                conops_obj = CONOPS.model_validate_json(
                    conops_path.read_text(encoding="utf-8"),
                )
            except Exception as e:  # noqa: BLE001
                log.warning("conops.json present but unparseable: %r", e)
        if decon_path.exists():
            try:
                decon_obj = Deconfliction.model_validate_json(
                    decon_path.read_text(encoding="utf-8"),
                )
            except Exception as e:  # noqa: BLE001
                log.warning("deconfliction.json present but unparseable: %r", e)
        return conops_obj, decon_obj

    def conops_context_block(self) -> str:
        """Render CONOPS + Deconfliction into a system-prompt block.

        Empty when neither artifact exists. Called by the orchestrator
        agent factory so the planner knows the threat actor it's
        emulating and the SOC attribution markers in effect.
        """
        lines: list[str] = []
        if self._conops and self._conops.threat_actors:
            actor = self._conops.threat_actors[0]
            lines.append(f"- emulating threat actor: {actor.name}")
            if actor.sophistication:
                lines.append(f"  sophistication: {actor.sophistication}")
            if actor.motivation:
                lines.append(f"  motivation: {actor.motivation}")
            if actor.ttps:
                lines.append(f"  preferred MITRE TTPs: {', '.join(actor.ttps[:10])}")
        if self._conops and self._conops.attack_narrative:
            lines.append(f"- attack narrative: {self._conops.attack_narrative[:300]}")
        if self._deconfliction and self._deconfliction.shared_signature:
            lines.append(
                f"- SOC attribution: every probe carries User-Agent "
                f"{self._deconfliction.shared_signature!r} so the blue team can deconflict."
            )
        if self._deconfliction and self._deconfliction.time_windows:
            lines.append(
                f"- operational windows: {', '.join(self._deconfliction.time_windows)}"
            )
        if not lines:
            return ""
        return "\n\n## ENGAGEMENT PROFILE (CONOPS / Deconfliction)\n" + "\n".join(lines)

    def _load_evidence_chain(self):
        """Phase-4: load the engagement-scoped HMAC key + Merkle chain."""
        marker = self._workspace / "plan" / "hmac_key.txt"
        if not marker.exists():
            return None
        try:
            from network_pipeline.core.evidence_chain import (
                EvidenceChain, default_key_path, load_or_create_key,
            )
            spec = marker.read_text(encoding="utf-8").strip()
            # spec is the engagement_id; key path derives from it.
            engagement_id = spec or "default"
            key_path = default_key_path(engagement_id)
            key = load_or_create_key(key_path)
            chain = EvidenceChain(
                workspace=self._workspace,
                key=key,
                engagement_id=engagement_id,
            )
            log.info("evidence_chain enabled (engagement_id=%s)", engagement_id)
            return chain
        except Exception as e:  # pragma: no cover - defensive
            log.warning("evidence_chain init failed: %r", e)
            return None

    def _load_rag(self):
        """Phase-4: cross-engagement RAG. Opt-in via marker file."""
        marker = self._workspace / "plan" / "rag_index.txt"
        if not marker.exists():
            return None
        try:
            from network_pipeline.core.rag_memory import CrossEngagementRAG
            spec = marker.read_text(encoding="utf-8").strip()
            if not spec:
                return None
            rag = CrossEngagementRAG(
                index_path=Path(spec),
                base_url=self._config.ollama_base_url,
            )
            log.info("rag_memory enabled (index=%s)", spec)
            return rag
        except Exception as e:  # pragma: no cover - defensive
            log.warning("rag init failed: %r", e)
            return None

    def _load_blue_dir(self):
        """Phase-4: blue-team telemetry dir for purple-score correlation."""
        marker = self._workspace / "plan" / "blue_telemetry.txt"
        if not marker.exists():
            return None
        try:
            spec = marker.read_text(encoding="utf-8").strip()
            return Path(spec) if spec else None
        except OSError:
            return None

    def _load_adaptive_router(self):
        if not self._is_flag_set("adaptive.flag"):
            return None
        try:
            from network_pipeline.core.model_router import AdaptiveRouter
            router = AdaptiveRouter.load(self._workspace, enabled=True)
            log.info("adaptive_router enabled")
            return router
        except Exception as e:  # pragma: no cover - defensive
            log.warning("adaptive_router init failed: %r", e)
            return None

    def _load_playbook_engine(self):
        """Load the configured playbook (if any) — returns None when off."""
        marker = self._workspace / "plan" / "playbook.txt"
        if not marker.exists():
            return None
        try:
            spec = marker.read_text(encoding="utf-8").strip()
        except OSError:
            return None
        if not spec:
            return None
        try:
            from network_pipeline.core.playbook import (
                PlaybookEngine, load_playbook,
            )
            pb = load_playbook(spec)
            log.info("playbook loaded: %s (%d steps)", pb.name, len(pb.steps))
            return PlaybookEngine(pb)
        except Exception as e:
            log.warning("could not load playbook %r: %r", spec, e)
            return None

    # ── public ─────────────────────────────────────────────────────

    async def run(self) -> EngagementState:
        """Drive the loop until complete."""
        # Publish this loop so sync @tool wrappers in the agent layer
        # can schedule scanner coroutines on it via
        # run_on_engagement_loop() (otherwise sync tools end up with
        # un-awaited coroutines in worker threads — see runtime.py).
        from network_pipeline.tools.runtime import set_engagement_loop
        set_engagement_loop(asyncio.get_running_loop())

        # Phase-8: HITL pause. Install a cross-platform SIGINT handler
        # that flips _paused and writes plan/pause.flag. The handler is
        # checked between iterations — each iteration is already
        # atomic (state snapshot at end), so a between-turn break loses
        # no work. Resume on next `cli run` is automatic via
        # EngagementState.load.
        self._paused = False
        self._install_pause_handler()

        self._factory.probe()  # fail-fast if Ollama is down or models missing

        state = EngagementState.load(self._workspace) or EngagementState(
            workspace=str(self._workspace),
            target=self._config.target,
            max_iterations=self._config.max_iterations,
            phase=EngagementPhase.ATTACK,
        )
        if state.iteration > 0 and state.resumed_at is None:
            state.resumed_at = datetime.now(timezone.utc)
        self._state = state

        opplan = load_opplan(self._workspace)
        if opplan is None:
            log.error("no OPPLAN at %s — run `plan` first", self._workspace)
            state.phase = EngagementPhase.COMPLETE
            state.save(self._workspace)
            return state

        # Phase-L: universal baseline scan AFTER OPPLAN is confirmed.
        # Runs every applicable scanner against an auto-discovered
        # attack surface. No LLM consulted; works on any HTTP target.
        # The LLM-driven iteration loop runs afterward as enrichment.
        # Skipped on resume (state.iteration > 0) to avoid double-scanning.
        # Hard-capped at 12 minutes (the runner has its own per-scanner +
        # 10-min internal cap; this is a safety net).
        if state.iteration == 0:
            try:
                from network_pipeline.core.baseline_scan import (
                    run_universal_baseline,
                )
                log.info("Phase-L: running universal baseline scan on %s "
                         "(hard cap=12min)", self._config.target)
                histogram = await asyncio.wait_for(
                    run_universal_baseline(
                        http_client=self._http_client,
                        dns_client=self._dns_client,
                        target_url=self._config.target,
                        findings_log=self._findings,
                        workspace=self._workspace,
                        deep_mode=True,
                    ),
                    timeout=720.0,  # 12 minutes hard cap
                )
                log.info("Phase-L baseline persisted: %s", histogram)
            except asyncio.TimeoutError:
                log.warning(
                    "Phase-L: HARD TIMEOUT after 12min — proceeding to LLM loop",
                )
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "Phase-L baseline failed (continuing with LLM loop): %r", e,
                )

        # Budget governor lives across iterations; the BudgetState it
        # tracks is mutable on the OPPLAN doc so resume picks up where
        # the prior run stopped.
        from network_pipeline.core.budget import BudgetGovernor
        self._budget = BudgetGovernor(opplan.budget)
        # Hook the trace handler so every LLM exchange charges the budget.
        self._wire_budget_to_traces()
        # Phase-3: hook the trace handler for adaptive routing stats too.
        self._wire_router_to_traces()
        # Phase-3: forward the adaptive-router override into the LLM
        # factory so subsequent get_model() calls honour promotions.
        if self._adaptive_router is not None:
            self._factory._adaptive_router = self._adaptive_router  # type: ignore[attr-defined]

        # Phase-4: build the multi-agent supervisor when --parallel > 1.
        # Stays None when parallelism=1 so the existing single-agent
        # path is unchanged for default operators.
        self._supervisor = None
        if self._parallelism > 1:
            from network_pipeline.core.supervisor import (
                MultiAgentSupervisor, SupervisorContext,
            )
            self._supervisor = MultiAgentSupervisor(
                SupervisorContext(
                    workspace=self._workspace,
                    config=self._config,
                    runner=self._runner,
                    kg=self._kg,
                    findings=self._findings,
                    factory=self._factory,
                    engagement_id=state.engagement_id,
                ),
                parallelism=self._parallelism,
            )
            log.info(
                "supervisor enabled — parallelism=%d", self._parallelism,
            )

        # Bug-fix D: instantiate the orchestrator agent ONCE so its
        # ToT-planning + RAG-recall tools are reachable. The agent
        # runs a "planning pass" at iteration boundaries when ToT is
        # enabled or when the OPPLAN runs dry but RAG could re-seed.
        # When neither flag is set the agent is built but never invoked
        # — cheap because Ollama only loads the model on first call.
        await self._maybe_run_orchestrator_planning(state)

        # ── ATTACK ────────────────────────────────────────────────
        while (
            state.phase == EngagementPhase.ATTACK
            and state.iteration < state.max_iterations
        ):
            # Phase-8: HITL pause check. If the operator hit Ctrl+C
            # since the last iteration boundary, snapshot state + exit
            # cleanly. Phase remains ATTACK so the next `cli run`
            # resumes mid-stream.
            if self._paused or self._pause_flag_path().exists():
                log.warning(
                    "pause requested; checkpointing at iteration %d and exiting",
                    state.iteration,
                )
                try:
                    self._pause_flag_path().write_text(
                        f"paused at iteration {state.iteration} "
                        f"on {datetime.now(timezone.utc).isoformat()}\n",
                        encoding="utf-8",
                    )
                except OSError:
                    pass
                try:
                    state.save(self._workspace)
                except Exception as se:  # pragma: no cover - defensive
                    log.error("pause-time state save failed: %r", se)
                return state

            # Budget gate — abort cleanly if any cap is breached
            decision = self._budget.should_abort()
            if decision.abort:
                log.warning("aborting engagement: %s", decision.reason)
                state.phase = EngagementPhase.VACCINE
                break
            opplan = load_opplan(self._workspace)
            if opplan is None:
                break

            # ── Phase-4 parallel branch ───────────────────────────
            if self._supervisor is not None:
                try:
                    pairs = await self._supervisor.step(
                        opplan=opplan, iteration_base=state.iteration + 1,
                    )
                except Exception as e:  # pragma: no cover - defensive
                    log.error("supervisor step raised: %r — falling back to serial", e)
                    pairs = []
                if pairs:
                    for obj, result in pairs:
                        state.iteration += 1
                        state.current_objective_id = obj.id
                        state.iteration_history.append(result)
                        self._apply_result_to_opplan(obj, result, state)
                        state.findings_discovered.extend(result.findings_produced)
                        self._flush_episodic(obj, result)
                    snapshot_state(
                        self._workspace, state.iteration,
                        {
                            "supervisor_step": [
                                {"objective": o.id, "result": r.model_dump()}
                                for o, r in pairs
                            ],
                            "state": state.summary,
                        },
                    )
                    try:
                        state.save(self._workspace)
                    except Exception as se:  # pragma: no cover - defensive
                        log.error("state save failed: %r", se)
                    # Resync OPPLAN budget counters
                    try:
                        opplan_now = load_opplan(self._workspace)
                        if opplan_now is not None and self._budget is not None:
                            opplan_now.budget = self._budget.state
                            save_opplan(self._workspace, opplan_now)
                    except Exception as se:  # pragma: no cover - defensive
                        log.error("opplan budget save failed: %r", se)
                    continue
                # Empty supervisor batch ⇒ fall through to serial path
                # (e.g. all objectives target the same host)

            objective = opplan.next_pending()
            if objective is None:
                log.info("no pending objectives — transitioning to VACCINE")
                state.phase = EngagementPhase.VACCINE
                break

            state.current_objective_id = objective.id
            state.iteration += 1
            log.info("iteration %d: %s (%s)",
                     state.iteration, objective.id, objective.phase.value)

            # Phase-3 adaptive router: tick at iteration boundary so
            # cooldown counters advance and any pending promotion /
            # demotion is committed BEFORE we build the next agent.
            if self._adaptive_router is not None:
                self._adaptive_router.tick_iteration()
                self._adaptive_router.save()

            # Mark in-progress
            objective.status = ObjectiveStatus.IN_PROGRESS
            save_opplan(self._workspace, opplan)

            # Snapshot KG node ids BEFORE the iteration so we can diff
            # after and synthesise follow-up objectives for new assets.
            try:
                pre_kg_ids = {n["id"] for n in self._kg.query()}
            except Exception:  # pragma: no cover - defensive
                pre_kg_ids = set()

            result: IterationResult
            try:
                result = await self._run_iteration(
                    objective, state.iteration, state.engagement_id,
                )
                state.iteration_history.append(result)
                self._apply_result_to_opplan(objective, result, state)
                state.findings_discovered.extend(result.findings_produced)
                snapshot_state(
                    self._workspace, state.iteration,
                    {"iteration_result": result.model_dump(), "state": state.summary},
                )
                # KG-delta driven objective synthesis — append follow-up
                # work items for any new hosts / services / creds the
                # agent discovered. This is what makes the pipeline
                # autonomous vs. a static plan-then-execute flow.
                self._synthesize_follow_ups(objective, pre_kg_ids)
                # Phase-3 episodic memory: capture a "what was learned"
                # episode at iteration end so the next iteration's
                # orchestrator gets the recent-learnings block.
                self._flush_episodic(objective, result)
            except BaseException as e:
                # Capture-and-record so the engagement is resumable even
                # if the agent raises or the user ^Cs. The finally block
                # below persists state before re-raising.
                log.error("iteration %d raised: %r", state.iteration, e)
                err_result = IterationResult(
                    objective_id=objective.id,
                    agent_used="unknown",
                    outcome="ERROR",
                    error=repr(e),
                )
                state.iteration_history.append(err_result)
                # Best-effort: park the objective so a resume doesn't
                # loop on the same crashing target forever.
                try:
                    opplan_e = load_opplan(self._workspace)
                    if opplan_e is not None:
                        obj_e = opplan_e.get(objective.id)
                        if obj_e is not None:
                            obj_e.status = ObjectiveStatus.BLOCKED
                            obj_e.notes = (
                                obj_e.notes + f"\n[crash] {e!r}"
                            ).strip()
                            save_opplan(self._workspace, opplan_e)
                except Exception as se:  # pragma: no cover - defensive
                    log.error("opplan crash-park failed: %r", se)
                raise
            finally:
                # Always persist state, even on crash / ^C, so
                # ``engagement resume`` works from the latest iteration.
                # Also persist OPPLAN so the in-memory budget counters
                # mutated during this iteration survive resume.
                try:
                    state.save(self._workspace)
                except Exception as se:  # pragma: no cover - defensive
                    log.error("state save failed: %r", se)
                try:
                    opplan_now = load_opplan(self._workspace)
                    if opplan_now is not None and self._budget is not None:
                        # Mirror live budget counters back into the
                        # persisted OPPLAN budget block.
                        opplan_now.budget = self._budget.state
                        save_opplan(self._workspace, opplan_now)
                except Exception as se:  # pragma: no cover - defensive
                    log.error("opplan budget save failed: %r", se)

        # ── VACCINE ───────────────────────────────────────────────
        if state.phase == EngagementPhase.VACCINE:
            log.info("entering VACCINE phase")
            try:
                await self._run_vaccine(state)
            except Exception as e:  # noqa: BLE001
                # Mirror the agent-build catch in _run_iteration so the
                # vaccine phase failure (e.g. torch double-registration
                # in the defender agent build) doesn't bubble out and
                # mark the whole engagement as 'error'. Findings have
                # already been persisted; reports still work.
                msg = repr(e)
                hint = ""
                if "TORCH_LIBRARY" in msg:
                    hint = (
                        " — see iteration error hint above for the "
                        "torch uninstall command."
                    )
                log.error("vaccine phase raised: %s%s", msg, hint)
            state.phase = EngagementPhase.COMPLETE

        # ── Phase-4 COMPLETE-time hooks ───────────────────────────
        # (a) Blue-team correlation: tag findings.detected from
        #     Suricata/Zeek telemetry under the configured dir.
        if self._blue_telemetry_dir is not None:
            try:
                from network_pipeline.core.detection_ingest import (
                    correlate_workspace,
                )
                score = correlate_workspace(
                    workspace=self._workspace,
                    findings_log=self._findings,
                    blue_telemetry_dir=self._blue_telemetry_dir,
                )
                # Persist the score next to the state so the report
                # writer surfaces it without re-running correlation.
                (self._workspace / "purple_score.json").write_text(
                    f'{{"detected": {score.findings_detected}, '
                    f'"total": {score.findings_total}, '
                    f'"ratio": {score.ratio:.4f}}}\n',
                    encoding="utf-8",
                )
            except Exception as e:  # pragma: no cover - defensive
                log.warning("detection correlation failed: %r", e)

        # (b) RAG absorb: embed every finding + a KG summary so future
        #     engagements against similar targets get prior-context recall.
        if self._rag is not None:
            try:
                stats = self._kg.stats()
                kg_summary = (
                    f"nodes={stats.get('nodes', 0)} edges={stats.get('edges', 0)} "
                    f"by_type={stats.get('by_type', {})}"
                )
                self._rag.absorb_engagement(
                    findings=self._findings.all(),
                    kg_summary=kg_summary,
                    target_signature=str(self._config.target),
                    engagement_id=state.engagement_id,
                )
            except Exception as e:  # pragma: no cover - defensive
                log.warning("RAG absorb failed: %r", e)

        state.save(self._workspace)
        log.info("engagement complete: %s", state.summary)
        # Close the shared HTTP client (releases connection pool + cookie jar)
        try:
            await self._http_client.aclose()
        except Exception:
            pass
        return state

    # ── internals ──────────────────────────────────────────────────

    # Per-phase retry hints — appended to objective.notes when the loop
    # decides to re-dispatch a BLOCKED/TIMEOUT objective. Keep these
    # short; they nudge the agent, they don't reprogram it.
    _RETRY_HINTS: dict[str, list[str]] = {
        "SCAN": [
            "retry 1: narrow port range to 1-1024",
            "retry 2: drop full-port sweep; focus on well-known service ports only",
            "retry 3: last attempt — no version detection, tcp-connect only",
        ],
        "RECON": [
            "retry 1: passive sources only, skip DNS brute force",
            "retry 2: reduce timeout, skip whois/subfinder if they're hanging",
            "retry 3: final pass — just record what's already in the KG",
        ],
        "INITIAL_ACCESS": [
            "retry 1: restrict nuclei to medium+ templates only",
            "retry 2: skip nuclei entirely, use curl for targeted checks",
            "retry 3: final — record partial evidence and mark BLOCKED",
        ],
        "POST_EXPLOIT": [
            "retry 1: confirm RoE still permits this action",
            "retry 2: reduce scope to single target",
            "retry 3: last attempt before abandoning",
        ],
        "EXFILTRATION": [
            "retry 1: simulate only, do not copy data",
            "retry 2: record attempt, skip actual transfer",
            "retry 3: final pass",
        ],
    }

    def _apply_result_to_opplan(
        self, objective: Objective, result: IterationResult,
        state: EngagementState,
    ) -> None:
        """Update OPPLAN for this iteration's result.

        Handles adaptive retry: BLOCKED/TIMEOUT/ERROR outcomes below
        ``max_retries`` are re-queued (status → PENDING) with a
        retry_hint appended so the next attempt has different
        parameters. Only final failures flip the objective to BLOCKED.
        """
        opplan = load_opplan(self._workspace)
        if opplan is None:
            return
        obj = opplan.get(objective.id)
        if obj is None:
            return

        if result.outcome == "COMPLETED":
            obj.status = ObjectiveStatus.COMPLETED
            state.objectives_completed.append(objective.id)
            save_opplan(self._workspace, opplan)
            return

        # Non-success outcomes: decide retry vs. final-block.
        tag = {
            "BLOCKED": "[blocked]",
            "TIMEOUT": "[timeout]",
            "ERROR": "[error]",
        }.get(result.outcome, "[unknown]")
        err_note = f"{tag} {result.error}" if result.error else tag

        # Non-transient environment errors (torch double-registration,
        # missing API key, etc.) — don't bother retrying.
        non_transient = bool(result.error and any(
            marker in result.error for marker in (
                "TORCH_LIBRARY", "agent build failed",
                "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                "NoProvidersAvailable",
            )
        ))
        if non_transient:
            obj.status = ObjectiveStatus.BLOCKED
            state.objectives_blocked.append(objective.id)
            obj.notes = (obj.notes + f"\n{err_note} (non-transient — not retried)").strip()
            save_opplan(self._workspace, opplan)
            return

        if obj.retries < obj.max_retries:
            # Re-queue with a hint. Leave status PENDING so next_pending()
            # picks it up again. Bump priority slightly so other pending
            # work doesn't starve the retry, but don't jump to the head
            # of the queue (fairness).
            obj.retries += 1
            hints_for_phase = self._RETRY_HINTS.get(
                objective.phase.name, ["retry: tweak parameters"],
            )
            hint = hints_for_phase[min(obj.retries - 1, len(hints_for_phase) - 1)]
            obj.retry_hints.append(hint)
            obj.status = ObjectiveStatus.PENDING
            obj.notes = (
                obj.notes + f"\n{err_note} (retry {obj.retries}/{obj.max_retries}: {hint})"
            ).strip()
            log.info(
                "retrying %s (%d/%d): %s",
                objective.id, obj.retries, obj.max_retries, hint,
            )
        else:
            obj.status = ObjectiveStatus.BLOCKED
            state.objectives_blocked.append(objective.id)
            obj.notes = (
                obj.notes + f"\n{err_note} (giving up after {obj.retries} retries)"
            ).strip()
        save_opplan(self._workspace, opplan)

    def _synthesize_follow_ups(
        self, objective: Objective, pre_kg_ids: set[str],
    ) -> None:
        """Append KG-delta objectives to the OPPLAN if new assets appeared.

        Idempotent: ``synthesize_from_kg_delta`` checks existing
        ``synthesized_from`` tags and won't duplicate objectives.
        """
        try:
            post_nodes = self._kg.query()
        except Exception as e:  # pragma: no cover - defensive
            log.warning("KG query for synthesis failed: %r", e)
            return
        new_nodes = [n for n in post_nodes if n["id"] not in pre_kg_ids]
        if not new_nodes:
            return

        opplan = load_opplan(self._workspace)
        if opplan is None:
            return
        appended = synthesize_from_kg_delta(
            opplan, new_nodes,
            default_opsec=objective.opsec,
            playbook_engine=getattr(self, "_playbook_engine", None),
            all_kg_nodes=post_nodes,
            c2_tier=objective.c2_tier,
        )
        if appended:
            save_opplan(self._workspace, opplan)
            log.info(
                "synthesised %d follow-up objective(s) from iteration %s: %s",
                len(appended), objective.id,
                [o.id for o in appended],
            )

    async def _run_iteration(
        self, objective: Objective, iteration: int, engagement_id: str,
    ) -> IterationResult:
        # Phase-4: HRL fast-path. Multi-turn objectives bypass the
        # standard ReAct dispatch and go to the HRL attacker, which
        # uses a high-level + low-level policy with composite reward
        # shaping. The standard path remains the fallback on any HRL
        # error so a broken HRL config never blocks an engagement.
        if getattr(objective, "multi_turn", False):
            try:
                return await self._run_hrl_iteration(objective, iteration, engagement_id)
            except Exception as e:  # noqa: BLE001
                log.warning(
                    "HRL attacker failed for %s (%r) — falling back to standard ReAct",
                    objective.id, e,
                )

        factory_entry = _AGENT_FACTORIES.get(objective.phase)
        if factory_entry is None:
            log.error(
                "no agent registered for phase %s — registry=%s",
                objective.phase, sorted(p.value for p in _AGENT_FACTORIES),
            )
            return IterationResult(
                objective_id=objective.id, agent_used="none",
                outcome="ERROR",
                error=f"no agent registered for phase {objective.phase.value}",
            )
        role, factory_fn = factory_entry

        # Build the agent. This call can fail with environmental issues
        # (e.g. torch double-registration when the user has duplicate
        # torch installs across user-site + conda env). Catch here so
        # one bad iteration doesn't tank the whole engagement.
        try:
            agent, handler = factory_fn(
                workspace=self._workspace,
                config=self._config,
                runner=self._runner,
                kg=self._kg,
                findings=self._findings,
                factory=self._factory,
                iteration=iteration,
                engagement_id=engagement_id,
                opsec_level=objective.opsec,
                c2_tier=objective.c2_tier,
                http_client=self._http_client,
                dns_client=self._dns_client,
            )
        except Exception as e:  # noqa: BLE001
            msg = repr(e)
            hint = ""
            if "TORCH_LIBRARY" in msg or "single TORCH_LIBRARY" in msg:
                hint = (
                    " — duplicate torch install detected. Fix with: "
                    "`pip uninstall -y --user torch transformers sentence-transformers` "
                    "(safe to remove; the pipeline falls back to a hash-based embedding "
                    "when sentence-transformers is missing)."
                )
            log.error(
                "iteration %d agent build raised: %s%s",
                iteration, msg, hint,
            )
            return IterationResult(
                objective_id=objective.id, agent_used=role,
                outcome="ERROR",
                error=f"agent build failed: {msg}{hint}",
            )

        from langchain_core.messages import HumanMessage  # type: ignore[import-not-found]
        prompt_parts = [
            f"Objective {objective.id} ({objective.phase.value}): {objective.title}",
            "",
            objective.description,
            "",
            "Acceptance criteria:",
            *[f"- {c}" for c in objective.acceptance_criteria],
            "",
            f"Target: {self._config.target}",
        ]
        # Adaptive retry context: surface previous attempt's hint so the
        # model knows it's on attempt N and what to tweak.
        if objective.retries > 0 and objective.retry_hints:
            prompt_parts.extend([
                "",
                f"RETRY ATTEMPT {objective.retries}/{objective.max_retries}",
                "Previous attempts failed. Follow these retry hints:",
                *[f"- {h}" for h in objective.retry_hints],
            ])
        if objective.synthesized_from:
            prompt_parts.extend([
                "",
                f"(This objective was auto-synthesised from KG node "
                f"{objective.synthesized_from}.)",
            ])
        # Phase-3 episodic memory: append "Recent learnings" so the
        # model carries forward what prior iterations discovered without
        # bloating message history. Empty on iteration 1.
        episodic_block = self._episodic.render_for_prompt(n=5)
        if episodic_block:
            prompt_parts.extend(["", episodic_block])
        # Phase-3 scratchpad injection (Plan risk #13): on retries ONLY,
        # paste the per-objective scratch into the system prompt. The
        # agent can write to scratch via scratch_append() but cannot
        # spam-read it as a tool — context-bleed prevention.
        if objective.retries > 0:
            scratch_block = self._scratchpad.render_for_retry_prompt(objective.id)
            if scratch_block:
                prompt_parts.extend(["", scratch_block])
        prompt = HumanMessage(content="\n".join(prompt_parts))

        t0 = time.time()
        before_findings = set(self._findings.snapshot_ids())
        try:
            await asyncio.wait_for(
                agent.ainvoke(
                    {"messages": [prompt]},
                    config={"callbacks": [handler]},
                ),
                timeout=self._config.iteration_max_seconds,
            )
            after_findings = set(self._findings.snapshot_ids())
            new_findings = sorted(after_findings - before_findings)
            return IterationResult(
                objective_id=objective.id,
                agent_used=role,
                outcome="COMPLETED",
                findings_produced=new_findings,
                duration_seconds=time.time() - t0,
            )
        except asyncio.TimeoutError:
            return IterationResult(
                objective_id=objective.id, agent_used=role,
                outcome="TIMEOUT",
                duration_seconds=time.time() - t0,
                error=f"iteration timeout after {self._config.iteration_max_seconds}s",
            )
        except Exception as e:
            return IterationResult(
                objective_id=objective.id, agent_used=role,
                outcome="ERROR", duration_seconds=time.time() - t0, error=repr(e),
            )

    async def _run_hrl_iteration(
        self, objective: Objective, iteration: int, engagement_id: str,
    ) -> IterationResult:
        """Phase-4: HRL multi-turn attacker dispatch path.

        Runs the two-policy HRL loop (high-level strategy → low-level
        token policy) under the same iteration timeout the standard
        path uses. Persists turn-level traces under
        ``workspace/hrl/<objective_id>.jsonl`` for post-mortem replay.
        """
        from urllib.parse import urljoin

        from network_pipeline.agents.hrl_attacker import HRLAttacker
        from network_pipeline.core.hrl_trajectory import TurnObservation

        t0 = time.time()
        log_path = self._workspace / "hrl" / f"{objective.id}.jsonl"
        attacker = HRLAttacker(self._factory, log_path=log_path)

        target = self._config.target
        intent = objective.description or objective.title

        async def http_adapter(req: dict) -> TurnObservation:
            """Wrap the low-level policy's JSON request into HTTPClient.request."""
            if self._http_client is None:
                return TurnObservation(error="no HTTPClient configured for HRL")
            path = req.get("path", "/") or "/"
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            method = (req.get("method") or "GET").upper()
            headers = req.get("headers") or {}
            body = req.get("body") or ""
            kwargs: dict[str, object] = {"headers": headers}
            if body and method not in ("GET", "HEAD"):
                kwargs["content"] = body
            try:
                resp = await self._http_client.request(
                    method, url,
                    scanner_tool="hrl_attacker",
                    agent="hrl_attacker",
                    objective_id=objective.id,
                    **kwargs,
                )
            except Exception as e:  # noqa: BLE001
                return TurnObservation(error=repr(e))
            if resp is None:
                return TurnObservation(error="request refused (scope/RoE)")
            return TurnObservation(
                response_status=resp.status_code,
                response_headers={k: v for k, v in resp.headers.items()},
                response_body=resp.text[:8000],
                response_cookies={k: v for k, v in resp.cookies.items()},
            )

        try:
            state = await asyncio.wait_for(
                attacker.run(objective, target, intent, http_adapter),
                timeout=self._config.iteration_max_seconds,
            )
        except asyncio.TimeoutError:
            return IterationResult(
                objective_id=objective.id, agent_used="hrl_attacker",
                outcome="TIMEOUT",
                duration_seconds=time.time() - t0,
                error=f"HRL iteration timeout after {self._config.iteration_max_seconds}s",
            )

        outcome = "COMPLETED" if state.terminal_reason == "oracle_fired" else "BLOCKED"
        return IterationResult(
            objective_id=objective.id, agent_used="hrl_attacker",
            outcome=outcome,
            findings_produced=[],
            duration_seconds=time.time() - t0,
            error=None if outcome == "COMPLETED" else (
                f"HRL terminal_reason={state.terminal_reason} "
                f"turns={state.turns_taken} reward={state.cumulative_reward:.3f}"
            ),
        )

    async def _run_vaccine(self, state: EngagementState) -> None:
        agent, handler = create_defender_agent(
            workspace=self._workspace, config=self._config, runner=self._runner,
            kg=self._kg, findings=self._findings, factory=self._factory,
            iteration=state.iteration + 1, engagement_id=state.engagement_id,
        )
        from langchain_core.messages import HumanMessage  # type: ignore[import-not-found]
        prompt = HumanMessage(
            content=(
                "Vaccine phase: review every finding in findings.jsonl, "
                "group by root cause, and produce a defense_brief.json via "
                "write_defense_brief(...). Each recommendation must include: "
                "finding_ids, root_cause, patch, detection, hardening."
            )
        )
        try:
            await asyncio.wait_for(
                agent.ainvoke(
                    {"messages": [prompt]},
                    config={"callbacks": [handler]},
                ),
                timeout=self._config.iteration_max_seconds,
            )
        except asyncio.TimeoutError:
            log.warning("defender timed out in vaccine phase")
        except Exception as e:
            log.error("defender failed: %r", e)

        # ── Verifier re-attack ────────────────────────────────────
        # After the defender writes defense_brief.json, run the verifier
        # to replay each finding's reproduction. Skip if the brief is
        # missing (nothing to verify against).
        brief_path = self._workspace / "defense_brief.json"
        if brief_path.exists():
            log.info("vaccine: running verifier")
            vagent, vhandler = create_verifier_agent(
                workspace=self._workspace, config=self._config,
                runner=self._runner, kg=self._kg, findings=self._findings,
                factory=self._factory,
                iteration=state.iteration + 2, engagement_id=state.engagement_id,
            )
            vprompt = HumanMessage(
                content=(
                    "Verifier phase: read defense_brief.json, list every "
                    "finding, replay its reproduction steps, and call "
                    "write_verification_results(results) exactly once. Do "
                    "not record new findings. Do not escalate OPSEC."
                )
            )
            try:
                await asyncio.wait_for(
                    vagent.ainvoke(
                        {"messages": [vprompt]},
                        config={"callbacks": [vhandler]},
                    ),
                    timeout=self._config.iteration_max_seconds,
                )
            except asyncio.TimeoutError:
                log.warning("verifier timed out in vaccine phase")
            except Exception as e:
                log.error("verifier failed: %r", e)
        else:
            log.info("vaccine: no defense_brief.json — skipping verifier")

    # ── budget plumbing ──────────────────────────────────────────────

    def _wire_budget_to_traces(self) -> None:
        """Patch ``TraceCallbackHandler`` so each LLM exchange charges the budget.

        The trace handler already records ``prompt_chars`` and
        ``response_chars`` per exchange. We override its ``_write``
        method so every JSONL line emitted ALSO calls
        ``BudgetGovernor.charge`` with the same numbers. Done once per
        engagement, against the class — every agent's handler instance
        picks it up automatically.

        Idempotent: re-runs replace the patch with the new budget ref.
        """
        from network_pipeline.core.logging import TraceCallbackHandler

        budget = self._budget
        if budget is None:
            return
        original = getattr(
            TraceCallbackHandler, "_orig_write_for_budget", None,
        ) or TraceCallbackHandler._write

        def _write_with_budget(self, payload):  # type: ignore[no-untyped-def]
            try:
                ev = payload.get("event")
                if ev == "llm_start":
                    # llm_start carries prompt_chars; stash on the
                    # handler instance keyed by run_id so llm_end can
                    # charge a complete prompt+response token estimate.
                    cache = getattr(self, "_budget_prompt_chars", None)
                    if cache is None:
                        cache = {}
                        self._budget_prompt_chars = cache
                    rid = payload.get("run_id", "")
                    cache[rid] = int(payload.get("prompt_chars", 0))
                elif ev == "llm_end":
                    cache = getattr(self, "_budget_prompt_chars", {}) or {}
                    rid = payload.get("run_id", "")
                    prompt_chars = int(cache.pop(rid, 0))
                    response_text = payload.get("response_text", "") or ""
                    budget.charge(
                        role=getattr(self, "_agent", "unknown"),
                        prompt_chars=prompt_chars,
                        response_chars=len(response_text),
                        phase=getattr(self, "_phase", None),
                    )
            except Exception:  # pragma: no cover - never break tracing
                pass
            return original(self, payload)

        TraceCallbackHandler._orig_write_for_budget = original  # type: ignore[attr-defined]
        TraceCallbackHandler._write = _write_with_budget  # type: ignore[assignment]

    def _wire_router_to_traces(self) -> None:
        """Patch the trace handler so adaptive-router stats update on every llm_end.

        No-op when ``--adaptive-models`` is off. We layer this on top of
        the budget patch — both write hooks call the original.
        """
        from network_pipeline.core.logging import TraceCallbackHandler

        router = self._adaptive_router
        if router is None:
            return
        original = getattr(
            TraceCallbackHandler, "_orig_write_for_router", None,
        ) or TraceCallbackHandler._write

        def _write_with_router(self, payload):  # type: ignore[no-untyped-def]
            try:
                ev = payload.get("event")
                if ev == "llm_end":
                    role = getattr(self, "_agent", "unknown")
                    latency_ms = float(payload.get("latency_ms", 0.0))
                    router.record_call(
                        role, success=True, timeout=False,
                        latency_ms=latency_ms,
                    )
                elif ev == "llm_error":
                    role = getattr(self, "_agent", "unknown")
                    err = (payload.get("error") or "").lower()
                    is_to = "timeout" in err or "timed out" in err
                    router.record_call(
                        role, success=False, timeout=is_to, error=not is_to,
                    )
            except Exception:  # pragma: no cover - never break tracing
                pass
            return original(self, payload)

        TraceCallbackHandler._orig_write_for_router = original  # type: ignore[attr-defined]
        TraceCallbackHandler._write = _write_with_router  # type: ignore[assignment]

    async def _maybe_run_orchestrator_planning(self, state) -> None:
        """Bug-fix D: run a one-shot orchestrator planning pass.

        Called once per engagement (and again before VACCINE if the
        OPPLAN runs dry). Builds the orchestrator agent with ToT +
        RAG tools wired in, hands it the current OPPLAN + KG snapshot,
        and asks it to commit any new objectives via its OPPLAN-CRUD
        tools. No-op when neither ToT nor RAG is enabled — saves the
        token spend of an agent that has nothing to do.
        """
        if not (self._tot_enabled or self._rag is not None):
            return
        try:
            from network_pipeline.agents.orchestrator import (
                create_orchestrator_agent,
            )
            from langchain_core.messages import HumanMessage  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover - missing langchain
            log.warning("orchestrator planning skipped: %r", e)
            return
        agent, handler = create_orchestrator_agent(
            workspace=self._workspace,
            config=self._config,
            runner=self._runner,
            kg=self._kg,
            findings=self._findings,
            factory=self._factory,
            iteration=state.iteration,
            engagement_id=state.engagement_id,
            opsec_level=None,
            c2_tier=None,
            tot_enabled=self._tot_enabled,
            rag=self._rag,
        )
        try:
            kg_stats = self._kg.stats()
        except Exception:
            kg_stats = {}
        prompt = HumanMessage(content=(
            "Planning pass — review the current OPPLAN and KG, then\n"
            "commit any new objectives you think are warranted via the\n"
            "opplan_add_objective tool. If ToT is available, branch on\n"
            "alternatives via tot_plan_branches. If rag_recall is\n"
            "available, query it for prior learnings on this target\n"
            "class.\n\n"
            f"Target: {self._config.target}\n"
            f"KG stats: {kg_stats}\n"
            f"Iteration: {state.iteration}\n"
        ))
        try:
            await asyncio.wait_for(
                agent.ainvoke(
                    {"messages": [prompt]},
                    config={"callbacks": [handler]},
                ),
                timeout=self._config.iteration_max_seconds,
            )
            log.info("orchestrator planning pass complete")
        except asyncio.TimeoutError:
            log.warning("orchestrator planning pass timed out")
        except Exception as e:
            log.warning("orchestrator planning pass failed: %r", e)

    def _flush_episodic(self, objective, result) -> None:
        """Record one episode at iteration end.

        Compact summary: phase, outcome, finding count, error tail.
        Capped at ~200 tokens upstream by EpisodicMemory.append.
        """
        try:
            learned = (
                f"phase={objective.phase.value} "
                f"outcome={result.outcome} "
                f"findings={len(result.findings_produced)}"
            )
            if result.error:
                learned += f" error={result.error[:120]}"
            if result.findings_produced:
                learned += " new=" + ",".join(result.findings_produced[:5])
            self._episodic.append(
                iteration=getattr(self._state, "iteration", 0) if self._state else 0,
                objective_id=objective.id,
                agent=result.agent_used,
                learned=learned,
                engagement_id=getattr(self._state, "engagement_id", "") if self._state else "",
            )
        except Exception as e:  # pragma: no cover - defensive
            log.warning("episodic flush failed: %r", e)
