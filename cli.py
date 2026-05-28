"""Click CLI — plan / run / report / status.

Separate from the existing Security_module CLI at Security_module/cli.py.
Invoke as: ``python -m network_pipeline.cli <command>``
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import click

from network_pipeline.core.config import (
    assert_supported_platform,
    init_workspace,
    validate_workspace,
)
from network_pipeline.core.engagement import (
    EngagementConfig,
    EngagementState,
)
from network_pipeline.core.logging import attach_pipeline_log, get_logger
from network_pipeline.core.schemas import (
    OPPLAN,
    Objective,
    ObjectivePhase,
    RoE,
    ScopeEntry,
)

log = get_logger("cli")


# ── helpers ───────────────────────────────────────────────────────


def _load_roe(workspace: Path) -> RoE | None:
    p = workspace / "plan" / "roe.json"
    if not p.exists():
        return None
    return RoE.model_validate_json(p.read_text(encoding="utf-8"))


def _save_roe(workspace: Path, roe: RoE) -> None:
    p = workspace / "plan" / "roe.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(roe.model_dump_json(indent=2), encoding="utf-8")


def _seed_opplan(workspace: Path, target: str) -> None:
    """Write a minimal starter OPPLAN the orchestrator can expand on."""
    from network_pipeline.agents.orchestrator import save_opplan

    opplan = OPPLAN(
        engagement_name=f"network-engagement-{target}",
        objectives=[
            # ── RECON ───────────────────────────────────────────────
            Objective(
                id="OBJ-001",
                phase=ObjectivePhase.RECON,
                title=f"Passive DNS + WHOIS + subdomain enum for {target}",
                description=(
                    f"Run dns_scan, whois_lookup, and subdomain_enum against {target}. "
                    f"Populate the knowledge graph with discovered hosts and DNS records."
                ),
                acceptance_criteria=[
                    "dns_scan ScanResult appended to findings (or KG host nodes)",
                    "whois_lookup ScanResult recorded",
                    "subdomain_enum ran (data.total_found present)",
                ],
                priority=10,
            ),
            Objective(
                id="OBJ-002",
                phase=ObjectivePhase.RECON,
                title=f"JS endpoint + parameter mining on {target}",
                description=(
                    "Run js_endpoints to extract URLs/parameters from JS bundles, "
                    "then parameter_mining to discover hidden GET/POST params."
                ),
                acceptance_criteria=[
                    "js_endpoints ran, total_endpoints recorded",
                    "parameter_mining ran on at least one endpoint",
                ],
                priority=15,
                blocked_by=["OBJ-001"],
            ),
            # ── SCAN ────────────────────────────────────────────────
            Objective(
                id="OBJ-003",
                phase=ObjectivePhase.SCAN,
                title=f"Port + TLS + HTTP fingerprint of {target}",
                description=(
                    "port_scan top-1k ports via TCPConnectProbe, tls_audit on every "
                    "TLS port, http_probe for tech-fingerprint and security-header coverage."
                ),
                acceptance_criteria=[
                    "port_scan completed, open_ports recorded",
                    "tls_audit ran on at least one HTTPS endpoint OR target uses HTTP",
                    "http_probe completed; missing-headers findings recorded",
                ],
                priority=20,
                blocked_by=["OBJ-001"],
            ),
            Objective(
                id="OBJ-004",
                phase=ObjectivePhase.SCAN,
                title=f"Content discovery against {target}",
                description=(
                    "content_discovery against the target with the bundled common "
                    "wordlist; record every 200/301/403/500 hit on a sensitive path."
                ),
                acceptance_criteria=[
                    "content_discovery ran (data.total_hits present)",
                    "Any sensitive-path finding recorded as exposed-path",
                ],
                priority=25,
                blocked_by=["OBJ-003"],
            ),
            # ── INITIAL ACCESS / EXPLOIT ───────────────────────────
            Objective(
                id="OBJ-005",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"CVE template + web-audit batteries on {target}",
                description=(
                    "cve_check fires the bundled YAML signatures (Log4Shell, "
                    "PHPUnit RCE, exposed .git/.env, Spring4Shell, …). web_audit "
                    "runs misconfig + CORS + injection-breadth + SSRF batteries."
                ),
                acceptance_criteria=[
                    "cve_check executed; any positive match raised as finding",
                    "web_audit completed; CORS/security-header/git findings recorded",
                ],
                priority=30,
                blocked_by=["OBJ-003"],
            ),
            Objective(
                id="OBJ-006",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"Targeted SQLi / XSS / auth probes on {target}",
                description=(
                    "sqli_scan against any param surfaced by parameter_mining or "
                    "js_endpoints, error-based + boolean + time-based with baseline. "
                    "xss_scan with context-aware canaries (html/attr/js-string). "
                    "auth_audit for cookie flags, session fixation, default creds."
                ),
                acceptance_criteria=[
                    "sqli_scan ran on ≥1 parameter; verified findings have confidence=verified",
                    "xss_scan ran on ≥1 reflected-input endpoint",
                    "auth_audit completed",
                ],
                priority=35,
                blocked_by=["OBJ-002", "OBJ-005"],
            ),
            Objective(
                id="OBJ-007",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"JWT + sqlmap deep dive on {target}",
                description=(
                    "If a JWT bearer token was captured, run jwt_scan (alg=none, "
                    "weak-secret, kid traversal, RS→HS confusion). If sqli_scan "
                    "produced a positive on a param, hand it to sqlmap_dispatch "
                    "with the allowlisted flag set for confirmation."
                ),
                acceptance_criteria=[
                    "jwt_scan executed if a bearer token exists in AuthStore",
                    "sqlmap_dispatch run on every confirmed-SQLi parameter",
                ],
                priority=40,
                blocked_by=["OBJ-006"],
            ),
            # ── POST-EXPLOIT ────────────────────────────────────────
            Objective(
                id="OBJ-008",
                phase=ObjectivePhase.POST_EXPLOIT,
                title=f"Authenticated probing + IDOR walk on {target}",
                description=(
                    "Replay captured cookies/bearer via probe_uri; walk numeric "
                    "IDs via idor_walk on any /<resource>/<id> endpoint surfaced "
                    "during recon."
                ),
                acceptance_criteria=[
                    "probe_uri ran >=1 authenticated request OR no auth captured",
                    "idor_walk attempted on at least one numeric path segment",
                ],
                priority=50,
                blocked_by=["OBJ-006"],
            ),
            # ── DEEP RECON (Phase-2 thoroughness) ──────────────────
            Objective(
                id="OBJ-009",
                phase=ObjectivePhase.RECON,
                title=f"Deep web crawl of {target}",
                description=(
                    "Full recursive crawl: seed every link, follow every form "
                    "action, harvest endpoints into the KG. Use the new "
                    "web_crawler scanner with depth=4."
                ),
                acceptance_criteria=[
                    "web_crawler ran (data.endpoints_found present)",
                    ">=20 endpoint nodes in kg.json OR target only has fewer",
                ],
                priority=12,
                blocked_by=["OBJ-002"],
            ),
            Objective(
                id="OBJ-010",
                phase=ObjectivePhase.RECON,
                title=f"OpenAPI/Swagger discovery on {target}",
                description=(
                    "Probe 14 well-known spec paths; if found, walk every "
                    "operation and emit BOLA/auth-matrix probes per param."
                ),
                acceptance_criteria=[
                    "openapi_scan completed",
                ],
                priority=14,
                blocked_by=["OBJ-001"],
            ),
            Objective(
                id="OBJ-011",
                phase=ObjectivePhase.RECON,
                title=f"GraphQL surface on {target}",
                description=(
                    "Look for /graphql or /api/graphql; check introspection, "
                    "alias-DoS, depth limit, batching, suggestion leakage."
                ),
                acceptance_criteria=[
                    "graphql_scan completed",
                ],
                priority=14,
                blocked_by=["OBJ-001"],
            ),
            # ── DEEPER SCAN ────────────────────────────────────────
            Objective(
                id="OBJ-012",
                phase=ObjectivePhase.SCAN,
                title=f"Recursive content discovery on {target}",
                description=(
                    "content_discovery in recursive mode: follow every 200/3xx "
                    "to a depth of 2; bigger raft-small wordlist."
                ),
                acceptance_criteria=[
                    "content_discovery ran with recursive=True",
                    ">=5 sensitive paths recorded OR target serves no extras",
                ],
                priority=27,
                blocked_by=["OBJ-004"],
            ),
            Objective(
                id="OBJ-013",
                phase=ObjectivePhase.SCAN,
                title=f"Subdomain takeover check on {target}",
                description=(
                    "For each CNAME found in subdomain_enum, fingerprint the "
                    "upstream service (S3, Heroku, Azure, GitHub Pages, ...) "
                    "and flag dangling pointers."
                ),
                acceptance_criteria=[
                    "subdomain_takeover ran",
                ],
                priority=28,
                blocked_by=["OBJ-001"],
            ),
            Objective(
                id="OBJ-014",
                phase=ObjectivePhase.SCAN,
                title=f"Supply chain check on {target}",
                description=(
                    "Probe for exposed package.json/composer.lock/requirements.txt "
                    "etc.; OSV.dev lookup on any package@version found."
                ),
                acceptance_criteria=[
                    "supply_chain ran",
                ],
                priority=28,
                blocked_by=["OBJ-003"],
            ),
            # ── DEEPER EXPLOIT ─────────────────────────────────────
            Objective(
                id="OBJ-015",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"BOLA / mass-assignment battery on {target}",
                description=(
                    "For every authenticated endpoint, walk neighbour IDs; for "
                    "every captured POST/PUT body, mutate with privileged "
                    "fields (role, isAdmin, __proto__)."
                ),
                acceptance_criteria=[
                    "bola_scan ran on >=1 endpoint",
                    "mass_assignment ran on >=1 captured request",
                ],
                priority=42,
                blocked_by=["OBJ-006", "OBJ-008"],
            ),
            Objective(
                id="OBJ-016",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"HTTP request smuggling probe on {target}",
                description=(
                    "CL.TE / TE.CL / TE.TE timing differential against the "
                    "front-end. Vulnerable pairs hang past baseline."
                ),
                acceptance_criteria=[
                    "request_smuggling ran",
                ],
                priority=44,
                blocked_by=["OBJ-005"],
            ),
            Objective(
                id="OBJ-017",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"WebSocket scan on {target}",
                description=(
                    "Discover WS endpoints, check origin enforcement (CSWSH), "
                    "cleartext WS, auth-replay over WS."
                ),
                acceptance_criteria=[
                    "websocket_scan ran",
                ],
                priority=44,
                blocked_by=["OBJ-005"],
            ),
            # ── ADAPTIVE / RETRY ───────────────────────────────────
            Objective(
                id="OBJ-018",
                phase=ObjectivePhase.INITIAL_ACCESS,
                title=f"WAF-evaded payload retry pass on {target}",
                description=(
                    "For every 403/406-blocked probe in this engagement, retry "
                    "with progressive evasion: percent-encode, double-encode, "
                    "case-flip, comment injection, unicode NFKD, query split."
                ),
                acceptance_criteria=[
                    "evasion-bypass attempts logged in evidence/",
                ],
                priority=46,
                blocked_by=["OBJ-006", "OBJ-007"],
            ),
            # ── DEEP POST-EXPLOIT ──────────────────────────────────
            Objective(
                id="OBJ-019",
                phase=ObjectivePhase.POST_EXPLOIT,
                title=f"Authenticated full-walk of {target}",
                description=(
                    "After any cookie/bearer captured, hit EVERY endpoint in "
                    "the KG with auth. Compare anonymous vs authenticated "
                    "responses; flag privilege escalations and information "
                    "leaks."
                ),
                acceptance_criteria=[
                    "probe_uri ran on >=10 endpoints OR fewer exist",
                    "diff between anon/auth response logged",
                ],
                priority=52,
                blocked_by=["OBJ-008", "OBJ-015"],
            ),
            Objective(
                id="OBJ-020",
                phase=ObjectivePhase.POST_EXPLOIT,
                title=f"Persistent foothold + secondary recon on {target}",
                description=(
                    "If admin-equivalent access was achieved, dump session "
                    "tokens for replay; locate secondary targets reachable "
                    "from the foothold (internal API endpoints, jwks.json, "
                    "admin dashboards)."
                ),
                acceptance_criteria=[
                    "secondary recon attempted OR no foothold gained",
                ],
                priority=55,
                blocked_by=["OBJ-019"],
            ),
        ],
    )
    save_opplan(workspace, opplan)


# ── commands ──────────────────────────────────────────────────────


@click.group()
def cli() -> None:
    """network_pipeline — autonomous network security testing.

    .env autoload: if a ``.env`` file lives in the CWD (or one dir up)
    its variables are loaded into the process before any command runs.
    Real shell env vars win over .env values. Typical .env contents:

        OPENAI_API_KEY=sk-...
        ANTHROPIC_API_KEY=sk-ant-...     # optional
        # NETWORK_PIPELINE_PROFILE=openai_only  # optional override
    """
    from network_pipeline.llm.credentials import load_dotenv_files
    loaded = load_dotenv_files()
    if loaded:
        # Surface what we loaded so operators see how a missing key was
        # resolved (or wasn't). Goes to stderr so JSON output piping
        # still works clean.
        click.echo(f"[env] loaded {', '.join(loaded)}", err=True)
    assert_supported_platform()


@cli.command()
@click.option("--target", required=True, help="Primary target (URL, domain, or CIDR)")
@click.option("--out", "workspace", required=True, type=click.Path(),
              help="Engagement workspace directory (must be on WSL ext4 or native Linux)")
@click.option("--in-scope", multiple=True,
              help="Additional in-scope entries as 'type:value' (e.g. 'domain:example.com' or 'cidr:10.0.0.0/24')")
@click.option("--engagement-name", default="", help="Human-readable engagement name")
@click.option("--playbook", default="", help="MITRE playbook to drive synthesis (e.g. owasp_top10)")
@click.option("--web-mode", is_flag=True, default=False,
              help="Convenience: --playbook owasp_top10 + sensible web defaults")
@click.option("--target-type",
              type=click.Choice(["network", "llm"], case_sensitive=False),
              default="network", show_default=True,
              help="Phase-6: 'llm' selects the llm_target playbook (prompt-injection, "
                   "CoP jailbreak, RAG poisoning, multi-turn HRL).")
@click.option("--auth-cookie", default="",
              help="Pre-seed AuthStore with a Cookie header for the primary target")
def plan(target: str, workspace: str, in_scope: tuple[str, ...],
         engagement_name: str, playbook: str, web_mode: bool,
         target_type: str, auth_cookie: str) -> None:
    """Initialise a workspace with RoE + starter OPPLAN."""
    ws = validate_workspace(Path(workspace))
    init_workspace(ws)
    attach_pipeline_log(ws)

    # Build RoE from --target plus any extra --in-scope entries
    # (primary target is inferred as domain or cidr/ip)
    entries = [_entry_from(target)]
    for s in in_scope:
        if ":" in s:
            kind, value = s.split(":", 1)
            entries.append(ScopeEntry(target=value, type=kind))
        else:
            entries.append(ScopeEntry(target=s, type="domain"))
    roe = RoE(
        engagement_name=engagement_name or f"network-engagement-{target}",
        in_scope=entries,
    )
    _save_roe(ws, roe)
    _seed_opplan(ws, target)

    # Phase-2: persist the playbook choice so `run` picks it up on
    # every iteration (including resume).
    # Phase-6: --target-type llm overrides the default to llm_target
    # unless --playbook was explicitly given (the explicit flag wins).
    pb_choice = playbook
    if web_mode and not pb_choice:
        pb_choice = "owasp_top10"
    if (target_type or "network").lower() == "llm" and not pb_choice:
        pb_choice = "llm_target"
    if pb_choice:
        # Validate up-front so a typo (e.g. --playbook owasp10) errors
        # loudly here instead of silently falling through to "no
        # playbook" at iteration time.
        try:
            from network_pipeline.core.playbook import load_playbook
            pb = load_playbook(pb_choice)
        except FileNotFoundError as e:
            click.echo(
                f"error: --playbook {pb_choice!r} not found ({e}). "
                "Built-ins: owasp_top10, mitre_initial_access, "
                "mitre_credential_access, mitre_discovery.",
                err=True,
            )
            sys.exit(2)
        except Exception as e:
            click.echo(f"error: --playbook {pb_choice!r} failed to load: {e}", err=True)
            sys.exit(2)
        marker = ws / "plan" / "playbook.txt"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(pb_choice + "\n", encoding="utf-8")
        click.echo(f"  playbook: {pb_choice} ({len(pb.steps)} steps)")

    # Pre-seed AuthStore if --auth-cookie is provided
    if auth_cookie:
        from network_pipeline.tools.web.auth_replay import AuthStore
        store = AuthStore(ws)
        state = store.update_from_cookie_header(target, auth_cookie)
        click.echo(f"  auth pre-seeded for {state.host}: {state.fingerprint()}")

    click.echo(f"plan initialised at {ws}")
    click.echo(f"  roe:    {ws / 'plan' / 'roe.json'}")
    click.echo(f"  opplan: {ws / 'plan' / 'opplan.json'}")
    click.echo("Edit the OPPLAN / RoE as needed, then: python -m network_pipeline.cli run "
               + str(ws))


def _parse_provider_roles(pairs: tuple[str, ...]) -> dict[str, str]:
    """Parse repeated --provider-role 'role=provider' flags into a dict.

    Validates role + provider names so a typo aborts early instead of
    silently being ignored by the factory's default dispatch.
    """
    from network_pipeline.llm.profiles import ROLES

    valid_providers = {"ollama", "openai", "anthropic"}
    out: dict[str, str] = {}
    for entry in pairs:
        if "=" not in entry:
            raise click.BadParameter(
                f"--provider-role expects 'role=provider', got {entry!r}"
            )
        role, provider = entry.split("=", 1)
        role, provider = role.strip(), provider.strip().lower()
        if role not in ROLES:
            raise click.BadParameter(
                f"unknown role {role!r}. Known roles: {sorted(ROLES)}"
            )
        if provider not in valid_providers:
            raise click.BadParameter(
                f"unknown provider {provider!r}. Known: {sorted(valid_providers)}"
            )
        out[role] = provider
    return out


def _entry_from(target: str) -> ScopeEntry:
    import ipaddress

    try:
        ipaddress.ip_network(target, strict=False)
        return ScopeEntry(target=target, type="cidr")
    except ValueError:
        pass
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return ScopeEntry(target=host, type="domain")


@cli.command()
@click.argument("workspace", type=click.Path(exists=True))
@click.option("--profile", default="eco",
              help="Model profile: eco | max | test | cloud_eco | cloud_max | hybrid")
@click.option("--ollama-url", default="http://localhost:11434")
@click.option("--openai-base-url", default=None,
              help="Optional OpenAI-compatible endpoint (vLLM, OpenRouter, ...).")
@click.option("--anthropic-base-url", default=None,
              help="Optional Anthropic base URL override.")
@click.option("--provider-role", "provider_roles", multiple=True,
              help="Pin a role to a provider: 'role=provider' (e.g. 'exploit=ollama'). Repeatable.")
@click.option("--budget-usd", type=float, default=None,
              help="Hard cap on cumulative cloud spend (USD). Engagement aborts when exceeded.")
@click.option("--structured-reasoning/--no-structured-reasoning", default=True,
              help="Phase-2 SIRAJ-style 4-component reasoning contract. On by default; "
                   "disable to A/B compare token counts against free-form prose.")
@click.option("--cop/--no-cop", default=True,
              help="Phase-3 CoP (Composition-of-Principles) payload synthesis on the exploit "
                   "agent. On by default; disable for single-payload baseline.")
@click.option("--max-iterations", default=50, type=int)
@click.option("--iteration-timeout", default=600, type=int,
              help="Per-iteration wall-clock timeout (seconds)")
# ── Phase-1 reproducibility + budgets ────────────────────────────────
@click.option("--seed", type=int, default=None,
              help="Reproducibility seed (forwarded to Ollama options.seed)")
@click.option("--token-budget", type=int, default=None,
              help="Total prompt+completion token cap for the engagement")
@click.option("--wall-budget", type=int, default=None,
              help="Total wall-clock cap in seconds")
@click.option("--phase-budget", multiple=True,
              help="Per-phase token cap as 'phase:tokens' (e.g. 'exploit:200000'). Repeatable.")
@click.option("--rate", "rates", multiple=True,
              help="Per-binary rate cap as 'binary:rps' (e.g. 'nuclei:0.5'). Repeatable.")
# ── Phase-2 flags ───────────────────────────────────────────────────
@click.option("--playbook", default="",
              help="Override the configured playbook for this run (e.g. owasp_top10)")
@click.option("--web-mode", is_flag=True, default=False,
              help="Shortcut: --playbook owasp_top10 if no --playbook given")
@click.option("--auth-cookie", default="",
              help="Capture a Cookie header into the AuthStore before running")
# ── Phase-3 flags ───────────────────────────────────────────────────
@click.option("--c2-profile", default="",
              type=click.Choice(["", "stealth", "balanced", "loud"]),
              help="Mythic-style callback profile (sleep/jitter/UA pool)")
@click.option("--tot/--no-tot", default=False,
              help="Enable tree-of-thought planning at the orchestrator (k=3, depth=2)")
@click.option("--critic/--no-critic", default=True,
              help="Enable self-critic on findings (default on, off skips critique pass)")
@click.option("--adaptive-models/--no-adaptive-models", default=False,
              help="Promote/demote per-role models based on success/timeout stats")
# ── Phase-4 flags ───────────────────────────────────────────────────
@click.option("--parallel", type=int, default=1,
              help="Concurrent sub-agents per super-iteration (1..8)")
@click.option("--blue-telemetry", default="",
              help="Path to a directory of Suricata eve.json / Zeek conn.log files for purple-team correlation")
@click.option("--hmac-key", default="",
              help="Engagement id used to derive the HMAC key (key path: ~/.config/network_pipeline/keys/<id>.key)")
@click.option("--rag-index", default="",
              help="Path to the cross-engagement RAG JSON index (created on first absorb)")
# ── Pure-Python redesign flags ──────────────────────────────────────
@click.option("--proxy", default="",
              help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080) routed through HTTPClient")
@click.option("--dns-resolver", default="",
              help="Comma-separated DNS resolvers (defaults to 8.8.8.8,1.1.1.1)")
@click.option("--browser/--no-browser", default=False,
              help="Allow Playwright-backed scanners (requires `pip install network_pipeline[network-browser]`)")
def run(workspace: str, profile: str, ollama_url: str,
        openai_base_url: str | None, anthropic_base_url: str | None,
        provider_roles: tuple[str, ...], budget_usd: float | None,
        structured_reasoning: bool, cop: bool,
        max_iterations: int, iteration_timeout: int,
        seed: int | None, token_budget: int | None,
        wall_budget: int | None,
        phase_budget: tuple[str, ...], rates: tuple[str, ...],
        playbook: str, web_mode: bool, auth_cookie: str,
        c2_profile: str, tot: bool, critic: bool,
        adaptive_models: bool,
        parallel: int, blue_telemetry: str,
        hmac_key: str, rag_index: str,
        proxy: str, dns_resolver: str, browser: bool) -> None:
    """Run the engagement loop against the given workspace."""
    ws = validate_workspace(Path(workspace))
    attach_pipeline_log(ws)

    # Phase-8: detect a prior pause and clear the flag so subsequent
    # Ctrl+C creates a fresh checkpoint. EngagementState.load picks up
    # the iteration counter automatically — we only need to tell the
    # operator a resume is happening and unlock the flag.
    pause_flag = Path(workspace) / "plan" / "pause.flag"
    if pause_flag.exists():
        try:
            note = pause_flag.read_text(encoding="utf-8").strip()
        except OSError:
            note = ""
        click.echo(f"[resume] {pause_flag} present — resuming engagement"
                   + (f" ({note})" if note else ""))
        try:
            pause_flag.unlink()
        except OSError:
            pass

    # Phase-5: validate plan artifacts before launching the engagement.
    # Errors abort. Warnings (e.g. missing reviewer stamp) are surfaced
    # but don't block — operators running smoke tests or CI shouldn't
    # have to re-stamp every time.
    from network_pipeline.agents.soundwave import validate_plan
    _report = validate_plan(ws)
    for _w in _report.warnings:
        click.echo(f"warn: {_w}", err=True)
    if not _report.ok:
        for _e in _report.errors:
            click.echo(f"error: {_e}", err=True)
        click.echo("plan validation failed; run `soundwave interview <ws>` "
                   "or fix the JSON manually.", err=True)
        sys.exit(2)

    roe = _load_roe(ws)
    target = roe.in_scope[0].target if roe and roe.in_scope else ""
    if not target:
        click.echo("error: workspace has no RoE; run `plan` first", err=True)
        sys.exit(2)

    # Reproducibility seed — applied process-wide before any LLM is built
    from network_pipeline.core.seed import seed_all
    if seed is not None:
        seed_all(seed)

    # Phase-2: playbook override / web-mode shortcut
    pb_choice = playbook
    if web_mode and not pb_choice:
        pb_choice = "owasp_top10"
    if pb_choice:
        try:
            from network_pipeline.core.playbook import load_playbook
            load_playbook(pb_choice)
        except FileNotFoundError as e:
            click.echo(
                f"error: --playbook {pb_choice!r} not found ({e})",
                err=True,
            )
            sys.exit(2)
        except Exception as e:
            click.echo(f"error: --playbook {pb_choice!r} failed to load: {e}", err=True)
            sys.exit(2)
        marker = ws / "plan" / "playbook.txt"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(pb_choice + "\n", encoding="utf-8")

    # Phase-2: late auth seed
    if auth_cookie:
        from network_pipeline.tools.web.auth_replay import AuthStore
        AuthStore(ws).update_from_cookie_header(target, auth_cookie)

    # Phase-3 marker files — picked up by EngagementLoop on resume too.
    plan_dir = ws / "plan"
    plan_dir.mkdir(parents=True, exist_ok=True)
    if c2_profile:
        try:
            from network_pipeline.core.c2_profile import load_callback_profile
            load_callback_profile(c2_profile)  # validate up-front
        except Exception as e:
            click.echo(f"error: --c2-profile {c2_profile!r} failed to load: {e}", err=True)
            sys.exit(2)
        (plan_dir / "c2_profile.txt").write_text(c2_profile + "\n", encoding="utf-8")
    (plan_dir / "tot.flag").write_text("1\n" if tot else "", encoding="utf-8")
    (plan_dir / "nocritic.flag").write_text(
        "1\n" if not critic else "", encoding="utf-8",
    )
    (plan_dir / "adaptive.flag").write_text(
        "1\n" if adaptive_models else "", encoding="utf-8",
    )

    # ── Phase-4 markers ─────────────────────────────────────────────
    par = max(1, min(8, int(parallel)))
    (plan_dir / "parallel.txt").write_text(f"{par}\n", encoding="utf-8")
    if blue_telemetry:
        (plan_dir / "blue_telemetry.txt").write_text(
            blue_telemetry + "\n", encoding="utf-8",
        )
    if hmac_key:
        # hmac_key value is the engagement id; the actual 32-byte key
        # lives in ~/.config/network_pipeline/keys/<id>.key (created on
        # first run by load_or_create_key).
        (plan_dir / "hmac_key.txt").write_text(hmac_key + "\n", encoding="utf-8")
    if rag_index:
        (plan_dir / "rag_index.txt").write_text(rag_index + "\n", encoding="utf-8")

    # ── Pure-Python redesign markers (proxy / DNS / browser) ───────
    if proxy:
        (plan_dir / "proxy.txt").write_text(proxy + "\n", encoding="utf-8")
    if dns_resolver:
        (plan_dir / "dns_resolver.txt").write_text(dns_resolver + "\n", encoding="utf-8")
    (plan_dir / "browser.flag").write_text(
        "1\n" if browser else "", encoding="utf-8",
    )

    # Per-binary rate caps — populate the global registry before the
    # ShellRunner is constructed so the very first tool call respects them.
    if rates:
        from network_pipeline.core.rate_limit import (
            GLOBAL_RATE_LIMITS, parse_rate_flag,
        )
        for r in rates:
            try:
                binary, rps = parse_rate_flag(r)
            except ValueError as e:
                click.echo(f"error: bad --rate {r!r}: {e}", err=True)
                sys.exit(2)
            GLOBAL_RATE_LIMITS.set_rate(binary, rps)

    # Budget caps — written into the OPPLAN's BudgetState so resume
    # picks up where the prior run stopped.
    per_phase_caps: dict[str, int] = {}
    for spec in phase_budget:
        if ":" not in spec:
            click.echo(f"error: --phase-budget expects 'phase:tokens', got {spec!r}", err=True)
            sys.exit(2)
        ph, _, n = spec.partition(":")
        try:
            per_phase_caps[ph.strip()] = int(n)
        except ValueError:
            click.echo(f"error: --phase-budget tokens not an int in {spec!r}", err=True)
            sys.exit(2)

    if seed is not None or token_budget is not None or wall_budget is not None or per_phase_caps:
        from network_pipeline.agents.orchestrator import load_opplan, save_opplan
        from network_pipeline.core.schemas import BudgetState, SeedState
        opplan = load_opplan(ws)
        if opplan is not None:
            if seed is not None:
                opplan.seed = SeedState(seed=int(seed), seeded=True)
            opplan.budget = BudgetState(
                total_tokens=token_budget,
                total_seconds=wall_budget,
                per_phase_tokens=per_phase_caps,
                tokens_used=opplan.budget.tokens_used if opplan.budget else 0,
                seconds_used=opplan.budget.seconds_used if opplan.budget else 0.0,
                per_phase_used=(
                    opplan.budget.per_phase_used if opplan.budget else {}
                ),
            )
            save_opplan(ws, opplan)

    # Deferred import — pulls in langchain/langgraph only when actually running
    from network_pipeline.core.engagement_loop import EngagementLoop

    provider_overrides = _parse_provider_roles(provider_roles)
    config = EngagementConfig(
        target=target,
        workspace=ws,
        max_iterations=max_iterations,
        iteration_max_seconds=iteration_timeout,
        ollama_base_url=ollama_url,
        profile=profile,
        provider_overrides=provider_overrides,
        openai_base_url=openai_base_url,
        anthropic_base_url=anthropic_base_url,
        budget_usd=budget_usd,
        structured_reasoning=structured_reasoning,
        cop_enabled=cop,
    )
    loop = EngagementLoop(config)
    state = asyncio.run(loop.run())
    click.echo(json.dumps(state.summary, indent=2, default=str))


@cli.command()
@click.argument("workspace", type=click.Path(exists=True))
@click.option("--format", "fmt", default="json",
              type=click.Choice(["json", "sarif", "graph",
                                 "hackerone_md", "bugcrowd_csv"]))
@click.option("--out", "out", default=None,
              help="Output path (defaults to workspace/report.<fmt>)")
def report(workspace: str, fmt: str, out: str | None) -> None:
    """Emit a report from findings.jsonl.

    Formats:
      json          — rich JSON report (schema v2) for downstream tooling.
      sarif         — minimal SARIF 2.1.0 for IDE / CI annotation.
      graph         — Phase-7 Mermaid attack-chain (.mmd).
      hackerone_md  — Phase-8 directory of one .md per HIGH/CRITICAL
                      finding plus an index.md.
      bugcrowd_csv  — Phase-8 Bugcrowd VRT-aligned CSV (single file).
    """
    ws = validate_workspace(Path(workspace))
    from network_pipeline.tools.kg import FindingsLog
    from network_pipeline.tools.report import (
        write_bugcrowd_csv,
        write_hackerone_md,
        write_json_report,
        write_mermaid_attack_chain,
        write_sarif_report,
    )

    if fmt == "graph":
        target = Path(out) if out else (ws / "attack_chain.mmd")
        path = write_mermaid_attack_chain(ws, target)
        click.echo(f"mermaid attack-chain written: {path}")
        return

    findings = FindingsLog(ws / "findings.jsonl").all()

    if fmt == "hackerone_md":
        target = Path(out) if out else (ws / "report_hackerone")
        path = write_hackerone_md(findings, target, workspace=ws)
        click.echo(f"hackerone report dir: {path}  ({len(findings)} findings scanned)")
        return
    if fmt == "bugcrowd_csv":
        target = Path(out) if out else (ws / "report_bugcrowd.csv")
        path = write_bugcrowd_csv(findings, target, workspace=ws)
        click.echo(f"bugcrowd csv written: {path}  ({len(findings)} findings)")
        return

    default_out = ws / f"report.{fmt}"
    target = Path(out) if out else default_out
    if fmt == "json":
        path = write_json_report(findings, target, workspace=ws)
    else:
        path = write_sarif_report(findings, target, workspace=ws)
    click.echo(f"report written: {path}  ({len(findings)} findings)")


@cli.command()
@click.argument("workspace", type=click.Path(exists=True))
def status(workspace: str) -> None:
    """Show the current engagement state."""
    ws = validate_workspace(Path(workspace))
    state = EngagementState.load(ws)
    if state is None:
        click.echo("(no state yet)")
        return
    click.echo(json.dumps(state.summary, indent=2, default=str))


@cli.command(name="autopilot")
@click.argument("prompt", nargs=-1, required=True)
@click.option("--out", "workspace", required=True, type=click.Path(),
              help="Engagement workspace directory.")
@click.option("--profile", default="", show_default=False,
              help="Model profile. Empty (default) auto-selects via credentials: "
                   "OPENAI_API_KEY only → openai_only; both keys → cloud_eco; "
                   "Ollama only → eco. Override with eco/max/cloud_eco/cloud_max/"
                   "hybrid/openai_only.")
@click.option("--budget-usd", type=float, default=None,
              help="Hard cap on cloud spend; engagement aborts when exceeded.")
@click.option("--max-iterations", type=int, default=20, show_default=True)
@click.option("--iteration-timeout", type=int, default=600, show_default=True)
@click.option("--auto-answer/--no-auto-answer", default=True,
              help="When True (default), if the engagement raises a question and "
                   "no operator is around, accept the question's default.")
@click.option("--pretty/--no-pretty", default=True,
              help="Decepticon-style condensed log output. Hides per-URL connect "
                   "errors; shows phase banners and severity-coloured findings.")
def autopilot(prompt: tuple[str, ...], workspace: str, profile: str,
              budget_usd: float | None, max_iterations: int,
              iteration_timeout: int, auto_answer: bool, pretty: bool) -> None:
    """One-prompt autonomous engagement.

    Example:
      python -m network_pipeline.cli autopilot \\
          "scan the LLM chatbot at http://localhost:3000" \\
          --out ~/np-ws/auto1 --budget-usd 5
    """
    from network_pipeline.agents.autopilot import (
        AutopilotConfig, pending_question, run_autopilot,
    )
    from network_pipeline.core.pretty_log import (
        banner, install_pretty_logging, kv,
    )

    ws = Path(workspace).expanduser().resolve()
    ws.mkdir(parents=True, exist_ok=True)
    init_workspace(ws)
    attach_pipeline_log(ws)

    if pretty:
        install_pretty_logging()

    text = " ".join(prompt).strip()
    if pretty:
        banner("network_pipeline · autopilot")
        kv("target", text)
        kv("workspace", str(ws))
        kv("profile", profile or "auto-select")
        if budget_usd is not None:
            kv("budget cap", f"${budget_usd:.2f}")
        kv("max iters", str(max_iterations))
    else:
        click.echo(f"[autopilot] target prompt: {text!r}")
        click.echo(f"[autopilot] workspace:     {ws}")

    def _ask_terminal(question: dict) -> str:
        click.echo("")
        click.echo(f"[autopilot] question {question.get('id')} ({question.get('phase')})")
        click.echo(f"  {question.get('question')}")
        default = question.get("default") or ""
        suffix = f" [{default}]" if default else ""
        try:
            return click.prompt(f"  answer{suffix}", default=default, show_default=False)
        except click.Abort:
            return default

    handler = None if auto_answer else _ask_terminal
    cfg = AutopilotConfig(
        prompt=text, workspace=ws, profile=profile,
        budget_usd=budget_usd, max_iterations=max_iterations,
        iteration_timeout=iteration_timeout,
        auto_answer_defaults=auto_answer,
    )
    try:
        result = asyncio.run(run_autopilot(cfg, on_question=handler))
    except ValueError as e:
        click.echo(f"[autopilot] {e}", err=True)
        sys.exit(2)

    click.echo("")
    click.echo(f"[autopilot] engagement complete — {result.engagement_summary}")
    click.echo(f"[autopilot] plan files written under {ws / 'plan'}")
    if pending_question(ws):
        click.echo("[autopilot] WARNING: a question is still pending. "
                   "Answer with `cli answer-question <ws> ...` then re-run "
                   "`cli run <ws>` to resume.", err=True)


@cli.command(name="answer-question")
@click.argument("workspace", type=click.Path(exists=True))
@click.argument("answer", nargs=-1, required=True)
def answer_question(workspace: str, answer: tuple[str, ...]) -> None:
    """Resolve a pending plan/question.json. Clears the pause flag."""
    from network_pipeline.agents.autopilot import (
        pending_question, submit_answer,
    )

    ws = Path(workspace).expanduser().resolve()
    q = pending_question(ws)
    if q is None:
        click.echo("no pending question", err=True)
        sys.exit(1)
    submit_answer(ws, " ".join(answer))
    click.echo(f"answered question {q.get('id')}; re-run `cli run {ws}` to resume.")


@cli.command(name="selftest")
@click.option("--keep", is_flag=True, default=False,
              help="Keep the tmp workspace for inspection.")
def selftest(keep: bool) -> None:
    """Smoke-test every scanner / reporter against embedded fixtures.

    Inspired by `bumblebee selftest`. Exits non-zero on any failure.
    Run after install or in CI to confirm the pipeline is intact.
    """
    import tempfile
    failures: list[str] = []
    workdir = Path(tempfile.mkdtemp(prefix="np-selftest-"))
    try:
        # 1. Threat-intel catalogs load + parse.
        from network_pipeline.scanners.supply_chain_inventory import (
            load_catalogs, match_deps_against_catalogs, parse_package_json,
        )
        catalogs = load_catalogs()
        if not catalogs:
            failures.append("threat-intel catalogs failed to load")
        deps = parse_package_json(
            '{"dependencies": {"@types/node": "20.0.0"}}',
        )
        if not deps:
            failures.append("package.json parser produced no deps")
        match_deps_against_catalogs(deps)  # should not raise

        # 2. Principles library loads.
        from network_pipeline.core.principles import load_library, sample_compositions
        if len(load_library()) < 12:
            failures.append("CoP principles library missing entries")
        if not sample_compositions(size=2, count=1, seed=0):
            failures.append("CoP composer sampling failed")

        # 3. HRL reward maths.
        from network_pipeline.core.hrl_trajectory import (
            TrajectoryState, TurnObservation, compute_reward,
        )
        state = TrajectoryState(objective_id="X", target="t", intent="i")
        obs = TurnObservation(response_status=200, response_body="ok")
        rb = compute_reward(obs, state=state)
        if rb.total <= 0:
            failures.append("HRL compute_reward returned non-positive on clean turn")

        # 4. SIRAJ reasoning helpers.
        from network_pipeline.core.structured_reasoning import (
            REASONING_CONTRACT_BLOCK, parse_reasoning_block,
        )
        if "json" not in REASONING_CONTRACT_BLOCK:
            failures.append("SIRAJ contract block malformed")
        if parse_reasoning_block("free-form prose").valid:
            failures.append("SIRAJ parser accepted free-form prose")

        # 5. KG + attack-graph writers.
        from network_pipeline.tools.kg import (
            KnowledgeGraph, NodeType, EdgeType,
        )
        kg = KnowledgeGraph(workdir / "kg.json")
        kg.add_defense_action(
            action_id="REC-1", title="t", finding_ids=["F1"],
        )
        kg.add_verification(action_id="REC-1", finding_id="F1", verified=True)
        snap = kg.snapshot()
        if not any(e["relation"] == EdgeType.VERIFIED for e in snap["edges"]):
            failures.append("KG VERIFIED edge not emitted")

        # 6. Reporters produce well-formed output.
        from network_pipeline.tools.report import (
            write_bugcrowd_csv, write_hackerone_md, write_mermaid_attack_chain,
        )
        bc = write_bugcrowd_csv([], workdir / "bc.csv")
        if not bc.exists():
            failures.append("bugcrowd reporter did not write file")
        ho = write_hackerone_md([], workdir / "h1")
        if not (ho / "index.md").exists():
            failures.append("hackerone reporter did not write index.md")
        mm = write_mermaid_attack_chain(workdir, workdir / "chain.mmd")
        if "flowchart" not in mm.read_text(encoding="utf-8"):
            failures.append("mermaid reporter produced malformed output")

        # 7. Provider/credential probe (must not raise).
        from network_pipeline.llm.credentials import available_providers
        statuses = available_providers("http://127.0.0.1:1")
        if set(statuses.keys()) != {"openai", "anthropic", "ollama"}:
            failures.append("credentials probe returned unexpected providers")

        # 8. Agent registry has all expected phases.
        from network_pipeline.agents.registry import discover
        from network_pipeline.core.schemas import ObjectivePhase
        reg = discover(force=True)
        for needed in (ObjectivePhase.RECON, ObjectivePhase.SCAN,
                       ObjectivePhase.INITIAL_ACCESS,
                       ObjectivePhase.LLM_REDTEAM):
            if needed not in reg:
                failures.append(f"agent registry missing phase {needed.value}")
    finally:
        if not keep:
            import shutil
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            click.echo(f"[selftest] workspace kept at {workdir}")

    if failures:
        click.echo("[selftest] FAILED:")
        for f in failures:
            click.echo(f"  - {f}", err=True)
        sys.exit(1)
    click.echo("[selftest] OK — every scanner / reporter / catalog probe passed.")


@cli.group(name="soundwave")
def soundwave_grp() -> None:
    """Phase-5: interview-driven planner (RoE / ConOps / Deconfliction / OPPLAN)."""


@soundwave_grp.command(name="interview")
@click.argument("workspace", type=click.Path())
@click.option("--target", default="", help="Target hint (URL/domain/CIDR) used as a default.")
def soundwave_interview(workspace: str, target: str) -> None:
    """Run the interactive interview and write the four plan files."""
    from network_pipeline.agents.soundwave import run_interview

    ws = Path(workspace).expanduser().resolve()
    ws.mkdir(parents=True, exist_ok=True)
    init_workspace(ws)
    run_interview(ws, target_hint=target)


@soundwave_grp.command(name="validate")
@click.argument("workspace", type=click.Path(exists=True))
def soundwave_validate(workspace: str) -> None:
    """Schema-validate every plan artifact; non-zero exit on error."""
    from network_pipeline.agents.soundwave import validate_plan

    ws = Path(workspace).expanduser().resolve()
    report = validate_plan(ws)
    for w in report.warnings:
        click.echo(f"warn: {w}", err=True)
    for e in report.errors:
        click.echo(f"error: {e}", err=True)
    if not report.ok:
        sys.exit(2)
    click.echo("plan: OK")


@soundwave_grp.command(name="review")
@click.argument("workspace", type=click.Path(exists=True))
@click.option("--reviewer", default="",
              help="Reviewer handle. Defaults to $USER / $USERNAME, then prompts.")
@click.option("--no-editor", is_flag=True, default=False,
              help="Skip $EDITOR open; just stamp reviewed_by + reviewed_at.")
def soundwave_review(workspace: str, reviewer: str, no_editor: bool) -> None:
    """Open each plan file in $EDITOR and stamp roe.reviewed_by."""
    from network_pipeline.agents.soundwave import review_plan

    ws = Path(workspace).expanduser().resolve()
    roe = review_plan(ws, reviewer=reviewer, open_editor=not no_editor)
    click.echo(f"reviewed_by={roe.reviewed_by} at {roe.reviewed_at}")


@cli.command(name="auto")
@click.option("--target", required=True, help="Primary target (URL, domain, or CIDR)")
@click.option("--root", default="",
              help="Parent dir for per-target folders. Default: <package>/engagements/")
@click.option("--in-scope", multiple=True,
              help="Additional in-scope entries 'type:value' (e.g. 'cidr:10.0.0.0/24')")
@click.option("--out-of-scope", "out_of_scope_entries", multiple=True,
              help="Out-of-scope entries 'type:value'. Repeatable.")
@click.option("--engagement-name", default="",
              help="Human-readable engagement label")
@click.option("--profile", default="eco", help="Model profile: eco | max | test")
@click.option("--ollama-url", default="http://localhost:11434",
              help="Ollama server URL (use --ollama-url http://<remote>:11434 for remote)")
@click.option("--max-iterations", default=30, type=int)
@click.option("--iteration-timeout", default=600, type=int)
# Phase-1
@click.option("--seed", type=int, default=None)
@click.option("--token-budget", type=int, default=None)
@click.option("--wall-budget", type=int, default=None)
@click.option("--phase-budget", multiple=True)
@click.option("--rate", "rates", multiple=True)
# Phase-2
@click.option("--playbook", default="owasp_top10", show_default=True,
              help="MITRE/OWASP playbook driving objective synthesis")
@click.option("--web-mode", is_flag=True, default=False,
              help="Shortcut: --playbook owasp_top10 if no --playbook given")
@click.option("--auth-cookie", default="")
# Phase-3
@click.option("--c2-profile", default="balanced", show_default=True,
              type=click.Choice(["", "stealth", "balanced", "loud"]))
@click.option("--tot/--no-tot", default=False)
@click.option("--critic/--no-critic", default=True)
@click.option("--adaptive-models/--no-adaptive-models", default=False)
# Phase-4
@click.option("--parallel", type=int, default=1)
@click.option("--blue-telemetry", default="")
@click.option("--hmac-key", default="",
              help="Engagement id used to derive the HMAC key (auto-derived from target+timestamp when empty)")
@click.option("--rag-index", default="")
# Auto-mode controls
@click.option("--report-formats", default="sarif,json", show_default=True,
              help="Comma-separated list of formats to emit at the end")
def auto(target, root, in_scope, out_of_scope_entries,
         engagement_name, profile, ollama_url, max_iterations, iteration_timeout,
         seed, token_budget, wall_budget, phase_budget, rates,
         playbook, web_mode, auth_cookie,
         c2_profile, tot, critic, adaptive_models,
         parallel, blue_telemetry, hmac_key, rag_index,
         report_formats):
    """ONE-SHOT engagement: plan + run + verify + report.

    Creates ``<root>/<target-slug>/<timestamp>/`` automatically and
    fills it with every artefact the engagement produced. Supplies
    sensible Phase-1..4 defaults so you can drop a target URL and get
    a complete audit package back without remembering every flag.

    Example:

        python -m network_pipeline.cli auto \\
            --target https://shop.example.com \\
            --in-scope domain:shop.example.com \\
            --auth-cookie 'session=abc' \\
            --ollama-url http://10.0.0.5:11434 \\
            --hmac-key shopex-2026-04
    """
    from network_pipeline.core.auto import (
        default_engagement_root, finalise_meta, make_engagement_dir,
        slugify_target, update_stage, write_initial_meta,
    )

    # ── Step 0: Resolve workspace ───────────────────────────────────
    # Default to the in-package engagements/ folder so the audit trail
    # lives next to the code. Operator can override with any path.
    if not root:
        root_path = default_engagement_root()
    else:
        root_path = Path(os.path.expanduser(root)).resolve()
    root_path.mkdir(parents=True, exist_ok=True)
    ws = make_engagement_dir(root_path, target)
    ws = validate_workspace(ws)
    attach_pipeline_log(ws)
    click.echo(f"[auto] workspace = {ws}")

    # Auto-derive HMAC engagement id when caller didn't pass one.
    if not hmac_key:
        hmac_key = f"{slugify_target(target)}-{ws.name}"
        click.echo(f"[auto] hmac engagement id = {hmac_key}")

    # ── Step 1: write initial metadata ──────────────────────────────
    flags_recorded = {
        "max_iterations": max_iterations,
        "iteration_timeout": iteration_timeout,
        "seed": seed,
        "token_budget": token_budget,
        "wall_budget": wall_budget,
        "phase_budget": list(phase_budget),
        "rates": list(rates),
        "playbook": playbook,
        "web_mode": web_mode,
        "c2_profile": c2_profile,
        "tot": tot,
        "critic": critic,
        "adaptive_models": adaptive_models,
        "parallel": parallel,
        "blue_telemetry": blue_telemetry,
        "hmac_engagement_id": hmac_key,
        "rag_index": rag_index,
        "report_formats": report_formats,
    }
    in_scope_strs = [str(s) for s in in_scope]
    out_of_scope_strs = [str(s) for s in out_of_scope_entries]
    write_initial_meta(
        workspace=ws,
        target=target,
        in_scope=in_scope_strs,
        out_of_scope=out_of_scope_strs,
        engagement_name=engagement_name,
        ollama_base_url=ollama_url,
        profile=profile,
        flags=flags_recorded,
    )

    # ── Step 2: PLAN ────────────────────────────────────────────────
    update_stage(ws, "plan", "running")
    try:
        # Build RoE
        entries = [_entry_from(target)]
        for s in in_scope_strs:
            if ":" in s:
                kind, value = s.split(":", 1)
                entries.append(ScopeEntry(target=value, type=kind))
            else:
                entries.append(ScopeEntry(target=s, type="domain"))
        out_entries = []
        for s in out_of_scope_strs:
            if ":" in s:
                kind, value = s.split(":", 1)
                out_entries.append(ScopeEntry(target=value, type=kind))
        roe = RoE(
            engagement_name=engagement_name or f"engagement-{slugify_target(target)}",
            in_scope=entries,
            out_of_scope=out_entries,
        )
        _save_roe(ws, roe)
        _seed_opplan(ws, target)
        # Pre-validate playbook
        pb_choice = playbook
        if web_mode and not pb_choice:
            pb_choice = "owasp_top10"
        if pb_choice:
            from network_pipeline.core.playbook import load_playbook
            pb = load_playbook(pb_choice)
            (ws / "plan" / "playbook.txt").write_text(
                pb_choice + "\n", encoding="utf-8",
            )
            click.echo(f"[auto] playbook loaded: {pb.name} ({len(pb.steps)} steps)")
        # Auth cookie
        if auth_cookie:
            from network_pipeline.tools.web.auth_replay import AuthStore
            AuthStore(ws).update_from_cookie_header(target, auth_cookie)
            click.echo(f"[auto] auth seeded for {slugify_target(target)}")
        # Phase-3/4 markers
        plan_dir = ws / "plan"
        if c2_profile:
            from network_pipeline.core.c2_profile import load_callback_profile
            load_callback_profile(c2_profile)
            (plan_dir / "c2_profile.txt").write_text(
                c2_profile + "\n", encoding="utf-8",
            )
        (plan_dir / "tot.flag").write_text(
            "1\n" if tot else "", encoding="utf-8",
        )
        (plan_dir / "nocritic.flag").write_text(
            "1\n" if not critic else "", encoding="utf-8",
        )
        (plan_dir / "adaptive.flag").write_text(
            "1\n" if adaptive_models else "", encoding="utf-8",
        )
        (plan_dir / "parallel.txt").write_text(
            f"{max(1, min(8, int(parallel)))}\n", encoding="utf-8",
        )
        if blue_telemetry:
            (plan_dir / "blue_telemetry.txt").write_text(
                blue_telemetry + "\n", encoding="utf-8",
            )
        if hmac_key:
            (plan_dir / "hmac_key.txt").write_text(
                hmac_key + "\n", encoding="utf-8",
            )
        if rag_index:
            (plan_dir / "rag_index.txt").write_text(
                rag_index + "\n", encoding="utf-8",
            )
        update_stage(ws, "plan", "ok",
                     opplan=str(ws / "plan" / "opplan.json"),
                     roe=str(ws / "plan" / "roe.json"))
    except Exception as e:
        update_stage(ws, "plan", "failed", error=repr(e))
        click.echo(f"[auto] plan stage failed: {e}", err=True)
        sys.exit(2)

    # ── Step 3: seed budgets/seed/rate caps ────────────────────────
    if seed is not None:
        from network_pipeline.core.seed import seed_all
        seed_all(seed)
    if rates:
        from network_pipeline.core.rate_limit import (
            GLOBAL_RATE_LIMITS, parse_rate_flag,
        )
        for r in rates:
            try:
                binary, rps = parse_rate_flag(r)
                GLOBAL_RATE_LIMITS.set_rate(binary, rps)
            except ValueError as e:
                click.echo(f"[auto] bad --rate {r!r}: {e}", err=True)
    per_phase_caps: dict[str, int] = {}
    for spec in phase_budget:
        if ":" in spec:
            ph, _, n = spec.partition(":")
            try:
                per_phase_caps[ph.strip()] = int(n)
            except ValueError:
                pass
    if seed is not None or token_budget is not None or wall_budget is not None or per_phase_caps:
        from network_pipeline.agents.orchestrator import load_opplan, save_opplan
        from network_pipeline.core.schemas import BudgetState, SeedState
        opplan = load_opplan(ws)
        if opplan is not None:
            if seed is not None:
                opplan.seed = SeedState(seed=int(seed), seeded=True)
            opplan.budget = BudgetState(
                total_tokens=token_budget,
                total_seconds=wall_budget,
                per_phase_tokens=per_phase_caps,
            )
            save_opplan(ws, opplan)

    # ── Step 4: RUN ─────────────────────────────────────────────────
    update_stage(ws, "run", "running")
    state_summary: dict[str, Any] = {}
    try:
        from network_pipeline.core.engagement_loop import EngagementLoop
        config = EngagementConfig(
            target=target,
            workspace=ws,
            max_iterations=max_iterations,
            iteration_max_seconds=iteration_timeout,
            ollama_base_url=ollama_url,
            profile=profile,
        )
        state = asyncio.run(EngagementLoop(config).run())
        state_summary = state.summary
        update_stage(ws, "run", "ok", summary=state_summary)
        click.echo(f"[auto] run complete: {state_summary}")
    except Exception as e:
        update_stage(ws, "run", "failed", error=repr(e))
        click.echo(f"[auto] run stage failed: {e}", err=True)
        # Continue to report stage anyway — partial results are valuable.

    # ── Step 5: VERIFY-EVIDENCE (when HMAC key set) ────────────────
    verify_report: dict[str, Any] | None = None
    if hmac_key:
        update_stage(ws, "verify", "running")
        try:
            from network_pipeline.core.evidence_chain import (
                default_key_path, load_or_create_key,
                verify_evidence as do_verify,
            )
            key_path = default_key_path(hmac_key)
            key = load_or_create_key(key_path) if key_path.exists() else None
            rep = do_verify(ws, key)
            verify_report = {
                "ok": rep.ok,
                "expected_root": rep.expected_root,
                "actual_root": rep.actual_root,
                "leaf_count": rep.leaf_count,
                "unsigned_findings": rep.unsigned_findings,
                "bad_signatures": rep.bad_signatures,
                "missing_sidecars": rep.missing_sidecars,
                "bad_sidecar_hashes": rep.bad_sidecar_hashes,
                "notes": rep.notes,
            }
            update_stage(ws, "verify", "ok" if rep.ok else "mismatch",
                         **verify_report)
            click.echo(f"[auto] verify-evidence: ok={rep.ok}")
        except Exception as e:
            update_stage(ws, "verify", "failed", error=repr(e))
            click.echo(f"[auto] verify stage failed: {e}", err=True)
    else:
        update_stage(ws, "verify", "skipped",
                     reason="no --hmac-key supplied (audit chain disabled)")

    # ── Step 6: REPORT ──────────────────────────────────────────────
    update_stage(ws, "report", "running")
    report_paths: dict[str, str] = {}
    try:
        from network_pipeline.tools.kg import FindingsLog
        from network_pipeline.tools.report import (
            write_json_report, write_sarif_report,
        )
        findings = FindingsLog(ws / "findings.jsonl").all()
        for fmt in [f.strip() for f in report_formats.split(",") if f.strip()]:
            target_path = ws / f"report.{fmt}"
            if fmt == "json":
                write_json_report(findings, target_path, workspace=ws)
            elif fmt == "sarif":
                write_sarif_report(findings, target_path, workspace=ws)
            else:
                click.echo(f"[auto] unknown --report-formats entry {fmt!r} — skipping")
                continue
            report_paths[fmt] = str(target_path)
            click.echo(f"[auto] report ({fmt}): {target_path}")
        update_stage(ws, "report", "ok",
                     formats=list(report_paths.keys()),
                     finding_count=len(findings))
    except Exception as e:
        update_stage(ws, "report", "failed", error=repr(e))
        click.echo(f"[auto] report stage failed: {e}", err=True)

    # ── Step 7: finalise metadata ──────────────────────────────────
    finalise_meta(
        workspace=ws,
        state_summary=state_summary,
        verify_report=verify_report,
        report_paths=report_paths,
    )

    # ── Step 8: terminal summary ───────────────────────────────────
    click.echo("")
    click.echo("=" * 64)
    click.echo("ENGAGEMENT COMPLETE")
    click.echo("=" * 64)
    click.echo(f"workspace:        {ws}")
    click.echo(f"engagement.meta:  {ws / 'engagement.meta.json'}")
    if state_summary:
        click.echo(
            f"summary:          phase={state_summary.get('phase')}, "
            f"iterations={state_summary.get('iteration')}, "
            f"completed={state_summary.get('completed')}, "
            f"blocked={state_summary.get('blocked')}, "
            f"findings={state_summary.get('findings')}"
        )
    if verify_report:
        click.echo(
            f"verify-evidence:  ok={verify_report['ok']} "
            f"leaves={verify_report['leaf_count']}"
        )
    for fmt, p in report_paths.items():
        click.echo(f"report ({fmt}):  {p}")
    click.echo("=" * 64)


@cli.command(name="verify-evidence")
@click.argument("workspace", type=click.Path(exists=True))
@click.option("--hmac-key", default="",
              help="Engagement id whose key validates HMAC signatures")
def verify_evidence(workspace: str, hmac_key: str) -> None:
    """Phase-4: independently re-derive the Merkle root + check signatures.

    Read-only — never deletes or rewrites data. Distinguishes
    "unsigned legacy" from "signature mismatch" so a missing key
    doesn't look like tampering.
    """
    ws = validate_workspace(Path(workspace))
    from network_pipeline.core.evidence_chain import (
        default_key_path, load_or_create_key, verify_evidence as do_verify,
    )

    key: bytes | None = None
    eng_id = hmac_key.strip()
    if not eng_id:
        # Try the marker file recorded by `run --hmac-key <id>`.
        marker = ws / "plan" / "hmac_key.txt"
        if marker.exists():
            eng_id = marker.read_text(encoding="utf-8").strip()
    if eng_id:
        key_path = default_key_path(eng_id)
        if key_path.exists():
            key = load_or_create_key(key_path)

    report = do_verify(ws, key)
    payload = {
        "ok": report.ok,
        "expected_root": report.expected_root,
        "actual_root": report.actual_root,
        "leaf_count": report.leaf_count,
        "unsigned_findings": report.unsigned_findings,
        "bad_signatures": report.bad_signatures,
        "missing_sidecars": report.missing_sidecars,
        "bad_sidecar_hashes": report.bad_sidecar_hashes,
        "notes": report.notes,
    }
    click.echo(json.dumps(payload, indent=2))
    sys.exit(0 if report.ok else 1)


@cli.command(name="serve")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. Use 0.0.0.0 to expose on the LAN — "
                   "do NOT do that on an untrusted network without auth.")
@click.option("--port", type=int, default=8000, show_default=True)
@click.option("--root", default="",
              help="Per-target engagement root directory. Default: <package>/engagements/")
@click.option("--ollama-url", default="http://localhost:11434", show_default=True)
@click.option("--profile", default="eco", show_default=True,
              help="Model profile: eco | max | test")
@click.option("--rag-index", default="",
              help="Path to a JSON RAG index. Every engagement absorbs into "
                   "+ recalls from this shared store. Requires "
                   "'nomic-embed-text' pulled on the Ollama server. "
                   "Default: <package>/engagements/rag_index.json")
def serve(host: str, port: int, root: str, ollama_url: str, profile: str,
          rag_index: str) -> None:
    """Start the FastAPI service for click-to-run engagements.

    Browse http://<host>:<port>/ for the UI; or POST /api/engagements
    against the curated allowlist at /api/targets.
    """
    try:
        import uvicorn  # type: ignore[import-not-found]
    except ImportError:
        click.echo(
            "error: uvicorn + fastapi not installed. Install with:\n"
            "  pip install -e \".[network,api]\"",
            err=True,
        )
        sys.exit(2)

    from network_pipeline.api.server import create_app
    from network_pipeline.core.auto import default_engagement_root

    if not root:
        report_root = default_engagement_root()
    else:
        report_root = Path(os.path.expanduser(root)).resolve()
    report_root.mkdir(parents=True, exist_ok=True)

    # Phase-4 RAG: empty default → use <reports_root>/rag_index.json
    # so the cross-engagement memory accumulates next to the
    # engagement folders. Operator can point at any path with
    # --rag-index. Empty string disables RAG; we use the default
    # path if not explicitly overridden.
    if rag_index == "":
        rag_index_path = str(report_root / "rag_index.json")
    else:
        rag_index_path = str(Path(os.path.expanduser(rag_index)).resolve())

    app = create_app(
        report_root=report_root,
        ollama_url=ollama_url,
        profile=profile,
        rag_index=rag_index_path,
    )
    click.echo(
        f"network_pipeline serve · http://{host}:{port}/ "
        f"(reports under {report_root})"
    )
    click.echo(f"RAG index: {rag_index_path}")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    cli()
