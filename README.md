# network-pipeline

> An autonomous, multi-agent offensive-security pipeline that runs the full
> pentest loop — reconnaissance → scanning → exploitation → post-exploit →
> reporting — across network, web, and LLM targets, with a causal knowledge
> graph chaining evidence between every step.

`network-pipeline` is a LangGraph-driven orchestrator that routes work
across a fleet of specialised agents (Recon, Scanner, Exploit, Defender,
Verifier, Analyst, LLM-Redteam) and 100+ scanners. A hierarchical RL
planner picks the next action under a budget, a Tree-of-Thoughts planner
explores alternative attack paths, and every finding is chained through a
causal knowledge graph so reports show *exactly* how one weak signal led to
the next.

> ⚠️ **Use only against systems you are explicitly authorised to test.**

---

## High-level architecture

```
                ┌────────────────────────────────────┐
                │           Orchestrator             │
                │  (LangGraph state machine,         │
                │   HRL trajectory + ToT planner,    │
                │   budget + critic + supervisor)    │
                └─────────────────┬──────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
   Recon agent              Scanner agent             Exploit agent
   • passive DNS            • port scan               • SQLi / XSS
   • whois                  • web audit               • mass-assignment
   • subdomain enum         • TLS / JWT scan          • BOLA, SSRF, RCE
   • cert + JS endpoints    • OpenAPI / GraphQL       • Sliver C2 helpers
                            • LLM-target probes
        │                         │                         │
        └────────────┬────────────┴─────────────┬───────────┘
                     ▼                          ▼
              Defender agent              Verifier agent
              • deception traces          • re-runs PoCs
              • detection ingest          • integrity hashes
                     │                          │
                     └────────────┬─────────────┘
                                  ▼
                            Analyst agent
                            • finding synthesis
                            • attack-chain assembly
                            • skill / playbook lookup
                                  │
                                  ▼
                          Causal Knowledge Graph
                          (entities, signals,
                           evidence, exploit edges)
                                  │
                                  ▼
                          Report emitters
                          ├─ report.json
                          ├─ report.sarif
                          ├─ report_bugcrowd.csv
                          ├─ report_hackerone/
                          └─ attack_chain.mmd
```

---

## The engagement loop

Every run is an **engagement** — a persisted state object that lives under
`workspace/<engagement_id>/`. The loop:

1. **Plan** — `cli plan` builds an initial playbook from the target profile
   (`sample_configs/lab_target.json`) and a chosen profile (stealth /
   balanced / loud). The Tree-of-Thoughts planner generates candidate paths
   and ranks them under the budget.

2. **Run** — `cli run` (or `cli autopilot`) advances the LangGraph state
   machine one step at a time. The HRL trajectory chooses which agent /
   skill / tool to invoke; the supervisor blocks unsafe actions; the
   critic re-scores after each step.

3. **Recon** — passive enrichment (DNS, whois, certs) → active enumeration
   (subdomains, content discovery, JS endpoint extraction). Findings land
   in the causal KG as `recon-signal` nodes.

4. **Scan** — drives 100+ scanners across HTTP, TLS, JWT, GraphQL,
   OpenAPI, SQLi, XSS, BOLA, mass-assignment, request smuggling, supply
   chain, websocket. LLM-target scanners cover prompt injection, RAG
   poisoning, persona probing, jailbreak co-op, multi-turn jailbreak.

5. **Exploit** — turns a finding + a SKILL pack into a concrete PoC.
   Tool wrappers (`tools/web/`, `tools/exploit.py`) shell out to nmap,
   sqlmap, ffuf, feroxbuster, ZAP, nuclei, JWT-tool, paramspider, etc.,
   capturing structured output via `tools/output_schemas.py`.

6. **Verify** — re-runs the PoC, hashes the response, and produces an
   integrity-chain proof. Failed verifications fall back into the planner.

7. **Synthesize** — the Analyst merges related findings into one
   attack-chain object, attaches evidence pointers, and emits the final
   report formats listed above.

8. **Defend (optional)** — `agents/defender.py` consumes detection logs to
   simulate blue-team response, producing a Soundwave deception trace for
   training data.

The whole loop is reproducible: every engagement carries a deterministic
`seed`, and `core/argv_guard.py` blocks commands whose arguments would step
outside the agreed scope.

---

## The Causal Knowledge Graph

`core/causal_kg.py` stores every observation, hypothesis, exploit attempt,
and verification as a node with typed edges:

- `recon-signal → scanner-hit → finding → exploit-attempt → verification`
- `finding ─supports─→ finding` (corroboration)
- `finding ─enables─→ exploit-attempt` (chain)
- `exploit-attempt ─causes─→ finding` (post-exploit discovery)

Reports use the graph to render Mermaid attack-chain diagrams
(`attack_chain.mmd`) and to populate SARIF `relatedLocations`.

---

## Multi-provider LLM routing

`llm/` ships clients for OpenAI, Anthropic, and Ollama. The factory
(`llm/factory.py`) selects a provider per role from `llm/profiles.py` so a
single engagement can use, e.g., Claude for planning, GPT for code-heavy
exploit synthesis, and Ollama for cheap classification. Built-in
rate-limit and cost guards live in `llm/ratelimit.py` and `llm/cost.py`,
and credentials route through `llm/credentials.py` (never logged).

---

## Skills, playbooks, and principles

The pipeline is **policy-driven**:

- `skills/analyst/` — one folder per vulnerability class
  (`auth-bypass/`, `command-injection/`, `idor/`, `prompt-injection/`,
  `sql-injection/`, `ssti/`, `ssrf/`, `xxe/`, `xss-to-takeover/`, …),
  each with a `SKILL.md` that the Analyst agent loads as context.
- `skills/checks/cves/` — YAML CVE checks (Log4Shell, Spring Boot
  Actuator, etc.) loaded by the scanner.
- `skills/playbooks/` — MITRE ATT&CK playbooks
  (`mitre_initial_access.yaml`, `mitre_credential_access.yaml`,
  `mitre_discovery.yaml`, `owasp_top10.yaml`, `llm_target.yaml`).
- `skills/principles/library.yaml` — global rules (e.g.,
  no-destructive-actions, no-pivot-outside-scope) applied by the Cop
  Composer (`agents/cop_composer.py`).
- `skills/profiles/` — three stealth profiles (stealth / balanced /
  loud) tune timing, retries, and noise.

---

## Quickstart

```bash
git clone https://github.com/krishddd/network-pipeline.git
cd network-pipeline
pip install -r requirements.txt
cp .env.example .env  # add provider keys

# Single-engagement CLI
python cli.py plan --target sample_configs/lab_target.json --profile balanced
python cli.py run --engagement <id>

# Or run end-to-end
python cli.py autopilot --target sample_configs/lab_target.json

# Or use the API
python -m api.server                # FastAPI on :8000
# POST /engagements with { "target": "https://example.com", "profile": "stealth" }
```

Generated reports land under `workspace/<engagement_id>/`:

- `report.json` — structured findings + chains
- `report.sarif` — SARIF v2.1 for IDE / SAST tool ingestion
- `report_bugcrowd.csv` — bug-bounty submission template
- `report_hackerone/` — one Markdown per finding for HackerOne
- `attack_chain.mmd` — Mermaid diagram of the causal graph

---

## Project structure

```
agents/         Recon, Scanner, Exploit, Defender, Verifier, Analyst,
                LLM-Redteam, Soundwave (deception), HRL Attacker,
                Orchestrator, Cop Composer, Post-exploit
api/            FastAPI control plane (server + runner + static dashboard)
browser/        Playwright session + auth flows (cookie / OAuth)
core/           Engagement loop, causal KG, HRL trajectory, ToT planner,
                budget, critic, supervisor, structured reasoning, episodic
                memory, RAG memory, detection ingest, evidence chain,
                model router, principles, seed, diff scan, c2 profile,
                argv guard, rate limit, pretty log, baseline scan
llm/            Multi-provider chat clients (anthropic / openai / ollama),
                profiles, factory, credentials, cost + rate-limit guards
scanners/       100+ scanners spanning HTTP, DNS, TLS, JWT, GraphQL,
                OpenAPI, SQLi, XSS, BOLA, mass-assignment, request
                smuggling, supply chain, websocket, subdomain takeover,
                content discovery, parameter mining, web crawler, web
                audit, dispatch wrappers (sqlmap), and LLM-target probes
skills/         Per-vulnerability SKILL.md packs, checks (CVE YAMLs +
                wordlists), MITRE / OWASP playbooks, stealth profiles,
                shared finding-protocol and references
tools/          Tool wrappers — exploit, integrity, kg, oast,
                output_schemas, recon, report, request_guard, runtime,
                scan, shell, skills, streaming + tools/web/ for
                arjun / dalfox / feroxbuster / ffuf / getjs /
                jwt_tool / linkfinder / nikto / paramspider /
                sqlmap / wapiti / zap_baseline / auth_replay
tests/          Unit + integration suites (LLM target tests, planner,
                argv guard, attack graph, auth replay, budget, cop
                principles, finding dedup, jwt scan, migrations,
                streaming, request guard, multi-provider LLM)
```

---

## Reproducibility & safety

- Every engagement carries a deterministic `seed`. Re-running with the same
  seed reproduces the same plan and tool ordering.
- `core/argv_guard.py` blocks shell commands whose flags or targets fall
  outside the engagement's scope file.
- `tools/request_guard.py` blocks HTTP requests outside scope at the wrapper
  layer.
- `core/principles.py` enforces global rules (`no-destroy`, `no-out-of-scope`,
  `respect-robots-txt-on-recon`).
- The Supervisor (`core/supervisor.py`) can pause or kill an engagement on
  policy violation.

---

## Status

Personal research project. Built to explore how far autonomous offensive
security agents can be pushed *safely*. Lab-target configs are provided —
do not run against production systems you do not own.

## License

MIT
