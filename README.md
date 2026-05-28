# network_pipeline

Autonomous LangGraph-based network security testing module. Lives inside
`Security_module/` alongside the OWASP ASI suite but is fully decoupled
— the two subsystems share only the `reporting/` emitters.

> **Setting up a fresh machine?** Start with **[SETUP.md](SETUP.md)** —
> a step-by-step install for both WSL2/Linux and native Windows
> (binaries, Python deps, Ollama, and PATH gotchas).
>
> **Something broken?** Check **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**
> — every issue we've hit in real installs with the fix that worked
> (PATH truncation, httpx shadowing, `Sentinel` import error, empty
> findings, dead targets, ...).
>
> **Just want the Python deps?** `pip install -e ".[network,api]"` from
> the `Security_module` root, or
> `pip install -r network_pipeline/requirements.txt`.

Ported from [Decepticon](https://github.com/example/decepticon) and
trimmed for local use:

| Decepticon                         | network_pipeline                       |
|------------------------------------|----------------------------------------|
| LiteLLM proxy (multi-provider)     | **Local Ollama** (`langchain-ollama`)  |
| Docker/Kali sandbox + tmux         | **Local subprocess** with jailed cwd   |
| Neo4j knowledge graph              | **JSON KG** with `filelock`            |
| 16 specialist agents               | **7** — orchestrator, recon, scanner, exploit, postexploit, analyst, defender |

## Hard requirements

**WSL2 is recommended on Windows.** Windows builds of
`nmap`/`nuclei`/`masscan` have argv and log-format differences that can
trip parsers, and Python `filelock` on `/mnt/c` DrvFs is silently broken
under concurrency. The CLI refuses to start on native Windows unless
`NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS=1` is set, and refuses to use a
workspace under `/mnt/` unless `NETWORK_PIPELINE_ALLOW_DRVFS_WORKSPACE=1`
is set.

Native Windows works for smoke tests if you set the override; see
**[SETUP.md → Track B](SETUP.md)** for the full procedure including the
non-obvious gotchas (PD `httpx` vs Python `httpx` PATH shadowing, the
`setx PATH` 1024-char truncation trap, etc.).

**Install these once (inside WSL2 / Linux):**

```bash
# Ollama + models
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b
ollama pull llama3.2:3b
ollama pull qwen2.5-coder:7b

# Network tools on PATH
sudo apt install -y nmap whois dnsutils curl
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Phase-2 web tools (OWASP Top 10 playbook coverage)
sudo apt install -y ffuf feroxbuster nikto sqlmap wapiti zaproxy
go install github.com/003random/getJS@latest
go install github.com/hahwul/dalfox/v2@latest
pipx install paramspider
pipx install arjun
# LinkFinder + jwt_tool ship as Python scripts:
pipx install linkfinder
pipx install jwt-tool

# Python deps (from the Security_module root)
pip install -e ".[network]"
```

Models optional per profile: use `--profile test` for `llama3.2:1b` only.

## Pointing at a remote Ollama instance

If Ollama runs on another machine (e.g. a GPU box on your LAN), pass
`--ollama-url`:

```bash
python -m network_pipeline.cli run ~/np-ws/run1 \
    --ollama-url http://10.0.0.5:11434 \
    --profile eco
```

The `eco` profile expects `llama3.1:8b`, `llama3.2:3b`, and
`qwen2.5-coder:7b` pulled on the remote. The startup probe lists any
missing models before launching the engagement loop.

## Phase-2: MITRE playbooks + web mode

Drive the pipeline with a deterministic technique chain:

```bash
python -m network_pipeline.cli plan --target http://localhost:3000 \
    --out ~/np-ws/run-web --in-scope cidr:127.0.0.0/8 \
    --playbook owasp_top10                  # or --web-mode shortcut

python -m network_pipeline.cli run ~/np-ws/run-web \
    --profile eco --max-iterations 30 \
    --rate sqlmap:0.5 --rate dalfox:1.0 \
    --auth-cookie 'session=abc123; lang=en'
```

Available built-in playbooks: `owasp_top10`, `mitre_initial_access`,
`mitre_credential_access`, `mitre_discovery`. Add your own under
`network_pipeline/skills/playbooks/<name>.yaml`.

## Quickstart

```bash
# 1. Start Ollama (in a separate WSL terminal)
ollama serve

# 2. Launch a juice-shop container as a lab target
docker run -d --rm -p 8080:3000 bkimminich/juice-shop

# 3. Initialise workspace (must live on WSL ext4, NOT /mnt/c)
mkdir -p ~/network_pipeline_workspace
python -m network_pipeline.cli plan \
    --target http://localhost:8080 \
    --out ~/network_pipeline_workspace/run1 \
    --in-scope cidr:127.0.0.0/8

# 4. Run the engagement loop
python -m network_pipeline.cli run ~/network_pipeline_workspace/run1 \
    --profile eco --max-iterations 10

# 5. Emit a report
python -m network_pipeline.cli report ~/network_pipeline_workspace/run1 \
    --format sarif
```

## Workspace layout

```
workspace/run1/
├── .engagement-state.json     # loop state (iteration, phase, history)
├── plan/
│   ├── roe.json               # Rules of Engagement (scope, prohibited actions)
│   └── opplan.json            # Objectives (PTES-style task tree)
├── kg.json                    # Knowledge graph: hosts, ports, services, credentials
├── kg.json.lock               # filelock sentinel
├── findings.jsonl             # Append-only findings log
├── defense_brief.json         # Vaccine-phase defender output
├── state_snapshots/           # Per-iteration LangGraph state dumps
├── agent_traces.log           # JSONL — one line per LLM exchange (post-mortem gold)
├── pipeline.log               # Human-readable engagement log
└── tool_io/<agent>/           # Raw stdout/stderr/argv of every subprocess
```

## Architecture

```
cli.py plan  ──▶  writes roe.json + starter opplan.json
cli.py run   ──▶  EngagementLoop.run() (async)
                    Phase ATTACK:
                        loop:
                          next pending objective in opplan.json
                          → dispatch phase-matched agent:
                              recon / scanner / exploit / postexploit
                          each agent uses:
                              - kg_* tools (filelock-guarded)
                              - record_finding
                              - read_skill_md (progressive disclosure)
                              - binary-specific wrappers (nmap, nuclei, ...)
                                returning <4 KB condensed summaries
                          update objective status
                    Phase VACCINE:
                        defender reads findings.jsonl
                        → write_defense_brief(...)
                    Phase COMPLETE
cli.py report ──▶  findings.jsonl → SARIF / JSON (reuses Security_module/reporting/)
```

## Security hardening

The shell layer enforces (see `tools/shell.py`):

- Binary allowlist (`nmap`, `httpx`, `nuclei`, `subfinder`, `dnsx`,
  `curl`, `whois`, `dig`, `masscan`) — **no freeform bash is exposed**.
- `shell=False` everywhere. argv lists only.
- Working-directory jail: subprocess cwd = workspace root.
- Target-scope enforcement: every invocation is checked against the
  RoE `in_scope` CIDR/domain list; out-of-scope calls fail loudly.
- Per-call timeout (default 300s), 5 MB stdout truncation.

The knowledge graph layer enforces (see `tools/kg.py`):

- `filelock.FileLock` around every mutation.
- Atomic write via `tmp + os.replace` — readers never see a half-written file.
- Append-only findings log (`findings.jsonl`) — no lock needed (POSIX
  O_APPEND atomic for short lines).

## Skills

The `skills/` tree is a verbatim copy of the network-relevant parts of
Decepticon's knowledge base (recon / scanner / exploit / post-exploit /
analyst / detector / shared). Agents see only the skills relevant to
their role (see `tools/skills.py::ROLE_TO_SKILL_DIRS`) and read files on
demand via the `read_skill_md` tool — they do not ingest everything
upfront.

## Observability (no LangSmith required)

Every LLM exchange is logged as JSONL to `agent_traces.log` with:

- agent name, iteration, phase, engagement id
- model name, latency, response text (truncated at 8 KB)
- tool calls with input/output previews

Set `LANGCHAIN_API_KEY` to additionally mirror to LangSmith. The offline
traces remain authoritative.

## Parity with Decepticon

### Ported (pipeline-critical)

- 7 sub-agents: orchestrator, recon, scanner, exploit, postexploit,
  analyst, defender, **verifier** (vaccine re-attack validator).
- Ralph-mode async engagement loop (ATTACK → VACCINE → COMPLETE).
- Pydantic schemas: `RoE`, `CONOPS`, `OPPLAN`, `Objective`, `Finding`,
  `Evidence`, enums incl. `ObjectivePhase`, `OpsecLevel`, `C2Tier`,
  `RemediationPriority`, `FindingSeverity`, `FindingConfidence`.
- **Finding-protocol gate** enforced at schema layer: HIGH/CRITICAL
  requires `confidence=verified` AND ≥2 `verified_methods`.
- **Detection-gap tracking**: `Finding.detected`, `detection_notes` so
  purple-team engagements can score SOC efficacy.
- **Skills tree** copied verbatim from Decepticon's
  network-relevant subset (recon, scanner, exploit, post-exploit,
  analyst, detector, shared). Agents use progressive disclosure via
  `read_skill_md`.
- **OPSEC + C2 tier injection**: each sub-agent prompt is dynamically
  augmented with the current objective's `opsec` and `c2_tier` so
  agents self-regulate tool choice.
- **KG ingest helpers**: `ingest_nmap_xml`, `ingest_nuclei_jsonl`,
  `ingest_subfinder`, `ingest_httpx_jsonl`, `ingest_dnsx_jsonl`,
  `ingest_masscan` — agents don't waste context parsing tool output.
- **Shell hardening**: binary allowlist, `shell=False`, `cwd` jail,
  dangerous-token refusal (pkill/killall/shutdown/reboot/mkfs/dd/inline
  Lua in `--script=`), ANSI stripping, repetitive-line compression,
  5 MB truncation, per-call timeout, scope guard.
- **Offline observability**: `agent_traces.log` JSONL with
  per-LLM-exchange latency, tool calls, response previews; optional
  LangSmith mirror.

### Intentionally dropped

- Docker sandbox / tmux sessions → replaced with jailed subprocess.
- Neo4j → JSON KG + `filelock` + atomic `tmp + os.replace`.
- LiteLLM proxy → direct `langchain-ollama` with per-role timeouts
  and retry.
- AD / cloud / smart-contract / binary-reversing agents — not
  applicable to network scope.
- Web/CLI Decepticon clients — use the `network-pipeline` CLI.
- Interactive tmux shells → non-applicable with subprocess.

### Partial / deferred

- Token-accurate context trimming: conservative `tiktoken` ceiling
  (65 %/50 %) instead of per-tokenizer precise counting. Opt in to
  `transformers`-backed counting with the `network-precise` extra.
- Orchestrator `summarize_history` tool: deferred — filesystem-backed
  state (OPPLAN + KG + findings) is the primary long-horizon memory.
- Strict LangGraph state reducer for message trimming: the default
  create_react_agent messages channel is used; each sub-agent spawns
  fresh per iteration so cross-iteration bloat is not a concern.

## Relationship to the ASI suite

The network pipeline writes findings using the same severity taxonomy as
`Security_module.models.enums.Severity`, and the report adapter
(`tools/report.py`) hands off to `Security_module/reporting/` emitters
when available. You can run both pipelines against the same target and
combine reports, but they do not share state and can be run
independently.
