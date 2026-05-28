# Demo — autonomous red-team against `scanme.nmap.org`

A complete walk-through for demoing **network_pipeline**'s
*Offensive Adversary Emulation* (Decepticon-port, multi-agent
red-team) against a publicly-authorised target. The whole flow is
**one command** that produces structured findings + a Mermaid
attack-graph + HackerOne-style Markdown + Bugcrowd CSV.

## Why `scanme.nmap.org` (not `nmap.org`)

> `scanme.nmap.org` is the host the Nmap project explicitly authorises
> for public scanning. The Nmap homepage at `nmap.org` is **not** an
> authorised scan target. Demoing against the wrong host is a legal
> grey area. This walk-through always targets `http://scanme.nmap.org`.

The pipeline's curated allowlist at
[`api/targets.json`](api/targets.json) already pins
`scanme.nmap.org` with `scope_note: "passive + nmap only"` — the
scanner allowlist gate in `_apply_scanner_allowlist` strips
SQLi/XSS/sqlmap automatically when running against this target,
so the demo stays on the right side of the authorisation banner.

---

## One-time setup (≈3 minutes)

```powershell
# 1. From the network_pipeline directory:
cd C:\Users\hp\Downloads\Agent_security_testing\network_pipeline

# 2. Install Python deps (run once per machine).
pip install -r requirements.txt

# 3. Paste your OpenAI key into .env (already created from .env.example).
#    The file already exists at network_pipeline/.env — open it and replace
#    REPLACE_ME_WITH_YOUR_OPENAI_KEY with your real sk-... key.
notepad .env   # or your editor of choice

# 4. Confirm everything's wired correctly:
python -m network_pipeline.cli selftest
# Expected: "[selftest] OK - every scanner / reporter / catalog probe passed."
```

---

## The single-command demo

```powershell
python -m network_pipeline.cli autopilot `
    "scan the authorised pentest target at http://scanme.nmap.org" `
    --out .\runs\demo-nmap `
    --budget-usd 2.00 `
    --max-iterations 12
```

That's it. The autopilot will:

1. **Parse the prompt** → detects `http://scanme.nmap.org`, infers
   `network` target type, picks the `openai_only` profile because the
   `.env` only provided `OPENAI_API_KEY`.
2. **Synthesise the plan** → writes `runs/demo-nmap/plan/`:
   - `roe.json` — scope locked to `scanme.nmap.org`
   - `conops.json` — threat-actor narrative (autopilot-blackbox-external)
   - `deconfliction.json` — User-Agent attribution marker
   - `opplan.json` — 3 objectives (recon → scan → initial-access)
3. **Validate** the plan via the Phase-5 schema gate.
4. **Run the engagement loop** through every objective. You will see:
   - DNS + WHOIS + subdomain enumeration
   - Bumblebee-port supply-chain inventory scan
   - Port scan (nmap-style) limited by the allowlist
   - HTTP probe + TLS audit
   - CVE check against any discovered services
   - SIRAJ-structured reasoning in every agent turn
   - Live cost tracker streaming to stderr: `[cost] openai $0.18 | total $0.18`
5. **VACCINE phase** — defender writes `defense_brief.json` + `DefenseAction`
   nodes in the KG; verifier re-attacks and stamps `VERIFIED` edges.
6. **Reports auto-emit** to `runs/demo-nmap/` once the loop ends.

The whole run typically completes in **3–8 minutes** for under
**$0.30** of OpenAI spend at the `openai_only` profile defaults.

### Pause + resume

If you need to pause mid-demo, press `Ctrl+C`. The loop checkpoints
between iterations and writes `runs/demo-nmap/plan/pause.flag`.
Re-run the same `autopilot` command (or `python -m network_pipeline.cli
run runs/demo-nmap`) and it resumes from the checkpoint.

If a sub-agent ever needs operator input (rare in network mode), it
writes `plan/question.json` and pauses. With the default
`--auto-answer`, the autopilot accepts the embedded default and
continues. Pass `--no-auto-answer` to be prompted in the terminal.

---

## What the demo produces

Browse `runs/demo-nmap/` after the run. Files you'll want to show:

| File | What it is |
|---|---|
| `findings.jsonl` | Append-only line-per-finding ground truth. |
| `report.json` | Rich JSON: executive summary, top-5 priority, coverage stats, per-finding detail. **Generate via** `python -m network_pipeline.cli report runs/demo-nmap --format json` |
| `report.sarif` | GitHub Code-Scanning-ready SARIF 2.1.0. |
| `attack_chain.mmd` | Mermaid attack-graph (Vulnerability → DefenseAction → VERIFIED). Paste into a GitHub-flavoured Markdown file or render with `mmdc`. |
| `report_hackerone/index.md` | One Markdown file per HIGH/CRITICAL finding in HackerOne report format. |
| `report_bugcrowd.csv` | Bugcrowd VRT-mapped CSV (P1–P5 priority, vrt bucket from CWE). |
| `kg.json` | Persistent knowledge graph (hosts, ports, services, vulns, defenses + edges). |
| `agent_traces.log` | JSONL of every LLM exchange — latency, tokens, cost, SIRAJ reasoning compliance. **The post-mortem gold.** |
| `pipeline.log` | Human-readable engagement log. |
| `defense_brief.json` | Defender's mitigation recommendations. |
| `verification_results.json` | Verifier re-attack outcomes. |

Generate every reporter at the end of the demo (one command each):

```powershell
python -m network_pipeline.cli report runs\demo-nmap --format json
python -m network_pipeline.cli report runs\demo-nmap --format sarif
python -m network_pipeline.cli report runs\demo-nmap --format hackerone_md
python -m network_pipeline.cli report runs\demo-nmap --format bugcrowd_csv
python -m network_pipeline.cli report runs\demo-nmap --format graph
```

---

## Suggested demo narrative (≈10 minutes)

1. **Setup (30s)** — show `.env` with the OpenAI key + `selftest` passing.
2. **Run autopilot (5–8 min)** — run the single command, narrate as the
   live `[cost]` line ticks up and the agent traces stream. While
   waiting, explain the **8 building blocks** the pipeline composes:
   - Multi-provider LLM gateway (today: OpenAI-only)
   - SIRAJ structured reasoning compression
   - CoP multi-principle payload composition with Dual-Judge
   - HRL multi-turn trajectory attacker
   - Soundwave interactive planner (auto-driven here)
   - LLM-target red-team module (Phase 6 — not in this demo)
   - NetworkX attack-graph with MITIGATES/VERIFIED edges
   - HITL pause/resume + Bumblebee-port supply-chain scanner
3. **Open `pipeline.log`** — show the iteration boundaries, the recon →
   scan → initial-access progression, the budget governor decision.
4. **Open `report.json`** — point at `executive_summary`, `top_priority`,
   and the per-finding `verified_methods` (HIGH/CRITICAL enforcement).
5. **Render `attack_chain.mmd`** — paste it into a GitHub gist or
   `https://mermaid.live` to show the graph: hexagons = defenses,
   rounded boxes = findings, arrows = mitigation / verification.
6. **Open `report_hackerone/index.md`** — one click into a per-finding
   `.md` shows operators the format they would file to a triage queue.

### Talking points

- **"Single command. No babysitting."** Autopilot synthesises the
  pre-engagement docs from one English sentence; the engagement runs
  to completion; reports auto-emit.
- **"OpenAI-only by default, $0.30 typical."** The `openai_only`
  profile uses `gpt-4o` for planner/analyst/defender and
  `gpt-4o-mini` for the high-volume scanner roles. Live cost tracker
  + `--budget-usd` hard cap prevents surprise bills.
- **"Pauses on its own when uncertain."** SIGINT or a sub-agent
  ambiguity drops a `pause.flag` + (sometimes) a `question.json`. The
  resume path picks up at the iteration boundary.
- **"Authorised target only."** The scope guard, RoE gate, scanner
  allowlist, and finding-protocol gate together make sure the loop
  cannot drift off-scope or fabricate HIGH/CRITICAL findings.
- **"Five report formats."** JSON / SARIF / Mermaid / HackerOne MD /
  Bugcrowd CSV — covers every downstream tool a security team uses.

---

## Troubleshooting

**`[env] loaded ...` not shown** — your `.env` isn't in the CWD.
Run the command from `network_pipeline/` or set `OPENAI_API_KEY`
in the shell directly.

**`NoProvidersAvailable: OPENAI_API_KEY missing`** — `.env` still
has the `REPLACE_ME_WITH_YOUR_OPENAI_KEY` placeholder. Edit and retry.

**`HRL high-level invocation failed`** — usually a rate-limit on
`gpt-4o`. Re-run; the Phase-1 retry-with-jitter will recover.

**Native-Windows banner about sqlmap** — harmless. Pure-Python
scanners (port, http, tls, cve) work fine on Windows. The scanner
allowlist for `scanme.nmap.org` doesn't include sqlmap anyway.

**Cost tracker shows `$0.00`** — model name unrecognised in
`llm/cost.py:_PRICING_PER_1K`. The pricing map is approximate;
update it for accurate billing. Findings + reports are unaffected.
