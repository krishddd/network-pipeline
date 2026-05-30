# network-pipeline

> Multi-agent offensive security pipeline for network and web targets.

An autonomous LangGraph-based pipeline that automates the full pentest loop —
**reconnaissance → scanning → exploitation → post-exploit → reporting** — by
routing tasks across specialised agents (Recon, Scanner, Exploit, Defender,
Verifier, Analyst, LLM-Redteam) connected through a causal knowledge graph
that chains evidence between steps.

## Features

- **100+ scanners** — port, DNS, TLS, JWT, GraphQL, OpenAPI, SQLi, XSS, BOLA,
  mass-assignment, prompt-injection, RAG-poisoning, multi-turn jailbreak, and
  more.
- **Industry-tool wrappers** — nmap, sqlmap, ffuf, feroxbuster, ZAP, nuclei,
  JWT-tool, Wapiti, Playwright.
- **HRL planner** — hierarchical reinforcement-learning trajectory with budget
  control, structured reasoning, and a Tree-of-Thoughts planner.
- **Reports** — SARIF, Bugcrowd-CSV, HackerOne, Mermaid attack-chain diagrams.
- **Multi-provider LLM routing** — OpenAI, Anthropic, Ollama, with cost and
  rate-limit guards per provider.
- **FastAPI control plane** — kick off engagements, watch progress, fetch
  reports.

## Tech stack

Python · asyncio · LangGraph · FastAPI · Playwright · ChromaDB ·
Anthropic / OpenAI / Ollama SDKs

## Quickstart

```bash
git clone https://github.com/krishddd/network-pipeline.git
cd network-pipeline
pip install -r requirements.txt
cp .env.example .env   # add provider keys
python cli.py plan --target https://example.com
python cli.py run    --engagement <id>
```

Or via the API:

```bash
python -m api.server
# POST /engagements with { "target": "https://example.com" }
```

## Project structure

```
agents/        Recon, Scanner, Exploit, Defender, Verifier, Analyst, LLM-Redteam
api/           FastAPI server + runner + static dashboard
browser/       Playwright session + auth flows
core/          Engagement, causal KG, HRL trajectory, budget, supervisor
llm/           Multi-provider chat clients, profiles, rate-limits
scanners/      All network + web + LLM-target scanners
skills/        Per-vulnerability SKILL.md packs + checks / wordlists
tools/         Tool wrappers + reporting
tests/         Unit + integration suites
```

## Status

Personal research project — built to explore how far autonomous offensive
security agents can be pushed safely. **Use only against systems you are
explicitly authorised to test.**

## License

MIT
