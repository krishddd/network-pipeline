# network_pipeline — Troubleshooting

Issues observed during real installs, with the fix that worked.

---

## Pipeline / runtime

### `AttributeError: 'RunnableRetry' object has no attribute 'bind_tools'`

LangGraph's `create_react_agent` requires the model passed in to be a
`BaseChatModel`, not a `RunnableRetry` wrapper. Somewhere in
`network_pipeline/agents/_common.py::build_agent` the model was wrapped
with `.with_retry(...)` before being passed to `create_react_agent`.

**Fix**: keep the bare `ChatOllama` (or other `BaseChatModel`) and apply
retry inside the tool/handler layer, not on the model itself. The model
must expose `.bind_tools` for tool-calling agents.

### Engagement `status: complete` after only 3 iterations

Not a bug. The seeded OPPLAN in `cli.py::_seed_opplan` only contains 3
objectives (RECON, SCAN, INITIAL_ACCESS). The loop drains those, then
transitions to VACCINE.

Follow-up objectives (POST_EXPLOIT, EXFILTRATION, more recon, etc.) are
synthesized **only when** the KG gains new nodes (hosts, services,
findings). With every offensive binary missing, the KG never grows
beyond the seed → no follow-up objectives → loop ends quickly.

**Fix**: install the binaries listed in [SETUP.md](SETUP.md). With real
recon output, the synthesis engine and the playbook engine will append
many more objectives.

### `vaccine: no defense_brief.json — skipping verifier`

The defender ran but had nothing to write about — `findings.jsonl` was
empty. The verifier is correctly skipped because there's nothing to
re-attack.

**Fix**: install the offensive binaries so the agents produce real
findings. Then the defender will group them into a real
`defense_brief.json` and the verifier will run.

### `[network_pipeline] Native Windows is unsupported`

The CLI refuses to start on native Windows by design. Set the override
once per session, or persist it via the GUI environment editor:

```cmd
set NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS=1
```

WSL2 is recommended for production use. Native is fine for smoke tests.

### `capability_gate dropped tools (missing binaries): X(needs X), ...`

Informational — the wrapper for that binary was removed from this
agent's tool list because `shutil.which("X")` returned None. Install the
missing binary to get the wrapper back.

---

## Python deps

### `ImportError: cannot import name 'Sentinel' from 'typing_extensions'`

A pip-installed pentest tool (commonly `arjun` or its deps) downgraded
`typing_extensions`. Modern `pydantic_core` needs `Sentinel` (added in
4.13).

**Fix**:
```cmd
pip install -U "typing_extensions>=4.13"
```

If it recurs, also:
```cmd
pip install -U typing_extensions pydantic pydantic_core
pip check
```

### `pip install paramspider` → `No matching distribution found`

ParamSpider isn't on PyPI. Install from GitHub:

```cmd
set PYTHONUTF8=1
pip install git+https://github.com/0xKayala/ParamSpider.git
```

If the upstream `devanshbatham/ParamSpider` repo fails with a
`UnicodeDecodeError` at `setup.py` line ~20 (Windows cp1252 codec
choking on README.md), the `PYTHONUTF8=1` env var fixes it. The
`0xKayala` fork is the maintained one and works on both Linux and
Windows.

---

## PATH / shadowing (Windows)

### `httpx -version` prints `Usage: httpx [OPTIONS] URL`

That's the **Python `httpx` library's CLI**, not ProjectDiscovery
`httpx`. The pipeline calls flags that only PD `httpx` understands
(`-l`, `-json`, `-tech-detect`, `-version`).

**Symptom**: `where httpx` shows multiple paths with the conda
`Scripts\httpx.exe` first.

**Fix** — rename the Python shims so they can't shadow the Go binary:

```cmd
ren "%CONDA_PREFIX%\Scripts\httpx.exe" py-httpx.exe
ren "%USERPROFILE%\miniconda3\Scripts\httpx.exe" py-httpx.exe
```

The Python `httpx` library still works (your imports are unaffected) —
only the CLI entry point is renamed.

### `setx PATH "..."` warns `truncated to 1024 characters`

`setx` has a hard 1024-char limit on user PATH and **silently truncates**
anything past it, corrupting your environment.

**Fix**:
- Recover the lost entries via the GUI editor:
  ```cmd
  rundll32 sysdm.cpl,EditEnvironmentVariables
  ```
- From now on, **only** edit PATH through the GUI. Never use
  `setx PATH ...`.
- If you need to add a directory programmatically and PATH is short,
  prefer System PATH or use PowerShell's
  `[Environment]::SetEnvironmentVariable('Path', ..., 'User')` which
  doesn't truncate.

### `where nmap` prints nothing after install

You probably didn't check the "Add Nmap to PATH" box during the Nmap
installer. nmap landed in `C:\Program Files (x86)\Nmap\` but isn't on
PATH.

**Fix**: GUI edit System PATH (or User PATH) → New →
`C:\Program Files (x86)\Nmap` → close ALL cmd windows → reopen →
`where nmap`.

### `'go' is not recognized`

Go isn't installed. Run the MSI from https://go.dev/dl/, then **open a
new cmd** (PATH only refreshes for new shells). Verify with
`go version`.

### `go install` succeeds but the binary isn't found

`go install` writes to `%USERPROFILE%\go\bin` by default. That directory
isn't on PATH unless you added it. Add it via the GUI editor — see
SETUP.md step B3.2.

---

## nmap

### `WARNING: Could not import all necessary Npcap functions`

Benign for this pipeline. We only do TCP connect scans (`-sT`, default
without privileges) against web targets — those use OS sockets, not raw
packets. Nmap will fall back to `connect()` mode automatically.

If you ever need SYN scans (`-sS`), OS detection (`-O`), or UDP scans,
install the latest Npcap from https://npcap.com.

### Nmap exits with `dnet: Failed to open device ethN`

You're trying a scan mode that needs raw sockets without elevated
privileges. Either:
- Run cmd "as Administrator", or
- Stick to connect-mode scans (the pipeline default), or
- (WSL2) `sudo setcap cap_net_raw,cap_net_admin=eip $(which nmap)`.

---

## Targets

### Engagement runs but 0 findings on `testaspnet.vulnweb.com` / `testhtml5.vulnweb.com`

Acunetix retired both around 2020. DNS still resolves but the apps
respond with empty/404 pages. Drop them from your batch — only
`testphp.vulnweb.com` and `testasp.vulnweb.com` are still alive.

```bash
curl -sI http://testaspnet.vulnweb.com    # check before running
curl -sI http://testhtml5.vulnweb.com
```

### `hack-yourself-first.com` returns nothing

Pluralsight's HYF lab actually lives at
`hack-yourself-first.azurewebsites.net`. Verify with `curl -sI` and edit
the entry in `api/targets.json` if needed.

### `demo.testfire.net` (AltoroJ) is intermittent

IBM's been inconsistent about keeping the demo up. Always verify with
`curl -sI` before relying on it. If using auth-protected paths, capture
the `JSESSIONID` cookie via DevTools after logging in as
`jsmith / Demo1234` and pass it as `auth_cookie` in the engagement
request body.

### `scanme.nmap.org`: my engagement called nuclei/sqlmap

Don't. The site's banner explicitly authorizes nmap-style probing only.
Set `playbook: mitre_discovery` and `c2_profile: stealth` (the curated
target entry already does this). Open
`skills/playbooks/mitre_discovery.yaml` to confirm no offensive steps
are queued.

---

## Performance / budgets

### Engagement times out before nmap finishes

`wall_budget` defaults aren't generous for full scans. A complete `nmap
-A` against a single host with `nmap` rate-capped at 0.2 rps can take
20+ minutes. Either:

- Bump `wall_budget` (e.g. 1800–3600 for full scans).
- Restrict ports in the playbook (e.g. top-100 instead of full).
- Raise the `nmap` rate cap if the target permits.

---

## Where to look when something fails

```
engagements/<target>/<ts>/
├── pipeline.log              # human-readable engagement log
├── agent_traces.log          # JSONL — every LLM exchange + tool call
├── tool_io/<agent>/          # raw stdout/stderr of every subprocess
├── findings/findings.jsonl   # what landed
├── plan/opplan.json          # what was planned + status
└── kg.json                   # what was discovered
```

Order of triage:

1. **`pipeline.log`** — phase transitions, capability_gate drops,
   synthesis events, errors.
2. **`agent_traces.log`** — what the LLM actually said and which tools
   it tried to call.
3. **`tool_io/<agent>/`** — raw output from each binary (useful when an
   agent claims success but the underlying tool errored).
4. **`plan/opplan.json`** — see which objectives ran, which are
   blocked, which were synthesized.
5. **`kg.json`** — see what the KG actually accumulated.

If `findings.jsonl` is empty after a run, the answer is almost always in
`pipeline.log` (capability_gate drops) or `tool_io/` (tool errored
silently).
