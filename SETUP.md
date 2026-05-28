# network_pipeline — Fresh-System Setup

End-to-end install on a clean machine. Two tracks:

- **Track A — WSL2 / Linux** (supported, recommended)
- **Track B — Native Windows** (works for smoke tests; the CLI prints a
  banner and refuses to start unless an override env var is set)

When you're done, every binary the agents call will be on `PATH`, the
Python deps will be installed, and the FastAPI server will start cleanly.

---

## 0. What you need before anything else

| Component         | Version                          |
|-------------------|----------------------------------|
| Python            | 3.11 or 3.12 (3.10 also works)   |
| Go                | 1.21+ (for ProjectDiscovery tools) |
| Ollama            | latest (local LLM runtime)       |
| Disk              | ~6 GB (Go tools + Ollama models) |

For WSL2: Ubuntu 22.04+ inside WSL2 on Windows 10/11.

---

## Track A — WSL2 / Linux

### A1. System packages

```bash
sudo apt update
sudo apt install -y nmap whois dnsutils curl ffuf feroxbuster nikto sqlmap wapiti zaproxy git build-essential
```

### A2. Go + ProjectDiscovery tools

```bash
sudo apt install -y golang-go
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/003random/getJS/v2@latest

nuclei -update-templates   # one-time
```

### A3. Python tools

```bash
pipx install paramspider
pipx install arjun
pipx install linkfinder
pipx install jwt-tool
```

If `pipx install paramspider` fails with a UTF-8 error on a system with a
non-UTF-8 locale, prefix with `PYTHONUTF8=1`.

### A4. Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &                       # keep running in another terminal
ollama pull llama3.1:8b
ollama pull llama3.2:3b
ollama pull qwen2.5-coder:7b
```

### A5. Pipeline source + Python deps

```bash
git clone <your-repo-url> Security_module
cd Security_module
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[network,api]"
```

### A6. Smoke test

```bash
python -m network_pipeline.cli serve --port 8000
# in another terminal:
curl -s http://127.0.0.1:8000/api/targets | head
```

---

## Track B — Native Windows (cmd.exe, conda)

This is the path used in the field debug session that produced this doc.
**WSL2 is still recommended**; native works for smoke tests but a few
tool wrappers expect POSIX paths.

### B1. Conda env

```cmd
conda create -n LLM python=3.11 -y
conda activate LLM
```

### B2. Pipeline source + Python deps

```cmd
cd C:\path\to\Security_module
pip install -e ".[network,api]"
```

If you hit `ImportError: cannot import name 'Sentinel' from 'typing_extensions'`,
fix the version pin (some pentest pip packages downgrade it):

```cmd
pip install -U "typing_extensions>=4.13"
```

### B3. Go + ProjectDiscovery tools

1. Install Go: https://go.dev/dl/ → `go1.22.x.windows-amd64.msi`. Default
   options. Reopen cmd.

2. Add `%USERPROFILE%\go\bin` to your **User PATH** via the GUI:
   ```cmd
   rundll32 sysdm.cpl,EditEnvironmentVariables
   ```
   Under **User variables for <you>** → `Path` → **Edit** → **New** →
   `C:\Users\<you>\go\bin`. OK out.

   ⚠️ **Never use `setx PATH ...`** on Windows — it has a silent
   1024-character truncation that will corrupt your PATH. Always edit
   PATH via the GUI.

3. Install the tools:
   ```cmd
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
   go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
   go install -v github.com/ffuf/ffuf/v2@latest
   go install -v github.com/hahwul/dalfox/v2@latest
   go install -v github.com/003random/getJS/v2@latest
   ```

4. Critical fix — Python's `httpx` library installs a CLI shim that
   shadows ProjectDiscovery `httpx`. Rename the shims:
   ```cmd
   ren "%CONDA_PREFIX%\Scripts\httpx.exe" py-httpx.exe
   ren "%USERPROFILE%\miniconda3\Scripts\httpx.exe" py-httpx.exe
   ```
   Verify:
   ```cmd
   where httpx                 :: must show ...\go\bin\httpx.exe FIRST
   httpx -version              :: must print ProjectDiscovery banner
   ```

5. One-time:
   ```cmd
   nuclei -update-templates
   ```

### B4. Standalone tools

| Tool   | How                                                    |
|--------|--------------------------------------------------------|
| nmap   | https://nmap.org/dist/nmap-7.95-setup.exe (auto-PATH)  |
| sqlmap | `pip install sqlmap`                                   |
| arjun  | `pip install arjun`                                    |
| wapiti | `pip install wapiti3`                                  |
| paramspider | `set PYTHONUTF8=1 && pip install git+https://github.com/0xKayala/ParamSpider.git` |

The Npcap warning from `nmap --version` is benign — the pipeline only
does TCP connect scans against web targets, which use OS sockets.

### B5. Ollama

1. Install: https://ollama.com/download/windows
2. Open cmd:
   ```cmd
   ollama pull llama3.1:8b
   ollama pull llama3.2:3b
   ollama pull qwen2.5-coder:7b
   ```
3. Ollama runs as a tray app — leave it running.

### B6. Native Windows override + start the server

```cmd
:: For this session only:
set NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS=1
python -m network_pipeline.cli serve --port 8000
```

To persist across all future cmd windows, add via the GUI editor as a
new **User variable**: name `NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS`,
value `1`.

---

## Sanity-check checklist (run in a fresh shell)

```
where subfinder dnsx httpx nuclei ffuf dalfox sqlmap nmap arjun paramspider
httpx -version       # ProjectDiscovery banner, NOT "Usage: httpx [OPTIONS] URL"
nmap --version
nuclei -version
sqlmap --version
ollama list          # shows pulled models
python -c "import network_pipeline; print(network_pipeline.__file__)"
```

Every line should succeed. If `httpx -version` prints
`Usage: httpx [OPTIONS] URL` you're hitting the Python `httpx` library —
go back to step B3.4.

---

## First engagement

```bash
# Linux / WSL2:
python -m network_pipeline.cli serve --port 8000
```

```cmd
:: Windows native:
set NETWORK_PIPELINE_ALLOW_NATIVE_WINDOWS=1
python -m network_pipeline.cli serve --port 8000
```

In another shell:

```bash
curl -s -X POST http://127.0.0.1:8000/api/engagements \
  -H 'content-type: application/json' \
  -d '{
    "target_id": "vulnweb-php",
    "seed": 42,
    "max_iterations": 20,
    "token_budget": 500000,
    "wall_budget": 3600,
    "engagement_name": "vulnweb-php smoke test"
  }'
```

Watch the server log. With every tool installed you should see:

- `capability_gate dropped tools` mentioning **only** the optional ones
  you skipped (`whois`/`getJS`/`linkfinder` if you skipped them).
- Real recon output landing in `engagements/<target>/<ts>/tool_io/`.
- Hosts/ports/services accumulating in `kg.json`.
- Findings appearing in `findings/findings.jsonl`.
- The synthesis engine appending POST_EXPLOIT objectives → `postexploit`
  agent firing.
- VACCINE phase producing a real `defense_brief.json` → verifier kicks
  in afterwards.

If findings stay at 0, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## Curated targets (`api/targets.json`)

The API only accepts targets that exist in the allowlist. Built-ins:

| `target_id`            | URL                                        | Auth |
|------------------------|--------------------------------------------|------|
| `vulnweb-php`          | http://testphp.vulnweb.com                 | no   |
| `vulnweb-aspnet`       | http://testaspnet.vulnweb.com              | no   |
| `vulnweb-asp`          | http://testasp.vulnweb.com                 | no   |
| `vulnweb-html5`        | http://testhtml5.vulnweb.com               | no   |
| `altoro-mutual`        | https://demo.testfire.net                  | yes  |
| `hack-yourself-first`  | https://hack-yourself-first.com            | no   |
| `scanme-nmap`          | http://scanme.nmap.org                     | no   |

⚠️ Acunetix retired `testaspnet.vulnweb.com` and `testhtml5.vulnweb.com`
around 2020. DNS may resolve but the apps return 404. Sanity-check with:

```bash
curl -sI http://testaspnet.vulnweb.com
curl -sI http://testhtml5.vulnweb.com
```

If they 404, drop them from your batch — `testphp` and `testasp` are
the reliable ones. `hack-yourself-first.com` may also need to point at
`hack-yourself-first.azurewebsites.net`; verify before running.

To add your own target, edit `network_pipeline/api/targets.json` and
restart the server.

---

## Tool-to-phase reference

| Phase | Agent | Required binaries |
|---|---|---|
| RECON | recon | subfinder, dnsx, whois, dig, getJS, linkfinder, paramspider, arjun, httpx |
| SCAN  | scanner | nmap, ffuf, feroxbuster, wapiti, nikto, zap-baseline, httpx |
| INITIAL_ACCESS | exploit | nuclei, dalfox, sqlmap, jwt_tool |
| POST_EXPLOIT, EXFILTRATION | postexploit | (depends on synthesized objective) |

`capability_gate` strips wrappers whose binary isn't on PATH — the
pipeline doesn't crash, it just runs with fewer tools. Missing binaries
correlate directly with empty findings.
