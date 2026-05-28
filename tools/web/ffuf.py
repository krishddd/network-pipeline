"""ffuf wrapper — directory + content discovery via brute-force.

Used by the scanner agent to enumerate hidden paths beneath an HTTP
target. ffuf produces JSON output via ``-of json`` which we parse with
a light Pydantic model.

Defaults are intentionally gentle (50 threads, 10 s timeout per req)
so OPSEC gating + per-target rate limits stay meaningful — the OPSEC
gate strips ffuf at QUIET / SILENT regardless.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from network_pipeline.core.logging import get_logger
from network_pipeline.tools.web._common import truncate

if TYPE_CHECKING:
    from network_pipeline.tools.shell import ShellRunner

log = get_logger("tools.web.ffuf")


# Sensible default wordlist locations — fall back to a tiny embedded
# list if none are present so smoke tests still succeed.
_WORDLIST_CANDIDATES = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/dirb/common.txt",
)

_FALLBACK_WORDS = (
    "admin", "login", "api", "backup", "config", "test", "dev",
    ".git/HEAD", ".env", "robots.txt", "sitemap.xml", "swagger",
    "phpinfo.php", "wp-admin", "actuator", "actuator/health",
)


def _resolve_wordlist(workspace: Path, override: str | None) -> Path:
    if override:
        p = Path(override)
        if p.exists():
            return p
    for candidate in _WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return Path(candidate)
    # Embedded fallback — write once into the workspace so a deterministic
    # smoke run works without seclists installed.
    fallback = workspace / "tool_io" / "ffuf_default_wordlist.txt"
    fallback.parent.mkdir(parents=True, exist_ok=True)
    if not fallback.exists():
        fallback.write_text("\n".join(_FALLBACK_WORDS) + "\n", encoding="utf-8")
    return fallback


def run_ffuf(
    runner: "ShellRunner",
    target: str,
    *,
    wordlist: str | None = None,
    extensions: str = "",
    threads: int = 40,
    agent: str = "scanner",
    objective_id: str = "",
) -> str:
    """Brute-force directories/files under ``target`` (must end with FUZZ).

    If ``target`` doesn't already include the ``FUZZ`` token, append
    ``/FUZZ`` to it — that's the canonical ffuf placeholder.
    """
    fuzz_target = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
    wl = _resolve_wordlist(runner._workspace, wordlist)
    out_json = (
        runner._workspace / "tool_io" / agent
        / f"ffuf_{objective_id or 'noobj'}.json"
    )
    out_json.parent.mkdir(parents=True, exist_ok=True)
    argv = [
        "-u", fuzz_target,
        "-w", str(wl),
        "-of", "json",
        "-o", str(out_json),
        "-t", str(threads),
        "-mc", "200,204,301,302,307,401,403",
        "-ac",  # auto-calibrate against false positives
        "-s",   # silent stdout, JSON file is the source of truth
    ]
    if extensions:
        argv.extend(["-e", extensions])

    res = runner.run(
        "ffuf", argv,
        targets=[target],
        timeout_s=600,
        agent=agent,
        objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[ffuf skipped] {res.error}"

    if not out_json.exists():
        return f"ffuf against {target}: no JSON output produced ({out_json})"

    try:
        data = json.loads(out_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return f"[ffuf parse failed] {e}"
    results = data.get("results") or []
    by_status: dict[str, int] = {}
    samples: list[str] = []
    for hit in results:
        status = str(hit.get("status", "?"))
        by_status[status] = by_status.get(status, 0) + 1
        if len(samples) < 30:
            samples.append(
                f"  [{status}] {hit.get('url', '?')} "
                f"(len={hit.get('length', '?')})"
            )
    summary = (
        f"ffuf against {fuzz_target}: {len(results)} hits, "
        f"status histogram = {by_status}\n"
        + "\n".join(samples)
        + f"\nfull JSON: {out_json}"
    )
    return truncate(summary)
