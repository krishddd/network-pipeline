"""Convert ProjectDiscovery nuclei-templates → pipeline cve_check YAMLs.

Why: 2026 median time-to-exploit is 5 days. The pipeline ships ~9 CVE
YAMLs; nuclei-templates ships 12,000+. We can't embed a Go binary, but
we CAN convert the subset of HTTP templates that match our YAML grammar
(roughly 70% of HTTP templates — the rest use Go-only DSL helpers).

Usage:
    python -m network_pipeline.scripts.import_nuclei_templates \\
        --src ~/nuclei-templates --out network_pipeline/skills/checks/cves \\
        [--severity-min medium] [--limit 5500] [--refresh]

If ``--src`` is omitted, the script shallow-clones
``github.com/projectdiscovery/nuclei-templates`` into ``~/.cache/network_pipeline/nuclei-templates``
(refreshed daily). Requires ``git`` on PATH.

Pure stdlib + pyyaml. No Go, no nuclei binary required.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    print("error: pyyaml required (pip install pyyaml)", file=sys.stderr)
    raise SystemExit(2)


_REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
_DEFAULT_CACHE = Path.home() / ".cache" / "network_pipeline" / "nuclei-templates"
_REFRESH_AFTER_S = 24 * 3600

_SEV_ORDER = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# Convertible criteria — strict to keep false-positive imports low.
def _is_convertible(template: dict[str, Any]) -> tuple[bool, str]:
    """Return (ok, reason). Reject templates that use Go DSL we can't run."""
    if not isinstance(template, dict):
        return False, "not a dict"
    info = template.get("info") or {}
    if not info.get("severity"):
        return False, "no severity"

    # Need at least one HTTP request
    requests = template.get("http") or template.get("requests") or []
    if not requests or not isinstance(requests, list):
        return False, "no http requests"
    req = requests[0]
    if not isinstance(req, dict):
        return False, "request not dict"

    # Reject if it uses raw HTTP requests (those use templated CRLF strings
    # we can't safely route through our HTTPClient).
    if req.get("raw"):
        return False, "raw http"

    # Need exactly one path / method we can map
    paths = req.get("path") or []
    if isinstance(paths, str):
        paths = [paths]
    if not paths:
        return False, "no path"

    matchers = req.get("matchers") or []
    if not matchers:
        return False, "no matchers"
    # Reject if any matcher uses Go DSL functions we don't implement
    for m in matchers:
        if not isinstance(m, dict):
            continue
        if m.get("type") == "dsl":
            return False, "dsl matcher"

    return True, ""


def _convert(template: dict[str, Any]) -> dict[str, Any] | None:
    """Map a nuclei template into our cve_check YAML schema."""
    info = template.get("info") or {}
    requests = template.get("http") or template.get("requests") or []
    req = requests[0]

    paths = req.get("path") or []
    if isinstance(paths, str):
        paths = [paths]
    path = str(paths[0])
    # Strip nuclei's {{BaseURL}} placeholder — our engine prepends it.
    path = path.replace("{{BaseURL}}", "").replace("{{Hostname}}", "")
    if not path.startswith("/"):
        path = "/" + path

    method = (req.get("method") or "GET").upper()

    matchers = req.get("matchers") or []
    body_contains = ""
    status_match: int | None = None
    for m in matchers:
        if not isinstance(m, dict):
            continue
        mtype = m.get("type")
        if mtype == "word":
            words = m.get("words") or []
            if words:
                body_contains = str(words[0])
                break
        if mtype == "regex":
            regex = m.get("regex") or []
            if regex:
                # Take a literal-looking substring out of the regex if we can
                pat = str(regex[0])
                body_contains = re.sub(r"[.\\\*\[\]\(\)\^\$\?\+\|\{\}]", "", pat)[:64]
                break
    for m in matchers:
        if isinstance(m, dict) and m.get("type") == "status":
            statuses = m.get("status") or []
            if statuses:
                try:
                    status_match = int(statuses[0])
                except (TypeError, ValueError):
                    pass
                break

    if not body_contains and status_match is None:
        return None

    out: dict[str, Any] = {
        "id": template.get("id") or info.get("name") or "imported-nuclei",
        "title": str(info.get("name") or template.get("id") or "Imported nuclei template"),
        "severity": str(info.get("severity") or "informational").lower(),
        "http_request": {
            "method": method,
            "path": path,
        },
        "expected_response": {},
    }
    if status_match is not None:
        out["expected_response"]["status"] = status_match
    if body_contains:
        out["expected_response"]["body_contains"] = body_contains

    if info.get("classification"):
        c = info["classification"]
        if isinstance(c, dict):
            cve = c.get("cve-id") or c.get("cwe-id")
            if cve:
                out["cwe"] = [cve] if isinstance(cve, str) else list(cve)
            if c.get("cvss-score"):
                try:
                    out["cvss"] = float(c["cvss-score"])
                except (TypeError, ValueError):
                    pass
    if info.get("reference"):
        refs = info["reference"]
        out["references"] = refs if isinstance(refs, list) else [str(refs)]
    if info.get("description"):
        out["description"] = str(info["description"])[:512]
    if info.get("remediation"):
        out["remediation"] = str(info["remediation"])[:512]

    return out


def _ensure_clone(cache: Path, *, refresh: bool) -> Path:
    """Clone or refresh the nuclei-templates repo into ``cache``."""
    if cache.exists() and not refresh:
        # Skip if cloned within the refresh window
        try:
            mtime = (cache / ".git" / "HEAD").stat().st_mtime
            if (time.time() - mtime) < _REFRESH_AFTER_S:
                return cache
        except OSError:
            pass

    if not shutil.which("git"):
        raise SystemExit("error: git is required on PATH for auto-clone")

    cache.parent.mkdir(parents=True, exist_ok=True)

    if cache.exists():
        print(f"refreshing {cache} …")
        subprocess.run(["git", "-C", str(cache), "pull", "--depth=1"], check=True)
    else:
        print(f"shallow-cloning {_REPO_URL} → {cache} …")
        subprocess.run(
            ["git", "clone", "--depth=1", _REPO_URL, str(cache)],
            check=True,
        )
    return cache


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", help="path to a nuclei-templates checkout")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--severity-min", default="low",
                    choices=list(_SEV_ORDER.keys()))
    ap.add_argument("--limit", type=int, default=5500)
    ap.add_argument("--refresh", action="store_true",
                    help="force a fresh git pull on the cache clone")
    args = ap.parse_args()

    src = Path(args.src) if args.src else _ensure_clone(
        _DEFAULT_CACHE, refresh=args.refresh,
    )
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    sev_floor = _SEV_ORDER[args.severity_min]
    converted = 0
    skipped: dict[str, int] = {}
    for path in src.rglob("*.yaml"):
        if converted >= args.limit:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            tpl = yaml.safe_load(text)
        except Exception as e:
            skipped["parse-error"] = skipped.get("parse-error", 0) + 1
            continue
        ok, reason = _is_convertible(tpl)
        if not ok:
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        sev = (tpl.get("info") or {}).get("severity", "informational").lower()
        if _SEV_ORDER.get(sev, 0) < sev_floor:
            skipped["below-severity-floor"] = (
                skipped.get("below-severity-floor", 0) + 1
            )
            continue
        out = _convert(tpl)
        if out is None:
            skipped["unconvertible-matcher"] = (
                skipped.get("unconvertible-matcher", 0) + 1
            )
            continue
        # Filename: use the template id, sanitised.
        name = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(out.get("id", "imported")))
        out_path = out_dir / f"{name}.yaml"
        try:
            out_path.write_text(
                yaml.safe_dump(out, sort_keys=False),
                encoding="utf-8",
            )
            converted += 1
        except OSError as e:
            print(f"write failed {out_path}: {e}", file=sys.stderr)

    print(f"converted {converted} templates → {out_dir}")
    print(f"skipped:")
    for reason, n in sorted(skipped.items(), key=lambda kv: -kv[1])[:20]:
        print(f"  {reason}: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
