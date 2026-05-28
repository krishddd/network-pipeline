"""One-shot orchestration: plan → run → verify → report.

The ``cli auto`` subcommand collapses every engagement step into a
single call. The operator supplies target + auth + Ollama URL and the
helper:

1. Slugifies the target into a deterministic folder name.
2. Creates ``<root>/<target-slug>/<YYYYMMDD-HHMMSSZ>/`` for this
   engagement (so re-running against the same target builds a history
   under one parent directory).
3. Writes ``engagement.meta.json`` at start (target, operator, host,
   model versions, flags, timestamps).
4. Invokes the standard ``plan`` flow programmatically.
5. Drives ``EngagementLoop.run()`` in-process.
6. Runs ``verify-evidence`` if ``--hmac-key`` is set.
7. Writes both SARIF and JSON reports.
8. Finalises ``engagement.meta.json`` with end timestamps + Merkle root
   + purple score + counts.

All artefacts land in the per-engagement folder so the operator can
``tar`` it and hand it off as a complete audit package.
"""

from __future__ import annotations

import getpass
import json
import os
import platform
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from network_pipeline.core.logging import get_logger

log = get_logger("core.auto")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utcnow_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


# ── Target slugification ─────────────────────────────────────────────


_SLUG_BAD = re.compile(r"[^a-z0-9._-]+")


def default_engagement_root() -> Path:
    """Canonical engagement-artefacts root: inside the package directory.

    All per-target / per-timestamp folders land under
    ``<network_pipeline>/engagements/`` so the audit trail co-locates
    with the code. Falls back to ``~/np-engagements`` only when the
    package directory can't be resolved (extremely defensive — the
    package always resolves under normal install).
    """
    try:
        import network_pipeline
        pkg_dir = Path(network_pipeline.__file__).resolve().parent
        return pkg_dir / "engagements"
    except Exception:  # pragma: no cover - defensive
        return Path.home() / "np-engagements"


def slugify_target(target: str) -> str:
    """Turn a URL/domain/CIDR into a filesystem-safe folder name.

    Examples:
        https://shop.example.com/login  → shop.example.com
        10.0.0.0/24                     → 10.0.0.0_24
        http://localhost:3000           → localhost_3000
    """
    t = (target or "").strip().rstrip("/").lower()
    if "://" in t:
        t = t.split("://", 1)[-1]
    t = t.split("/", 1)[0]  # strip path
    t = t.replace(":", "_").replace("/", "_")
    t = _SLUG_BAD.sub("_", t)
    return t.strip("_-.") or "unknown_target"


def make_engagement_dir(root: Path, target: str) -> Path:
    """Create ``<root>/<slug>/<timestamp>/`` and return the Path."""
    slug = slugify_target(target)
    stamp = _utcnow_compact()
    out = root / slug / stamp
    out.mkdir(parents=True, exist_ok=True)
    return out


# ── Engagement metadata ──────────────────────────────────────────────


def host_metadata() -> dict[str, str]:
    """Capture the host that ran the engagement (audit / repro)."""
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    return {
        "operator": user,
        "hostname": host,
        "platform": platform.platform(),
        "python_version": platform.python_version(),
    }


def ollama_metadata(base_url: str) -> dict[str, Any]:
    """Best-effort capture of remote Ollama version + installed models."""
    out: dict[str, Any] = {"base_url": base_url}
    try:
        import httpx
        ver = httpx.get(f"{base_url.rstrip('/')}/api/version", timeout=5)
        if ver.status_code == 200:
            out["version"] = ver.json().get("version", "")
        tags = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        if tags.status_code == 200:
            out["models"] = sorted(
                m.get("name", "") for m in tags.json().get("models", [])
            )
    except Exception as e:  # pragma: no cover - probe failures are non-fatal
        out["probe_error"] = repr(e)
    return out


def write_meta(workspace: Path, payload: dict[str, Any]) -> Path:
    """Atomically write/merge ``engagement.meta.json``."""
    path = workspace / "engagement.meta.json"
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = {}
    else:
        existing = {}
    # Shallow merge — caller passes only the keys it owns
    merged = {**existing, **payload}
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    return path


def write_initial_meta(
    *,
    workspace: Path,
    target: str,
    in_scope: list[str],
    out_of_scope: list[str],
    engagement_name: str,
    ollama_base_url: str,
    profile: str,
    flags: dict[str, Any],
) -> Path:
    """Write the engagement.meta.json the moment the run starts.

    Captures everything that matters for reproducibility +
    accountability: who ran it, on what host, against what target,
    with which models + flags + timestamps.
    """
    payload = {
        "schema": "network_pipeline.engagement.meta/v1",
        "engagement_name": engagement_name or f"engagement-{slugify_target(target)}",
        "target": target,
        "in_scope": list(in_scope),
        "out_of_scope": list(out_of_scope),
        "started_at": _utcnow_iso(),
        "host": host_metadata(),
        "ollama": ollama_metadata(ollama_base_url),
        "profile": profile,
        "flags": flags,
        "stages": {
            "plan": {"status": "pending"},
            "run":   {"status": "pending"},
            "verify": {"status": "pending"},
            "report": {"status": "pending"},
        },
    }
    return write_meta(workspace, payload)


def finalise_meta(
    *,
    workspace: Path,
    state_summary: dict[str, Any],
    verify_report: dict[str, Any] | None,
    report_paths: dict[str, str],
) -> Path:
    """Append final timestamps + Merkle root + purple score to the meta."""
    extras: dict[str, Any] = {
        "ended_at": _utcnow_iso(),
        "state_summary": state_summary,
        "report_paths": report_paths,
    }
    if verify_report is not None:
        extras["verify"] = verify_report

    # Pull the evidence root + purple score that the loop persists.
    root_path = workspace / "evidence_root.json"
    if root_path.exists():
        try:
            extras["evidence_root"] = json.loads(
                root_path.read_text(encoding="utf-8"),
            )
        except json.JSONDecodeError:
            pass
    purple_path = workspace / "purple_score.json"
    if purple_path.exists():
        try:
            extras["purple_score"] = json.loads(
                purple_path.read_text(encoding="utf-8"),
            )
        except json.JSONDecodeError:
            pass

    return write_meta(workspace, extras)


def update_stage(workspace: Path, stage: str, status: str, **detail: Any) -> None:
    """Update one ``stages[<stage>]`` field on engagement.meta.json."""
    path = workspace / "engagement.meta.json"
    if not path.exists():
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    stages = data.setdefault("stages", {})
    entry = stages.setdefault(stage, {})
    entry["status"] = status
    entry["ts"] = _utcnow_iso()
    if detail:
        entry.update(detail)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


__all__ = [
    "default_engagement_root",
    "finalise_meta",
    "host_metadata",
    "make_engagement_dir",
    "ollama_metadata",
    "slugify_target",
    "update_stage",
    "write_initial_meta",
    "write_meta",
]
