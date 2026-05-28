"""FastAPI app exposing the curated targets + engagement lifecycle.

Run via the ``python -m network_pipeline.cli serve`` subcommand which
starts uvicorn on the requested port.

Endpoints:

* ``GET  /``                              — static HTML UI
* ``GET  /api/targets``                   — list curated allowlist
* ``POST /api/engagements``               — start an engagement (target id from allowlist)
* ``GET  /api/engagements``               — list every engagement this server has seen
* ``GET  /api/engagements/{id}``          — full state including stages
* ``GET  /api/engagements/{id}/findings`` — findings JSONL (parsed)
* ``GET  /api/engagements/{id}/report``   — download SARIF or JSON report

Security boundary: the request body for ``POST /api/engagements`` only
accepts a ``target_id`` that exists in ``targets.json``. We never
construct an engagement against an arbitrary URL — that would turn
this service into an unauthenticated pentest weapon.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from network_pipeline.api.runner import (
    EngagementJob, MAX_PARALLEL_ENGAGEMENTS, bind_main_loop,
    get_engagement, list_engagements, make_engagement_id,
    submit_job, workspace_for,
)
from network_pipeline.core.auto import default_engagement_root
from network_pipeline.core.logging import get_logger


# ── Pydantic schemas (MUST be module-level) ──────────────────────────
#
# FastAPI's openapi-schema generation walks each route handler's
# signature and resolves forward refs from the handler's module
# globals. With ``from __future__ import annotations`` (Phase-1 std),
# every annotation is a string until pydantic evaluates it. Defining
# ``StartEngagement`` inside ``_build_app`` would put the class only in
# the function's local scope — pydantic can't see it at /openapi.json
# request time and raises ``PydanticUserError: not fully defined``.
# Module-level definition fixes that.


class StartEngagement(BaseModel):
    """Body for ``POST /api/engagements``.

    The ``target_id`` field MUST match an entry in the curated
    allowlist (``api/targets.json``). Free-form URLs are rejected.
    """

    target_id: str = Field(description="ID from /api/targets")
    auth_cookie: str = ""
    max_iterations: int | None = None
    seed: int | None = None
    token_budget: int | None = None
    wall_budget: int | None = None
    c2_profile_override: str = ""
    engagement_name: str = ""

log = get_logger("api.server")


# Config — defaults chosen so a fresh checkout serves something useful.
# Reports live INSIDE the network_pipeline package directory by default
# so the engagement audit trail co-locates with the code (see
# ``core.auto.default_engagement_root``).
DEFAULT_REPORT_ROOT = default_engagement_root()
DEFAULT_OLLAMA_URL = "http://localhost:11434"


# ── Targets allowlist ────────────────────────────────────────────────


def _targets_json_path() -> Path:
    return Path(__file__).resolve().parent / "targets.json"


def load_targets() -> list[dict[str, Any]]:
    """Read the curated allowlist. Cached at import time."""
    p = _targets_json_path()
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("targets", [])
    except (json.JSONDecodeError, OSError) as e:
        log.warning("failed to read targets.json: %r", e)
        return []


def _target_by_id(target_id: str) -> dict[str, Any] | None:
    for t in load_targets():
        if t.get("id") == target_id:
            return t
    return None


# ── Pydantic request/response shapes ─────────────────────────────────


def _build_app(
    *,
    report_root: Path,
    ollama_url: str,
    profile: str,
    rag_index: str = "",
):
    from fastapi import (  # type: ignore[import-not-found]
        FastAPI, HTTPException, Query,
    )
    from fastapi.responses import (  # type: ignore[import-not-found]
        FileResponse, HTMLResponse,
    )
    from fastapi.staticfiles import StaticFiles  # type: ignore[import-not-found]

    app = FastAPI(
        title="network_pipeline",
        version="phase-5",
        description=(
            "HTTP service for click-to-run engagements against a "
            "curated allowlist of public, authorised security-testing "
            "targets. Arbitrary targets are NOT accepted."
        ),
    )

    # Capture the main asyncio loop on startup so submit_job can spawn
    # engagement coroutines from FastAPI's threadpool route handlers
    # (Bug-fix: ``asyncio.get_event_loop()`` raises in worker threads).
    @app.on_event("startup")
    async def _on_startup() -> None:
        bind_main_loop(asyncio.get_running_loop())

    # ── Static UI ────────────────────────────────────────────────
    static_dir = Path(__file__).resolve().parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", response_class=HTMLResponse)
    def index():
        # No return-type annotation here on purpose: with
        # ``from __future__ import annotations`` and HTMLResponse
        # imported INSIDE this function, FastAPI's forward-ref
        # resolution fails to find the symbol in module globals.
        # ``response_class=HTMLResponse`` tells FastAPI what to do.
        idx = static_dir / "index.html"
        if idx.exists():
            return HTMLResponse(idx.read_text(encoding="utf-8"))
        return HTMLResponse(
            "<h1>network_pipeline API</h1>"
            "<p>The static UI is not present. Use <code>/api/targets</code>"
            " and <code>POST /api/engagements</code> directly.</p>",
        )

    # ── /api/targets ─────────────────────────────────────────────
    @app.get("/api/targets")
    def get_targets():
        return {"targets": load_targets(), "count": len(load_targets())}

    # ── /api/engagements ─────────────────────────────────────────
    @app.get("/api/engagements")
    def get_engagements():
        return {
            "engagements": list_engagements(),
            "max_parallel": MAX_PARALLEL_ENGAGEMENTS,
        }

    @app.post("/api/engagements")
    def post_engagement(body: StartEngagement):
        entry = _target_by_id(body.target_id)
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"target_id {body.target_id!r} not in allowlist. "
                    "GET /api/targets to see valid ids."
                ),
            )
        if entry.get("auth_required") and not body.auth_cookie:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"target {body.target_id!r} requires auth_cookie. "
                    f"hint: {entry.get('auth_hint', '(none)')}"
                ),
            )
        defaults = entry.get("default_flags") or {}
        engagement_id = make_engagement_id(entry["target"])
        job = EngagementJob(
            engagement_id=engagement_id,
            target=entry["target"],
            in_scope=list(entry.get("in_scope") or []),
            out_of_scope=[],
            engagement_name=body.engagement_name or entry["name"],
            ollama_base_url=ollama_url,
            profile=profile,
            max_iterations=int(
                body.max_iterations or defaults.get("max_iterations") or 20
            ),
            iteration_timeout=600,
            playbook=str(defaults.get("playbook") or "owasp_top10"),
            c2_profile=str(
                body.c2_profile_override or defaults.get("c2_profile") or "balanced"
            ),
            auth_cookie=body.auth_cookie,
            rate_caps={k: float(v) for k, v in (defaults.get("rate_caps") or {}).items()},
            seed=body.seed,
            # Coerce 0 → None so Swagger's default body never caps the
            # engagement to zero tokens / zero seconds. Real caps must
            # be > 0; anything else means "unlimited".
            token_budget=(
                int(body.token_budget)
                if body.token_budget and int(body.token_budget) > 0 else None
            ),
            wall_budget=(
                int(body.wall_budget)
                if body.wall_budget and int(body.wall_budget) > 0 else None
            ),
            hmac_engagement_id=engagement_id,  # auto-derive
            report_root=report_root,
            rag_index=rag_index,  # server-wide RAG index (Phase-4)
            allowed_scanners=list(entry.get("allowed_scanners") or []),
        )
        result = submit_job(job)
        if result.get("status") == "rejected":
            raise HTTPException(status_code=429, detail=result.get("reason", ""))
        return result

    @app.get("/api/engagements/{engagement_id}")
    def get_engagement_detail(engagement_id: str):
        entry = get_engagement(engagement_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="unknown engagement_id")
        # Hydrate from the on-disk meta if stages have advanced.
        meta_path = (
            workspace_for(engagement_id, report_root) / "engagement.meta.json"
        )
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                entry = {**entry, "meta": meta}
            except json.JSONDecodeError:
                pass
        return entry

    @app.get("/api/engagements/{engagement_id}/findings")
    def get_engagement_findings(engagement_id: str):
        entry = get_engagement(engagement_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="unknown engagement_id")
        ws = workspace_for(engagement_id, report_root)
        path = ws / "findings.jsonl"
        if not path.exists():
            return {"findings": [], "count": 0}
        items = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            # Strip HMAC suffix when present
            if "\t__sig__=" in line:
                line = line.split("\t__sig__=", 1)[0]
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"findings": items, "count": len(items)}

    @app.get("/api/engagements/{engagement_id}/report")
    def get_engagement_report(
        engagement_id: str,
        fmt: str = Query(default="sarif", regex="^(sarif|json)$"),
    ):
        entry = get_engagement(engagement_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="unknown engagement_id")
        ws = workspace_for(engagement_id, report_root)
        path = ws / f"report.{fmt}"
        if not path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"report.{fmt} not yet produced",
            )
        return FileResponse(
            str(path),
            media_type="application/json",
            filename=f"{engagement_id}.{fmt}",
        )

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def create_app(
    *,
    report_root: Path | None = None,
    ollama_url: str | None = None,
    profile: str = "eco",
    rag_index: str = "",
):
    return _build_app(
        report_root=Path(report_root) if report_root else DEFAULT_REPORT_ROOT,
        ollama_url=ollama_url or DEFAULT_OLLAMA_URL,
        profile=profile,
        rag_index=rag_index,
    )


__all__ = ["create_app", "load_targets"]
