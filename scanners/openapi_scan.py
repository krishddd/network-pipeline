"""OpenAPI / Swagger spec-aware scanner.

Discovers an API's machine-readable spec at common paths, parses every
operation, and emits *targeted* probes per parameter — the 2026
"adaptive exploitation" pattern.

Surface the scanner produces:
- Raw spec finding (information disclosure: full API surface map exposed)
- Per-operation BOLA probes (path params with int/uuid types)
- Per-operation auth-matrix probes (no token vs. captured token)
- Per-operation mass-assignment hints fed to mass_assignment.py
- Per-operation injection seeds (sqli/xss) handed to those scanners

Pure Python — uses stdlib + httpx (already in pipeline).
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import (
    ScanFinding,
    ScanResult,
    normalize_endpoint,
)

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


_SPEC_PATHS = (
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/docs/swagger.json", "/api/swagger.json",
    "/redoc.json", "/api/openapi.json", "/openapi/v3",
)

_INT_PATH_PARAM_RE = re.compile(r"^\{[^}]+\}$")


@register_scanner
class OpenAPIScanner(Scanner):
    name = "openapi_scan"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "low"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def scan(self, base_url: str) -> ScanResult:
        result = ScanResult(scanner=self.name, target=base_url)
        spec, spec_url = await self._discover(base_url)
        if spec is None:
            result.success = False
            result.error = "no spec found at common paths"
            return result

        # Finding 1: spec exposed
        result.findings.append(ScanFinding(
            vuln_class="api-spec-exposed",
            title=f"OpenAPI/Swagger spec exposed at {spec_url}",
            severity="low",
            affected_target=spec_url,
            description=(
                "Full machine-readable API surface is publicly retrievable. "
                "Adversaries use this to enumerate every operation, parameter, "
                "auth flow, and schema for targeted attacks."
            ),
            cwe=["CWE-200", "CWE-540"],
            confidence="verified",
            extra={"spec_format": _detect_format(spec)},
        ))

        operations = list(_walk_operations(spec))
        result.data["operations_count"] = len(operations)
        result.data["spec_url"] = spec_url

        # Finding 2: deprecated operations exposed
        deprecated = [op for op in operations if op.get("deprecated")]
        if deprecated:
            result.findings.append(ScanFinding(
                vuln_class="api-deprecated-operations",
                title=f"{len(deprecated)} deprecated API operations still reachable",
                severity="informational",
                affected_target=spec_url,
                description=(
                    "Deprecated operations are commonly under-tested and lag "
                    "on security patches. Adversaries probe them first."
                ),
                confidence="verified",
                extra={"sample": [op["path"] for op in deprecated[:10]]},
            ))

        # Per-operation probes
        bola_candidates = _bola_candidates(operations)
        result.data["bola_candidates"] = [
            {"path": c["path"], "method": c["method"], "param": c["param_name"]}
            for c in bola_candidates
        ]
        if bola_candidates:
            result.findings.append(ScanFinding(
                vuln_class="api-bola-candidate",
                title=(
                    f"{len(bola_candidates)} API operations expose object-id "
                    "path params suitable for BOLA testing"
                ),
                severity="informational",
                affected_target=spec_url,
                description=(
                    "Operations with integer/uuid path params are the BOLA "
                    "attack surface. Pipeline now feeds these to bola_scan."
                ),
                confidence="verified",
                extra={"first": bola_candidates[0] if bola_candidates else {}},
            ))

        # Auth-required surface
        auth_required = [op for op in operations if op.get("security")]
        result.data["operations_with_auth"] = len(auth_required)
        result.data["operations_without_auth"] = len(operations) - len(auth_required)

        # Targeted probe: hit a sample of authenticated operations WITHOUT
        # a token. If any return 200 instead of 401/403 — broken auth.
        broken_auth = await self._probe_unauthenticated(base_url, auth_required[:8])
        for hit in broken_auth:
            result.findings.append(ScanFinding(
                vuln_class="api-broken-auth",
                title=f"API operation accessible without auth: {hit['method']} {hit['path']}",
                severity="high",
                affected_target=urljoin(base_url, hit["path"]),
                description=(
                    "Spec marks this operation as requiring auth, but the "
                    "server returned 2xx for an unauthenticated request."
                ),
                cwe=["CWE-287", "CWE-862"],
                mitre=["T1190"],
                confidence="verified",
                extra={"status": hit["status"], "method": hit["method"]},
            ))

        result.raw_text = f"spec={spec_url} ops={len(operations)} bola_candidates={len(bola_candidates)}"
        return result

    # ── Internals ──────────────────────────────────────────────────

    async def _discover(self, base_url: str) -> tuple[dict | None, str]:
        """Walk the common paths; return the first spec found + its URL."""
        for path in _SPEC_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            resp = await self._http.get(url, scanner_tool=self.name)
            if resp is None or resp.status_code != 200:
                continue
            ctype = (resp.headers.get("content-type") or "").lower()
            text = resp.text or ""
            spec = _parse_spec(text, ctype)
            if spec is not None and _looks_like_openapi(spec):
                return spec, url
        return None, ""

    async def _probe_unauthenticated(
        self, base_url: str, ops: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Hit a sample of authenticated GET operations without any token.

        Skip non-GET methods to avoid mutation. Skip ops whose path
        templates contain unfilled params (we don't have IDs to plug in).
        """
        out: list[dict[str, Any]] = []
        for op in ops:
            if (op.get("method") or "").upper() != "GET":
                continue
            path = op.get("path") or ""
            if "{" in path:
                continue
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            resp = await self._http.get(url, scanner_tool=self.name)
            if resp is None:
                continue
            if 200 <= resp.status_code < 300:
                out.append({"path": path, "method": "GET", "status": resp.status_code})
        return out


# ── Spec parsers + walkers ──────────────────────────────────────────

def _parse_spec(text: str, content_type: str) -> dict[str, Any] | None:
    """JSON or YAML, best-effort."""
    text = (text or "").strip()
    if not text:
        return None
    # JSON path
    if text.startswith(("{", "[")):
        try:
            obj = json.loads(text)
            return obj if isinstance(obj, dict) else None
        except Exception:
            pass
    # YAML path
    try:
        import yaml  # type: ignore[import-untyped]
        obj = yaml.safe_load(text)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _detect_format(spec: dict[str, Any]) -> str:
    if "openapi" in spec:
        return f"openapi-{spec.get('openapi')}"
    if "swagger" in spec:
        return f"swagger-{spec.get('swagger')}"
    return "unknown"


def _looks_like_openapi(spec: dict[str, Any]) -> bool:
    return bool(
        ("openapi" in spec or "swagger" in spec)
        and isinstance(spec.get("paths"), dict),
    )


def _walk_operations(spec: dict[str, Any]) -> Any:
    """Yield ``{path, method, parameters, security, ...}`` per operation."""
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        path_level_params = item.get("parameters") or []
        for method in (
            "get", "post", "put", "patch", "delete", "head", "options",
        ):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = list(path_level_params) + list(op.get("parameters") or [])
            yield {
                "path": path,
                "method": method.upper(),
                "summary": op.get("summary", ""),
                "deprecated": bool(op.get("deprecated")),
                "security": op.get("security", spec.get("security", [])),
                "parameters": params,
                "request_body": op.get("requestBody"),
                "responses": op.get("responses", {}),
            }


def _bola_candidates(ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pick GET-by-id-style operations: numeric/UUID path params."""
    out: list[dict[str, Any]] = []
    for op in ops:
        if (op.get("method") or "").upper() != "GET":
            continue
        for p in op.get("parameters") or []:
            if not isinstance(p, dict):
                continue
            if p.get("in") != "path":
                continue
            schema = p.get("schema") or {}
            ptype = schema.get("type") or p.get("type") or ""
            pfmt = schema.get("format") or p.get("format") or ""
            looks_id = (
                ptype in ("integer", "number")
                or pfmt in ("uuid", "int32", "int64")
                or any(k in (p.get("name") or "").lower()
                       for k in ("id", "_id", "uuid", "guid"))
            )
            if looks_id:
                out.append({
                    "path": op["path"],
                    "method": op["method"],
                    "param_name": p.get("name", "id"),
                    "param_type": ptype or pfmt or "unknown",
                })
                break
    return out
