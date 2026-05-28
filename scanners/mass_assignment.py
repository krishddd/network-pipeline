"""Mass-assignment / privilege-escalation scanner.

For every captured POST/PUT/PATCH endpoint with a JSON body, mutates a
copy by appending privileged fields and compares the response to the
baseline. If the server accepts the privileged field — either by status
flip (4xx → 2xx) or by echoing the field back in the response — flag
as mass-assignment vulnerability.

Privileged-field universe (hand-picked from real CVE write-ups):

    role, isAdmin, is_admin, admin, verified, email_verified,
    is_active, is_superuser, permissions, roles, scopes,
    subscription_tier, plan, premium, balance, credit, owner_id,
    tenant_id, organization_id, __proto__, constructor.prototype

The scanner is *non-destructive*: it sends mutations only to endpoints
the operator already exercised (their bodies become the baselines), so
no random POSTs are issued.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import TYPE_CHECKING, Any

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanFinding, ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


# Field name → marker value used for the probe.
# Marker values are intentionally distinct so we can detect echo in responses.
_PRIVILEGED_FIELDS: dict[str, Any] = {
    "role": "admin",
    "roles": ["admin", "superuser"],
    "isAdmin": True,
    "is_admin": True,
    "admin": True,
    "is_superuser": True,
    "verified": True,
    "is_verified": True,
    "email_verified": True,
    "is_active": True,
    "active": True,
    "permissions": ["*"],
    "scopes": ["read", "write", "admin", "delete"],
    "subscription_tier": "enterprise",
    "subscriptionTier": "enterprise",
    "plan": "premium",
    "premium": True,
    "balance": 999999,
    "credit": 999999,
    "owner_id": 1,
    "ownerId": 1,
    "tenant_id": 1,
    "organization_id": 1,
    # Prototype-pollution variants (Node/Express)
    "__proto__": {"isAdmin": True},
    "constructor": {"prototype": {"isAdmin": True}},
}


@register_scanner
class MassAssignmentScanner(Scanner):
    name = "mass_assignment"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def scan(
        self,
        captured: list[dict[str, Any]],
    ) -> ScanResult:
        """Run mass-assignment probes against captured request specs.

        Each captured entry must be a dict shaped like::

            {
                "method": "POST" | "PUT" | "PATCH",
                "url": "<full-url>",
                "headers": {...},      # optional
                "body": {...} | "<raw>" # JSON dict or raw string
            }
        """
        result = ScanResult(
            scanner=self.name,
            target=captured[0]["url"] if captured else "",
        )
        if not captured:
            result.success = False
            result.error = "no captured requests supplied"
            return result

        for req in captured:
            try:
                hits = await self._probe_request(req)
                result.findings.extend(hits)
            except Exception as e:  # noqa: BLE001
                result.data.setdefault("errors", []).append(
                    f"{req.get('url')}: {e!r}",
                )

        result.data["requests_probed"] = len(captured)
        result.data["mass_assign_findings"] = sum(
            1 for f in result.findings
            if f.vuln_class.startswith("mass-assignment")
        )
        return result

    async def _probe_request(
        self, req: dict[str, Any],
    ) -> list[ScanFinding]:
        method = (req.get("method") or "POST").upper()
        url = req.get("url") or ""
        headers = dict(req.get("headers") or {})
        body = req.get("body")

        if method not in {"POST", "PUT", "PATCH"}:
            return []
        if not url:
            return []
        # Only JSON bodies — form-encoded bodies have a separate scanner.
        body_obj = _coerce_json(body)
        if body_obj is None or not isinstance(body_obj, dict):
            return []

        # Baseline
        baseline = await self._send(method, url, headers, body_obj)
        if baseline is None:
            return []
        base_status = baseline.status_code
        base_text = baseline.text or ""
        base_keys = _shallow_keys(_safe_json(base_text))

        findings: list[ScanFinding] = []
        for field, value in _PRIVILEGED_FIELDS.items():
            mutated = deepcopy(body_obj)
            # Skip if the operator already set this field — we'd be
            # confounding the test.
            if field in mutated:
                continue
            mutated[field] = value
            r = await self._send(method, url, headers, mutated)
            if r is None:
                continue
            # Signal A: status flipped from 4xx → 2xx
            status_flip = (base_status >= 400) and (200 <= r.status_code < 300)
            # Signal B: response echoes the privileged field back as accepted
            resp_obj = _safe_json(r.text or "")
            field_echoed = (
                resp_obj is not None
                and _contains_field_value(resp_obj, field, value)
            )
            # Signal C: response keys grew vs. baseline (server accepted +
            # serialised the new field)
            resp_keys = _shallow_keys(resp_obj)
            new_keys = resp_keys - base_keys
            keys_grew = bool(new_keys & {field, field.lower(), field.replace("_", "")})

            if status_flip or field_echoed or keys_grew:
                sev = "high" if status_flip or field_echoed else "medium"
                findings.append(ScanFinding(
                    vuln_class=(
                        "mass-assignment-priv-esc"
                        if field in {
                            "role", "roles", "isAdmin", "is_admin", "admin",
                            "is_superuser", "permissions", "scopes",
                        }
                        else "mass-assignment"
                    ),
                    title=(
                        f"Mass-assignment accepted privileged field "
                        f"`{field}` on {method} {url}"
                    ),
                    severity=sev,
                    affected_target=url,
                    affected_param=field,
                    description=(
                        f"Baseline {method} returned {base_status}; injecting "
                        f"`{field}` produced {r.status_code}. "
                        f"status_flip={status_flip} echoed={field_echoed} "
                        f"keys_grew={keys_grew}. The endpoint deserialises "
                        "client-controlled fields into a privileged model "
                        "without an allowlist."
                    ),
                    cwe=["CWE-915", "CWE-269"],
                    mitre=["T1078", "T1068"],
                    confidence="probable",
                    extra={
                        "field": field,
                        "value": value if not isinstance(value, dict) else "<obj>",
                        "baseline_status": base_status,
                        "probe_status": r.status_code,
                    },
                ))
        return findings

    async def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, Any],
        body: dict[str, Any],
    ):
        # HTTPClient method dispatch — uses the shared async client
        h = dict(headers or {})
        h.setdefault("Content-Type", "application/json")
        try:
            payload = json.dumps(body, separators=(",", ":"))
        except (TypeError, ValueError):
            return None
        if method == "POST":
            return await self._http.post(
                url, headers=h, content=payload, scanner_tool=self.name,
            )
        if hasattr(self._http, "request"):
            return await self._http.request(
                method, url, headers=h, content=payload, scanner_tool=self.name,
            )
        # Fallback: GET (won't send body, but prevents crash)
        return await self._http.get(url, headers=h, scanner_tool=self.name)


# ── Helpers ──────────────────────────────────────────────────────────

def _coerce_json(body: Any) -> dict[str, Any] | None:
    if body is None:
        return None
    if isinstance(body, dict):
        return body
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", errors="ignore")
    if isinstance(body, str):
        body = body.strip()
        if not body:
            return None
        try:
            obj = json.loads(body)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None
    return None


def _safe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _shallow_keys(obj: Any) -> set[str]:
    if isinstance(obj, dict):
        return {str(k).lower() for k in obj.keys()}
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return {str(k).lower() for k in obj[0].keys()}
    return set()


def _contains_field_value(obj: Any, field: str, value: Any) -> bool:
    """Recursive search: does ``obj`` contain ``field`` with the probe value?"""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() == field.lower() and _value_matches(v, value):
                return True
            if _contains_field_value(v, field, value):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _contains_field_value(item, field, value):
                return True
    return False


def _value_matches(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict)
    if isinstance(expected, list):
        return isinstance(actual, list) and bool(actual)
    if isinstance(expected, bool):
        return bool(actual) == expected
    return str(actual).lower() == str(expected).lower()
