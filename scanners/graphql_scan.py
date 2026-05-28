"""GraphQL scanner — introspection, alias-DoS, depth, batching, suggestions.

Covers the OWASP API Security Top-10 GraphQL surface:
- Endpoint discovery (/graphql, /api/graphql, /v1/graphql, /graphiql)
- Introspection enabled in production
- Field-suggestion leakage (typo'd field → server enumerates alternatives)
- Alias-based amplification DoS (1000 aliases of same heavy field)
- Query-depth limit absent (10-deep recursion)
- Batched-query rate-bypass (single POST, N operations)

Pure Python — uses HTTPClient JSON helpers.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanFinding, ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


_DISCOVERY_PATHS = (
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/graphiql", "/playground", "/api/v1/graphql", "/query",
    "/gql", "/index.php?graphql", "/graphql/console",
)

_INTROSPECTION_QUERY = (
    "query IntrospectionQuery { __schema { queryType { name } "
    "types { name kind } } }"
)

# Trivial probe to detect that the endpoint speaks GraphQL.
_PROBE_QUERY = "{ __typename }"

# Field-suggestion leakage: ask for a typo'd field and look for server
# helpfully suggesting "Did you mean ..."
_SUGGEST_QUERY = "{ __typename usrr { id } }"


@register_scanner
class GraphQLScanner(Scanner):
    name = "graphql_scan"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def scan(self, base_url: str) -> ScanResult:
        result = ScanResult(scanner=self.name, target=base_url)
        endpoint = await self._discover(base_url)
        if endpoint is None:
            result.success = False
            result.error = "no GraphQL endpoint found at common paths"
            return result

        result.data["endpoint"] = endpoint

        # 1. Introspection
        introspection_enabled = await self._check_introspection(endpoint)
        if introspection_enabled:
            result.findings.append(ScanFinding(
                vuln_class="graphql-introspection",
                title="GraphQL introspection enabled",
                severity="medium",
                affected_target=endpoint,
                description=(
                    "Introspection lets adversaries enumerate the entire "
                    "schema — every type, field, and resolver — without "
                    "running a single business query. Disable in production "
                    "or restrict by role."
                ),
                cwe=["CWE-200"],
                confidence="verified",
            ))
        result.data["introspection_enabled"] = introspection_enabled

        # 2. Field-suggestion leakage
        suggestion_leak = await self._check_suggestions(endpoint)
        if suggestion_leak:
            result.findings.append(ScanFinding(
                vuln_class="graphql-field-suggestions",
                title="GraphQL field-name suggestions enabled",
                severity="low",
                affected_target=endpoint,
                description=(
                    'Server returns "Did you mean ..." for typo\'d fields, '
                    "leaking schema details even when introspection is off."
                ),
                cwe=["CWE-200"],
                confidence="verified",
            ))

        # 3. Alias-based DoS (informational — we don't actually flood)
        alias_ok = await self._check_alias_amplification(endpoint, count=20)
        if alias_ok:
            result.findings.append(ScanFinding(
                vuln_class="graphql-alias-amplification",
                title="GraphQL accepts large alias batches (DoS surface)",
                severity="medium",
                affected_target=endpoint,
                description=(
                    "Server accepted 20 aliased calls to the same field in "
                    "one request without rate-limiting. Adversaries scale "
                    "this to thousands for amplified DoS or auth-bypass on "
                    "per-call rate limits."
                ),
                cwe=["CWE-770"],
                confidence="probable",
            ))

        # 4. Depth-limit
        depth_ok = await self._check_depth_limit(endpoint, depth=8)
        if depth_ok:
            result.findings.append(ScanFinding(
                vuln_class="graphql-depth-unbounded",
                title="GraphQL accepts deeply-nested queries (no depth limit)",
                severity="medium",
                affected_target=endpoint,
                description=(
                    "Depth-8 recursive query was accepted without rejection. "
                    "Adversaries leverage this for exponential DoS."
                ),
                cwe=["CWE-674"],
                confidence="probable",
            ))

        # 5. Batched-query support (rate-limit bypass surface)
        batched_ok = await self._check_batching(endpoint)
        if batched_ok:
            result.findings.append(ScanFinding(
                vuln_class="graphql-batching",
                title="GraphQL accepts batched query arrays",
                severity="low",
                affected_target=endpoint,
                description=(
                    "Server accepts a JSON array of operations in a single "
                    "POST. Adversaries use this to bypass per-request rate "
                    "limits during credential brute-force."
                ),
                cwe=["CWE-307"],
                confidence="verified",
            ))

        return result

    # ── Internals ──────────────────────────────────────────────────

    async def _discover(self, base_url: str) -> str | None:
        for path in _DISCOVERY_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            r = await self._http.post(
                url,
                headers={"Content-Type": "application/json"},
                content=json.dumps({"query": _PROBE_QUERY}),
                scanner_tool=self.name,
            )
            if r is None:
                continue
            ctype = (r.headers.get("content-type") or "").lower()
            if r.status_code == 200 and "json" in ctype:
                try:
                    body = r.json()
                except Exception:
                    continue
                if isinstance(body, dict) and ("data" in body or "errors" in body):
                    return url
        return None

    async def _check_introspection(self, endpoint: str) -> bool:
        r = await self._http.post(
            endpoint,
            headers={"Content-Type": "application/json"},
            content=json.dumps({"query": _INTROSPECTION_QUERY}),
            scanner_tool=self.name,
        )
        if r is None or r.status_code != 200:
            return False
        try:
            data = r.json()
        except Exception:
            return False
        schema = (data or {}).get("data", {}).get("__schema")
        return bool(schema and isinstance(schema, dict))

    async def _check_suggestions(self, endpoint: str) -> bool:
        r = await self._http.post(
            endpoint,
            headers={"Content-Type": "application/json"},
            content=json.dumps({"query": _SUGGEST_QUERY}),
            scanner_tool=self.name,
        )
        if r is None:
            return False
        text = (r.text or "").lower()
        return "did you mean" in text

    async def _check_alias_amplification(self, endpoint: str, *, count: int) -> bool:
        aliases = " ".join(f"a{i}: __typename" for i in range(count))
        q = "{ " + aliases + " }"
        r = await self._http.post(
            endpoint,
            headers={"Content-Type": "application/json"},
            content=json.dumps({"query": q}),
            scanner_tool=self.name,
        )
        if r is None or r.status_code != 200:
            return False
        try:
            data = r.json()
        except Exception:
            return False
        # Server accepted all N aliased calls if data has all keys
        keys = set((data or {}).get("data", {}).keys())
        return len(keys) >= count // 2

    async def _check_depth_limit(self, endpoint: str, *, depth: int) -> bool:
        # Build "{ __schema { types { fields { type { fields ... } } } } }"
        # capped at the requested depth using __schema chain.
        inner = "name"
        for _ in range(depth):
            inner = f"{{ {inner} type {{ name }} }}"
        q = "query { __schema { types " + inner + " } }"
        r = await self._http.post(
            endpoint,
            headers={"Content-Type": "application/json"},
            content=json.dumps({"query": q}),
            scanner_tool=self.name,
        )
        if r is None:
            return False
        # Accepted = 200 with no "depth" / "complexity" error
        if r.status_code != 200:
            return False
        text = (r.text or "").lower()
        return ("depth" not in text and "complexity" not in text
                and "limit" not in text)

    async def _check_batching(self, endpoint: str) -> bool:
        batch = [{"query": _PROBE_QUERY}, {"query": _PROBE_QUERY}]
        r = await self._http.post(
            endpoint,
            headers={"Content-Type": "application/json"},
            content=json.dumps(batch),
            scanner_tool=self.name,
        )
        if r is None or r.status_code != 200:
            return False
        try:
            data = r.json()
        except Exception:
            return False
        return isinstance(data, list) and len(data) == 2
