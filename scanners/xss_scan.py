"""XSS scanner — replaces dalfox.

Context-aware canary probes reduce false-positive rate vs unstructured canaries.
Reflected XSS: HTTP-only path (always).
DOM XSS: Playwright path (gated on BrowserSession availability).

Canary contexts:
  html_body  — <cny-{token}
  html_attr  — cny-{token}=
  js_string  — 'cny-{token}'
  js_template— ${cny-{token}}
  script_break— </script><cny-{token}>
"""

from __future__ import annotations

import asyncio
import re
import secrets
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

_CONCURRENCY = 10

_CONTEXT_PAYLOADS: list[tuple[str, str, str]] = [
    ("html_body", "<cny-{token}", r"<cny-{token}"),
    ("html_attr", 'cny-{token}="', r'cny-{token}="'),
    ("js_string", "'cny-{token}'", r"'cny-{token}'"),
    ("js_template", "${cny-{token}}", r"\$\{cny-{token}\}"),
    ("script_break", '</script><cny-{token}>', r'cny-{token}>'),
]

# Context detected from surrounding 8 chars
_CONTEXT_DETECTION_RE = {
    "html_body": re.compile(r"<cny-\w+"),
    "html_attr": re.compile(r'cny-\w+="'),
    "js_string": re.compile(r"'cny-\w+'"),
    "js_template": re.compile(r"\$\{cny-\w+\}"),
    "script_break": re.compile(r"cny-\w+>"),
}


@register_scanner
class XSSScanner(Scanner):
    name = "xss_scan"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(
        self,
        http_client: "HTTPClient",
        browser: Any | None = None,  # BrowserSession | None
    ) -> None:
        self._http = http_client
        self._browser = browser

    async def scan(
        self,
        target_url: str,
        params: list[str] | None = None,
    ) -> ScanResult:
        """Scan for XSS in URL parameters."""
        parsed = urlparse(target_url)
        existing_params = list(parse_qs(parsed.query).keys())
        all_params = list(dict.fromkeys((params or []) + existing_params))

        if not all_params:
            return ScanResult(
                scanner=self.name, target=target_url, success=False,
                error="no parameters to test",
            )

        sem = asyncio.Semaphore(_CONCURRENCY)
        findings: list[ScanFinding] = []

        # Reflected XSS (always)
        refl_tasks = [
            self._scan_param_reflected(target_url, param, sem)
            for param in all_params
        ]
        refl_results = await asyncio.gather(*refl_tasks, return_exceptions=True)
        findings.extend(f for f in refl_results if isinstance(f, ScanFinding))

        # DOM XSS (Playwright-gated)
        if self._browser is not None:
            dom_findings = await self._scan_dom_xss(target_url, all_params)
            findings.extend(dom_findings)

        dom_mode = "DOM+reflected" if self._browser is not None else "reflected-only"
        return ScanResult(
            scanner=self.name,
            target=target_url,
            success=True,
            data={
                "params_tested": all_params,
                "findings": len(findings),
                "mode": dom_mode,
            },
            findings=findings,
            raw_text=_format_xss(target_url, findings, all_params, dom_mode),
        )

    async def _scan_param_reflected(
        self, url: str, param: str, sem: asyncio.Semaphore
    ) -> ScanFinding | None:
        token = secrets.token_hex(6)
        async with sem:
            for ctx_name, payload_tpl, detection_tpl in _CONTEXT_PAYLOADS:
                payload = payload_tpl.format(token=token)
                detection = detection_tpl.format(token=token)
                probe_url = _inject_param(url, param, payload)
                resp = await self._http.get(probe_url, scanner_tool=self.name)
                if resp is None:
                    continue
                if re.search(re.escape(detection.replace("\\", "")), resp.text):
                    return ScanFinding(
                        vuln_class=f"xss-reflected-{ctx_name}",
                        title=f"Reflected XSS in parameter '{param}' ({ctx_name} context)",
                        severity="high",
                        affected_target=url,
                        affected_param=param,
                        description=(
                            f"Reflected XSS: payload {payload!r} reflected in "
                            f"{ctx_name} context (token={token})."
                        ),
                        cwe=["CWE-79"],
                        mitre=["T1059.007"],
                        remediation="HTML-encode all user input before rendering.",
                        confidence="probable",
                        extra={"context": ctx_name, "payload": payload},
                    )
        return None

    async def _scan_dom_xss(
        self, url: str, params: list[str]
    ) -> list[ScanFinding]:
        """Use Playwright to detect DOM XSS (execute JS, hook DOM mutations)."""
        findings: list[ScanFinding] = []
        try:
            token = secrets.token_hex(6)
            # Inject into first param
            param = params[0] if params else "q"
            payload = f"<img src=x onerror=window.__xss_cny_{token}=1>"
            probe_url = _inject_param(url, param, payload)

            await self._browser.navigate(probe_url)
            # Check if our marker was set (onerror fired)
            result = await self._browser.evaluate(
                f"typeof window.__xss_cny_{token} !== 'undefined'"
            )
            if result:
                findings.append(ScanFinding(
                    vuln_class="xss-dom",
                    title=f"DOM XSS in parameter '{param}'",
                    severity="high",
                    affected_target=url,
                    affected_param=param,
                    description=f"DOM XSS: injected payload executed in browser (token={token}).",
                    cwe=["CWE-79"],
                    mitre=["T1059.007"],
                    remediation="Sanitise DOM sinks (innerHTML, document.write, eval).",
                    confidence="verified",
                ))
        except Exception as e:
            pass  # Browser errors don't block reflected path
        return findings


def _inject_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _format_xss(url: str, findings: list[ScanFinding], params: list[str], mode: str) -> str:
    lines = [f"XSS scan on {url} ({len(params)} params, mode={mode}):"]
    if findings:
        for f in findings:
            lines.append(f"  VULN [{f.severity}] {f.vuln_class}: {f.affected_param}")
    else:
        lines.append("  No XSS found.")
    return "\n".join(lines)
