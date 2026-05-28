"""Web application auditor — replaces wapiti + nikto + zap-baseline.

Three HTTP-only batteries:
  1. Misconfig (nikto-style): .git, .env, admin paths, default creds, debug pages
  2. CORS audit: reflected-origin, null-origin, wildcard+credentials
  3. Injection breadth (wapiti-style): file inclusion, XXE time-based, command injection time-based
  4. Non-blind SSRF: in-band detection only (cloud metadata, localhost reflection)

Blind SSRF deferred to v1.1 (requires OOB callback infrastructure).
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

# ── Misconfig paths ───────────────────────────────────────────────────────────

_SENSITIVE_PATHS = [
    ("/.git/HEAD", "high", "git-exposure", "Git repository HEAD exposed"),
    ("/.env", "high", "env-exposure", ".env file exposed"),
    ("/.htaccess", "medium", "htaccess-exposure", ".htaccess exposed"),
    ("/web.config", "medium", "webconfig-exposure", "web.config exposed"),
    ("/phpinfo.php", "medium", "phpinfo-exposure", "phpinfo() page exposed"),
    ("/admin/", "low", "admin-panel", "Admin panel accessible"),
    ("/administrator/", "low", "admin-panel", "Admin panel accessible"),
    ("/wp-admin/", "medium", "wordpress-admin", "WordPress admin exposed"),
    ("/actuator", "medium", "spring-actuator", "Spring actuator exposed"),
    ("/actuator/env", "high", "spring-actuator-env", "Spring actuator /env exposed"),
    ("/api-docs", "low", "api-docs", "API docs exposed"),
    ("/swagger-ui.html", "low", "swagger-ui", "Swagger UI exposed"),
    ("/debug", "medium", "debug-page", "Debug page accessible"),
    ("/.well-known/security.txt", "informational", "security-txt", "security.txt present (OK)"),
    ("/server-status", "high", "apache-server-status", "Apache server-status exposed"),
    ("/server-info", "high", "apache-server-info", "Apache server-info exposed"),
]

# Default credentials to try on /admin paths
_DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("admin", ""), ("test", "test"),
    ("administrator", "administrator"), ("user", "user"),
]

# ── SSRF probes (non-blind, in-band only) ─────────────────────────────────────

_SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",           # GCP metadata
    "http://169.254.169.254/metadata/instance",   # Azure metadata
    "http://127.0.0.1/",                          # localhost
]

_SSRF_INDICATORS = [
    "ami-id", "instance-id", "hostname", "computeMetadata",
    "subscriptionId", "resourceGroupName",
]

# ── Command injection time-based ──────────────────────────────────────────────

_CMDI_PAYLOADS = [
    "; sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "& ping -c 5 127.0.0.1",
    "; timeout 5",
]
_CMDI_THRESHOLD = 4.0

# ── File inclusion payloads ────────────────────────────────────────────────────

_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../../../windows/win.ini",
    "....//....//....//etc/passwd",
]
_LFI_INDICATORS = ["root:x:", "[extensions]", "boot.ini"]

# ── XXE payload ───────────────────────────────────────────────────────────────

_XXE_PAYLOAD = (
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    '<foo>&xxe;</foo>'
)
_XXE_INDICATOR = "root:x:"

_CONCURRENCY = 15


@register_scanner
class WebAuditScanner(Scanner):
    name = "web_audit"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def audit(self, target_url: str) -> ScanResult:
        """Run all web audit batteries against target_url."""
        target_url = target_url.rstrip("/")
        sem = asyncio.Semaphore(_CONCURRENCY)

        results = await asyncio.gather(
            self._misconfig_checks(target_url, sem),
            self._cors_audit(target_url, sem),
            self._injection_breadth(target_url, sem),
            self._ssrf_probes(target_url, sem),
            return_exceptions=True,
        )

        findings: list[ScanFinding] = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return ScanResult(
            scanner=self.name,
            target=target_url,
            success=True,
            data={"findings": len(findings)},
            findings=findings,
            raw_text=_format_audit(target_url, findings),
        )

    # ── Battery 1: Misconfig ───────────────────────────────────────────────────

    async def _misconfig_checks(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        tasks = [self._check_path(base, path, severity, vuln_class, title, sem)
                 for path, severity, vuln_class, title in _SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, ScanFinding):
                findings.append(r)

        # Default credentials
        cred_findings = await self._check_default_creds(base, sem)
        findings.extend(cred_findings)

        # Phase-J 2026: deep Content-Security-Policy analysis. Replaces
        # the old boolean "is the header present?" check with a real
        # parser that flags unsafe-inline, unsafe-eval, wildcard sources,
        # data:-allowed script-src, missing frame-ancestors/base-uri,
        # and CDN-origin allowlists known to host JSONP gadgets.
        async with sem:
            root_resp = await self._http.get(base, scanner_tool=self.name)
        if root_resp is not None:
            findings.extend(_analyze_csp(base, root_resp.headers))

        return findings

    async def _check_path(
        self, base: str, path: str, severity: str,
        vuln_class: str, title: str, sem: asyncio.Semaphore
    ) -> ScanFinding | None:
        async with sem:
            url = base + path
            resp = await self._http.get(url, scanner_tool=self.name)
            if resp is None:
                return None
            if resp.status_code in (200, 204, 403):
                if vuln_class == "security-txt" and resp.status_code == 200:
                    return None  # security.txt present is good
                return ScanFinding(
                    vuln_class=vuln_class,
                    title=title,
                    severity=severity,
                    affected_target=url,
                    description=f"HTTP {resp.status_code} at {url}.",
                    cwe=["CWE-538"] if "git" in vuln_class else ["CWE-200"],
                    mitre=["T1083"],
                    remediation=f"Restrict access to {path} via server config.",
                    confidence="verified",
                )
        return None

    async def _check_default_creds(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        admin_paths = ["/admin/", "/admin", "/administrator/", "/wp-admin/"]
        for admin_path in admin_paths:
            url = base + admin_path
            for user, pwd in _DEFAULT_CREDS[:5]:
                async with sem:
                    import base64
                    creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    resp = await self._http.get(
                        url,
                        headers={"Authorization": f"Basic {creds}"},
                        scanner_tool=self.name,
                    )
                    if resp and resp.status_code in (200, 204):
                        findings.append(ScanFinding(
                            vuln_class="default-credentials",
                            title=f"Default credentials accepted: {user}:{pwd} on {url}",
                            severity="critical",
                            affected_target=url,
                            description=f"Basic auth with {user}:{pwd} returned HTTP {resp.status_code}.",
                            cwe=["CWE-521"],
                            mitre=["T1110.001"],
                            remediation="Change default credentials immediately.",
                            confidence="verified",
                        ))
                        break
        return findings

    # ── Battery 2: CORS audit ──────────────────────────────────────────────────

    async def _cors_audit(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        test_urls = [base + "/", base + "/api/", base + "/api/me"]

        for url in test_urls:
            async with sem:
                # Test: reflected origin
                resp = await self._http.get(
                    url,
                    headers={"Origin": "https://attacker.example.com"},
                    scanner_tool=self.name,
                )
                if resp is None:
                    continue
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == "*" and acac.lower() == "true":
                    findings.append(ScanFinding(
                        vuln_class="cors-wildcard-credentials",
                        title=f"CORS wildcard + credentials on {url}",
                        severity="high",
                        affected_target=url,
                        description="ACAO:* combined with ACAC:true allows cross-origin requests with credentials.",
                        cwe=["CWE-942"],
                        mitre=["T1557"],
                        remediation="Never combine ACAO:* with ACAC:true. Use explicit origin allowlist.",
                        confidence="verified",
                    ))
                elif "attacker.example.com" in acao:
                    findings.append(ScanFinding(
                        vuln_class="cors-reflected-origin",
                        title=f"CORS reflects arbitrary Origin on {url}",
                        severity="high",
                        affected_target=url,
                        description=f"Server reflects attacker origin in ACAO: {acao}",
                        cwe=["CWE-942"],
                        mitre=["T1557"],
                        remediation="Validate Origin against a strict allowlist.",
                        confidence="verified",
                    ))

                # Test: null origin
                resp2 = await self._http.get(
                    url,
                    headers={"Origin": "null"},
                    scanner_tool=self.name,
                )
                if resp2 and resp2.headers.get("access-control-allow-origin") == "null":
                    findings.append(ScanFinding(
                        vuln_class="cors-null-origin",
                        title=f"CORS accepts null origin on {url}",
                        severity="medium",
                        affected_target=url,
                        description="Server accepts null Origin — exploitable from sandboxed iframes.",
                        cwe=["CWE-942"],
                        remediation='Remove "null" from the CORS allowlist.',
                        confidence="verified",
                    ))
        return findings

    # ── Battery 3: Injection breadth ──────────────────────────────────────────

    async def _injection_breadth(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        # File inclusion (GET params)
        lfi_urls = [base + "/?file=", base + "/?page=", base + "/?path="]
        for url_prefix in lfi_urls:
            for payload in _LFI_PAYLOADS:
                async with sem:
                    resp = await self._http.get(
                        url_prefix + payload, scanner_tool=self.name
                    )
                    if resp and any(ind in resp.text for ind in _LFI_INDICATORS):
                        findings.append(ScanFinding(
                            vuln_class="path-traversal-lfi",
                            title=f"Path traversal / LFI at {url_prefix}",
                            severity="high",
                            affected_target=url_prefix,
                            description=f"LFI payload {payload!r} returned OS file content.",
                            cwe=["CWE-22"],
                            mitre=["T1083"],
                            remediation="Whitelist allowed file paths; never concatenate user input into file paths.",
                            confidence="verified",
                        ))
                        break

        # XXE
        async with sem:
            resp = await self._http.post(
                base + "/",
                content=_XXE_PAYLOAD.encode(),
                headers={"Content-Type": "application/xml"},
                scanner_tool=self.name,
            )
            if resp and _XXE_INDICATOR in resp.text:
                findings.append(ScanFinding(
                    vuln_class="xxe",
                    title=f"XXE injection at {base}",
                    severity="critical",
                    affected_target=base,
                    description="XXE: entity expansion returned /etc/passwd content.",
                    cwe=["CWE-611"],
                    mitre=["T1190"],
                    remediation="Disable external entity processing in XML parser.",
                    confidence="verified",
                ))

        # Command injection (time-based)
        cmdi_urls = [base + "/?cmd=", base + "/?exec=", base + "/?ping="]
        baseline = await _measure_resp_time(self._http, base + "/", "web_audit")
        for url_prefix in cmdi_urls:
            for payload in _CMDI_PAYLOADS[:3]:
                async with sem:
                    t0 = time.monotonic()
                    resp = await self._http.get(
                        url_prefix + payload, scanner_tool=self.name
                    )
                    elapsed = time.monotonic() - t0
                    if resp and elapsed - baseline >= _CMDI_THRESHOLD:
                        findings.append(ScanFinding(
                            vuln_class="command-injection",
                            title=f"Command injection (time-based) at {url_prefix}",
                            severity="critical",
                            affected_target=url_prefix,
                            description=f"Response took {elapsed:.1f}s (baseline={baseline:.1f}s, payload={payload!r}).",
                            cwe=["CWE-78"],
                            mitre=["T1059"],
                            remediation="Never pass user input to shell commands.",
                            confidence="probable",
                        ))
                        break

        return findings

    # ── Battery 4: Non-blind SSRF ─────────────────────────────────────────────

    async def _ssrf_probes(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        ssrf_params = [base + "/?url=", base + "/?dest=", base + "/?target="]

        for param_prefix in ssrf_params:
            for ssrf_target in _SSRF_TARGETS:
                async with sem:
                    resp = await self._http.get(
                        param_prefix + ssrf_target,
                        scanner_tool=self.name,
                        check_scope=True,
                    )
                    if resp and any(ind in resp.text for ind in _SSRF_INDICATORS):
                        findings.append(ScanFinding(
                            vuln_class="ssrf-non-blind",
                            title=f"Non-blind SSRF at {param_prefix}",
                            severity="critical",
                            affected_target=param_prefix,
                            description=(
                                f"SSRF: fetching {ssrf_target} returned cloud metadata indicators. "
                                "Blind SSRF not tested (requires OOB infrastructure)."
                            ),
                            cwe=["CWE-918"],
                            mitre=["T1190"],
                            remediation="Implement server-side URL allowlist; block RFC1918 + link-local ranges.",
                            confidence="verified",
                        ))
        return findings


async def _measure_resp_time(http: "HTTPClient", url: str, tool: str) -> float:
    t0 = time.monotonic()
    await http.get(url, scanner_tool=tool)
    return time.monotonic() - t0


def _format_audit(target: str, findings: list[ScanFinding]) -> str:
    lines = [f"Web audit on {target}: {len(findings)} findings"]
    for f in sorted(findings, key=lambda x: x.severity):
        lines.append(f"  [{f.severity}] {f.vuln_class}: {f.affected_target}")
    return "\n".join(lines)


# ── Phase-J 2026: deep CSP analyzer ─────────────────────────────────
#
# Most modern web findings come from CSP MISCONFIG, not absence of CSP.
# We parse the directive→sources map and flag canonical bad patterns:
# 'unsafe-inline', 'unsafe-eval', '*', data:, missing frame-ancestors /
# base-uri, and CDN allowlists known to host JSONP gadgets that bypass
# strict CSP.

_CSP_CDN_GADGET_HOSTS = frozenset({
    "ajax.googleapis.com",
    "www.googleapis.com",
    "gstatic.com",
    "*.googleapis.com",
    "yandex.ru",
    "*.yandex.net",
    "vk.com",
    "ok.ru",
    "*.alicdn.com",
})


def _parse_csp(value: str) -> dict[str, list[str]]:
    """Return ``{directive: [sources, ...]}`` from a CSP header value."""
    out: dict[str, list[str]] = {}
    if not value:
        return out
    for policy in value.split(","):
        for directive in policy.split(";"):
            parts = directive.strip().split()
            if not parts:
                continue
            name = parts[0].lower().strip()
            srcs = [p.strip() for p in parts[1:]]
            out.setdefault(name, []).extend(srcs)
    return out


def _analyze_csp(target: str, headers: Any) -> list[ScanFinding]:
    """Emit findings for CSP misconfig.

    ``headers`` is either an httpx Headers object or a dict-like.
    """
    findings: list[ScanFinding] = []
    csp_value = ""
    try:
        csp_value = headers.get("content-security-policy", "") or ""
    except Exception:
        return findings
    csp_ro = ""
    try:
        csp_ro = headers.get("content-security-policy-report-only", "") or ""
    except Exception:
        pass

    if not csp_value:
        if csp_ro:
            findings.append(ScanFinding(
                vuln_class="csp-report-only",
                title="CSP is in report-only mode (not enforced)",
                severity="medium",
                affected_target=target,
                description=(
                    "Only Content-Security-Policy-Report-Only is set; the "
                    "policy is observed but never enforced. Adversaries "
                    "still execute inline scripts."
                ),
                cwe=["CWE-693"],
                confidence="verified",
            ))
        else:
            findings.append(ScanFinding(
                vuln_class="missing-csp",
                title="Content-Security-Policy header missing",
                severity="medium",
                affected_target=target,
                description="No CSP enforced on root document.",
                cwe=["CWE-693"],
                confidence="verified",
            ))
        return findings

    parsed = _parse_csp(csp_value)
    script_src = (parsed.get("script-src") or parsed.get("default-src") or [])
    style_src = (parsed.get("style-src") or parsed.get("default-src") or [])

    def _has(src: list[str], pat: str) -> bool:
        return any(pat == s.lower() or pat in s.lower() for s in src)

    if _has(script_src, "'unsafe-inline'"):
        findings.append(ScanFinding(
            vuln_class="csp-unsafe-inline",
            title="CSP allows 'unsafe-inline' for scripts",
            severity="high",
            affected_target=target,
            description=(
                "script-src includes 'unsafe-inline' — every reflected "
                "XSS becomes executable. Use a nonce or hash instead."
            ),
            cwe=["CWE-79", "CWE-693"],
            mitre=["T1059.007"],
            confidence="verified",
        ))

    if _has(script_src, "'unsafe-eval'"):
        findings.append(ScanFinding(
            vuln_class="csp-unsafe-eval",
            title="CSP allows 'unsafe-eval' for scripts",
            severity="medium",
            affected_target=target,
            description=(
                "script-src includes 'unsafe-eval' — eval(), Function(), "
                "setTimeout(string, ...) remain available, defeating a "
                "common XSS-mitigation property of CSP."
            ),
            cwe=["CWE-693", "CWE-95"],
            confidence="verified",
        ))

    if _has(script_src, "*") and not _has(script_src, "'self'"):
        findings.append(ScanFinding(
            vuln_class="csp-wildcard-script-src",
            title="CSP script-src contains wildcard *",
            severity="high",
            affected_target=target,
            description=(
                "script-src includes a literal '*' — the policy permits "
                "scripts from ANY origin, neutralising CSP."
            ),
            cwe=["CWE-693"],
            confidence="verified",
        ))

    if any(s.lower().startswith("data:") for s in script_src):
        findings.append(ScanFinding(
            vuln_class="csp-data-script-src",
            title="CSP script-src allows data: URIs",
            severity="high",
            affected_target=target,
            description=(
                "script-src allows the data: scheme, letting an XSS "
                "payload deliver script via a data URI."
            ),
            cwe=["CWE-693", "CWE-79"],
            confidence="verified",
        ))

    flagged_hosts: list[str] = []
    for src in script_src:
        host = src.strip("'").lower()
        if host in _CSP_CDN_GADGET_HOSTS:
            flagged_hosts.append(host)
    if flagged_hosts:
        findings.append(ScanFinding(
            vuln_class="csp-cdn-gadget-allowlist",
            title=f"CSP allowlists CDN with known JSONP gadgets: {flagged_hosts}",
            severity="medium",
            affected_target=target,
            description=(
                f"script-src includes {flagged_hosts}. These origins host "
                "JSONP/open-redirect gadgets that adversaries chain with "
                "reflected XSS to bypass CSP."
            ),
            cwe=["CWE-693"],
            confidence="probable",
            extra={"flagged_hosts": flagged_hosts},
        ))

    if "frame-ancestors" not in parsed:
        findings.append(ScanFinding(
            vuln_class="csp-missing-frame-ancestors",
            title="CSP missing frame-ancestors directive",
            severity="medium",
            affected_target=target,
            description=(
                "Without frame-ancestors the page is clickjackable even "
                "if X-Frame-Options is set on a different host."
            ),
            cwe=["CWE-1021"],
            confidence="verified",
        ))

    if "base-uri" not in parsed:
        findings.append(ScanFinding(
            vuln_class="csp-missing-base-uri",
            title="CSP missing base-uri directive",
            severity="low",
            affected_target=target,
            description=(
                "Without base-uri an XSS that injects a <base> tag can "
                "redirect every relative-URL fetch to an attacker host."
            ),
            cwe=["CWE-693"],
            confidence="verified",
        ))

    if _has(style_src, "'unsafe-inline'") and not _has(style_src, "'nonce-"):
        findings.append(ScanFinding(
            vuln_class="csp-style-unsafe-inline",
            title="CSP allows 'unsafe-inline' for styles",
            severity="low",
            affected_target=target,
            description=(
                "style-src 'unsafe-inline' enables CSS-injection exfil "
                "patterns (attribute-selector regex)."
            ),
            cwe=["CWE-693"],
            confidence="verified",
        ))

    return findings
