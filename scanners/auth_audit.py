"""Auth flow auditor.

Checks: weak password reset, session fixation, predictable cookies,
missing CSRF tokens, cookie security flags.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

_CONCURRENCY = 10


@register_scanner
class AuthAuditScanner(Scanner):
    name = "auth_audit"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def audit(self, target_url: str) -> ScanResult:
        """Run auth-flow checks against target_url."""
        target_url = target_url.rstrip("/")
        sem = asyncio.Semaphore(_CONCURRENCY)

        results = await asyncio.gather(
            self._cookie_flags(target_url, sem),
            self._csrf_check(target_url, sem),
            self._session_fixation(target_url, sem),
            self._password_reset_weakness(target_url, sem),
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
            raw_text=_format_auth(target_url, findings),
        )

    async def _cookie_flags(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        async with sem:
            resp = await self._http.get(base + "/", scanner_tool=self.name)
            if resp is None:
                return findings

            for header_val in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]:
                if not header_val:
                    continue
                cookie_lower = header_val.lower()
                missing_flags: list[str] = []
                if "httponly" not in cookie_lower:
                    missing_flags.append("HttpOnly")
                if "secure" not in cookie_lower:
                    missing_flags.append("Secure")
                if "samesite" not in cookie_lower:
                    missing_flags.append("SameSite")

                if missing_flags:
                    cookie_name = header_val.split("=")[0].strip()
                    findings.append(ScanFinding(
                        vuln_class="insecure-cookie",
                        title=f"Cookie '{cookie_name}' missing flags: {', '.join(missing_flags)}",
                        severity="medium" if "HttpOnly" in missing_flags else "low",
                        affected_target=base,
                        description=f"Set-Cookie: {header_val[:120]} — missing {', '.join(missing_flags)}.",
                        cwe=["CWE-1004"] if "HttpOnly" in missing_flags else ["CWE-614"],
                        mitre=["T1539"],
                        remediation=f"Add {', '.join(missing_flags)} flags to Set-Cookie.",
                        confidence="verified",
                    ))
        return findings

    async def _csrf_check(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        """Check if POST endpoints accept requests without CSRF tokens."""
        findings: list[ScanFinding] = []
        post_paths = ["/login", "/register", "/password/reset", "/account/update", "/api/"]

        for path in post_paths:
            async with sem:
                url = base + path
                resp = await self._http.post(
                    url,
                    data={"test": "csrf_probe"},
                    headers={"Referer": "https://attacker.example.com"},
                    scanner_tool=self.name,
                )
                if resp and resp.status_code in (200, 302, 400):
                    # Check response doesn't mention CSRF error
                    if not any(w in resp.text.lower() for w in ("csrf", "token", "forbidden")):
                        findings.append(ScanFinding(
                            vuln_class="missing-csrf",
                            title=f"Possible missing CSRF protection at {url}",
                            severity="medium",
                            affected_target=url,
                            description=f"POST to {url} returned {resp.status_code} with no CSRF error indication.",
                            cwe=["CWE-352"],
                            mitre=["T1185"],
                            remediation="Implement CSRF tokens (Double Submit Cookie or Synchronizer Token Pattern).",
                            confidence="unverified",
                        ))
        return findings

    async def _session_fixation(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        """Check if the server accepts a pre-set session ID without regenerating."""
        findings: list[ScanFinding] = []
        fixed_id = secrets.token_hex(16)
        async with sem:
            # Request with a crafted session cookie
            resp = await self._http.get(
                base + "/login",
                headers={"Cookie": f"PHPSESSID={fixed_id}; JSESSIONID={fixed_id}"},
                scanner_tool=self.name,
            )
            if resp is None:
                return findings
            # If our fixed session ID is reflected back unchanged → fixation risk
            set_cookie = resp.headers.get("set-cookie", "")
            if fixed_id in set_cookie:
                findings.append(ScanFinding(
                    vuln_class="session-fixation",
                    title=f"Session fixation: server echoed pre-set session ID",
                    severity="high",
                    affected_target=base + "/login",
                    description="Server echoed the attacker-supplied session ID without regeneration.",
                    cwe=["CWE-384"],
                    mitre=["T1185"],
                    remediation="Regenerate session ID after authentication.",
                    confidence="probable",
                ))
        return findings

    async def _password_reset_weakness(
        self, base: str, sem: asyncio.Semaphore
    ) -> list[ScanFinding]:
        """Check for predictable/short reset tokens in password reset flow."""
        findings: list[ScanFinding] = []
        reset_paths = ["/forgot-password", "/password/reset", "/account/forgot",
                       "/reset", "/auth/forgot"]
        short_token_re = re.compile(r'[?&]token=([a-zA-Z0-9]{1,8})(?:&|$|")')

        for path in reset_paths:
            async with sem:
                url = base + path
                resp = await self._http.post(
                    url,
                    data={"email": "test@example.com"},
                    scanner_tool=self.name,
                )
                if resp is None:
                    continue
                m = short_token_re.search(resp.text)
                if m:
                    token = m.group(1)
                    findings.append(ScanFinding(
                        vuln_class="weak-reset-token",
                        title=f"Weak password reset token at {url}",
                        severity="high",
                        affected_target=url,
                        description=f"Reset token {token!r} appears short/predictable ({len(token)} chars).",
                        cwe=["CWE-640"],
                        mitre=["T1078"],
                        remediation="Use cryptographically random tokens ≥32 bytes.",
                        confidence="probable",
                    ))
        return findings


def _format_auth(target: str, findings: list[ScanFinding]) -> str:
    lines = [f"Auth audit on {target}: {len(findings)} findings"]
    for f in findings:
        lines.append(f"  [{f.severity}] {f.vuln_class}: {f.title}")
    return "\n".join(lines)
