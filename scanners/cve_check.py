"""CVE check engine — replaces nuclei.

Loads YAML check files from skills/checks/cves/ and tests each against the
target URL via the shared HTTPClient. Each check follows this schema:

  id: CVE-2024-XXXXX
  severity: high
  http_request:
    method: GET
    path: /admin/login.php
    body: ""
    headers: {}
  expected_response:
    status: 200            # optional; omit to match any
    body_contains: "Tomcat"
    body_not_contains: ""  # optional negative match
    headers_contain: {}    # dict of header_name → substring
  cvss: 7.5
  cwe: ["CWE-89"]
  mitre: ["T1190"]
  references: []

Operator can add custom checks to workspace/checks/*.yaml.
"""

from __future__ import annotations

import importlib.resources
import asyncio
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, Field, field_validator

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

_NETWORK_PIPELINE_ROOT = Path(__file__).parent.parent
_BUNDLED_CHECKS_DIR = _NETWORK_PIPELINE_ROOT / "skills" / "checks" / "cves"

_CONCURRENCY = 10


# ── Check schema ──────────────────────────────────────────────────────────────


class CheckHTTPRequest(BaseModel):
    method: str = "GET"
    path: str = "/"
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)


class CheckExpectedResponse(BaseModel):
    status: int | None = None
    body_contains: str = ""
    body_not_contains: str = ""
    headers_contain: dict[str, str] = Field(default_factory=dict)


class CVECheck(BaseModel):
    id: str
    title: str = ""
    severity: str = "medium"
    http_request: CheckHTTPRequest = Field(default_factory=CheckHTTPRequest)
    expected_response: CheckExpectedResponse = Field(default_factory=CheckExpectedResponse)
    cvss: float = 0.0
    cwe: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    remediation: str = ""

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"critical", "high", "medium", "low", "informational"}
        return v.lower() if v.lower() in valid else "medium"


# ── Check loader ──────────────────────────────────────────────────────────────


def load_checks(extra_dir: Path | None = None) -> list[CVECheck]:
    """Load all YAML checks from bundled dir + optional workspace dir."""
    checks: list[CVECheck] = []

    dirs: list[Path] = [_BUNDLED_CHECKS_DIR]
    if extra_dir and extra_dir.is_dir():
        dirs.append(extra_dir)

    for check_dir in dirs:
        if not check_dir.is_dir():
            continue
        for yaml_file in sorted(check_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    continue
                check = CVECheck.model_validate(data)
                checks.append(check)
            except Exception as e:
                import logging
                logging.getLogger("scanners.cve_check").warning(
                    "failed to load check %s: %s", yaml_file.name, e
                )

    return checks


# ── Scanner ───────────────────────────────────────────────────────────────────


@register_scanner
class CVECheckScanner(Scanner):
    name = "cve_check"
    requires_libs = ("yaml",)
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(
        self,
        http_client: "HTTPClient",
        workspace: Path | None = None,
    ) -> None:
        self._http = http_client
        self._workspace = workspace
        self._checks: list[CVECheck] | None = None

    def _get_checks(self) -> list[CVECheck]:
        if self._checks is None:
            extra = (self._workspace / "checks") if self._workspace else None
            self._checks = load_checks(extra_dir=extra)
        return self._checks

    async def run(self, target_url: str) -> ScanResult:
        """Run all loaded checks against target_url."""
        checks = self._get_checks()
        if not checks:
            return ScanResult(
                scanner=self.name, target=target_url,
                data={"checks_loaded": 0},
                raw_text="No CVE checks loaded.",
            )

        target_url = target_url.rstrip("/")
        sem = asyncio.Semaphore(_CONCURRENCY)
        tasks = [self._run_check(target_url, check, sem) for check in checks]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings = [r for r in results if isinstance(r, ScanFinding)]

        return ScanResult(
            scanner=self.name,
            target=target_url,
            success=True,
            data={
                "checks_run": len(checks),
                "findings": len(findings),
            },
            findings=findings,
            raw_text=_format_cve_results(target_url, findings, len(checks)),
        )

    async def _run_check(
        self,
        target_url: str,
        check: CVECheck,
        sem: asyncio.Semaphore,
    ) -> ScanFinding | None:
        async with sem:
            url = target_url + check.http_request.path
            try:
                resp = await self._http.request(
                    check.http_request.method,
                    url,
                    content=check.http_request.body.encode() if check.http_request.body else None,
                    headers=check.http_request.headers,
                    scanner_tool=self.name,
                )
            except Exception:
                return None

            if resp is None:
                return None

            exp = check.expected_response
            # Status check
            if exp.status is not None and resp.status_code != exp.status:
                return None
            # Body positive match
            if exp.body_contains and exp.body_contains not in resp.text:
                return None
            # Body negative match (must NOT contain)
            if exp.body_not_contains and exp.body_not_contains in resp.text:
                return None
            # Header checks
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            for hdr_name, hdr_val in exp.headers_contain.items():
                actual = resp_headers.get(hdr_name.lower(), "")
                if hdr_val not in actual:
                    return None

            # All conditions matched
            return ScanFinding(
                vuln_class=check.id,
                title=check.title or f"{check.id} detected on {target_url}",
                severity=check.severity,
                affected_target=url,
                description=f"Check {check.id} matched. References: {', '.join(check.references[:2])}",
                cwe=check.cwe,
                mitre=check.mitre,
                remediation=check.remediation,
                confidence="probable",
                extra={"cvss": check.cvss, "path": check.http_request.path},
            )


def _format_cve_results(target: str, findings: list[ScanFinding], total: int) -> str:
    lines = [f"CVE check on {target}: {len(findings)}/{total} checks matched"]
    for f in findings:
        lines.append(f"  [{f.severity}] {f.vuln_class}: {f.title}")
    return "\n".join(lines)
