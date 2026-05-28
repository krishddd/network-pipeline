"""Web-exposed supply-chain scanner.

Probes for accidentally-exposed dependency manifests + lock files
(``/package.json``, ``/package-lock.json``, ``/yarn.lock``,
``/composer.lock``, ``/Gemfile.lock``, ``/requirements.txt``,
``/poetry.lock``, ``/Pipfile.lock``, ``/go.sum``, ``/Cargo.lock``).

For each ``<name>@<version>`` extracted, batches a query to
OSV.dev (free, no key) and emits findings for any package version
with known advisories. Results are cached per-engagement so repeat
probes don't re-hit the API.

References:
- https://ossf.github.io/osv-schema/
- https://api.osv.dev/v1/querybatch
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanFinding, ScanResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


_LOCKFILE_PATHS = (
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock",
    "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/poetry.lock", "/Pipfile.lock",
    "/go.sum", "/go.mod",
    "/Cargo.lock", "/Cargo.toml",
    "/.env", "/.env.production", "/.env.local",  # also catches secrets
)

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_TIMEOUT_S = 15.0
_CACHE_TTL_S = 24 * 3600


@register_scanner
class SupplyChainScanner(Scanner):
    name = "supply_chain"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "low"

    def __init__(
        self,
        http_client: "HTTPClient",
        *,
        workspace: Path | None = None,
    ) -> None:
        self._http = http_client
        self._cache_dir = (workspace or Path(".")) / "cache" / "osv"
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            self._cache_dir = None  # type: ignore[assignment]

    async def scan(self, base_url: str) -> ScanResult:
        result = ScanResult(scanner=self.name, target=base_url)
        exposed: dict[str, str] = {}

        # 1. Probe lockfiles
        for path in _LOCKFILE_PATHS:
            url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            r = await self._http.get(url, scanner_tool=self.name)
            if r is None or r.status_code != 200:
                continue
            text = r.text or ""
            if len(text) < 5 or len(text) > 5_000_000:
                continue
            # Must look like the file type, not an HTML 404 with status 200
            if not _looks_like_lockfile(path, text):
                continue
            exposed[path] = url
            result.findings.append(ScanFinding(
                vuln_class="exposed-lockfile",
                title=f"Dependency manifest exposed: {path}",
                severity="medium" if path.endswith((".env", ".env.production", ".env.local")) else "low",
                affected_target=url,
                description=(
                    f"{path} is publicly retrievable. Adversaries use this "
                    "to identify exact dependency versions, then look up "
                    "known CVEs and known-malicious package names."
                ),
                cwe=["CWE-538", "CWE-200"],
                mitre=["T1592.002"],
                confidence="verified",
                extra={"size_bytes": len(text)},
            ))
            # 2. Parse + extract package@version pairs
            pkgs = _extract_packages(path, text)
            if pkgs:
                result.data.setdefault("packages_seen", {})[path] = len(pkgs)
                cve_findings = await self._osv_lookup(pkgs, url)
                result.findings.extend(cve_findings)

        result.data["lockfiles_exposed"] = list(exposed.keys())
        return result

    # ── OSV.dev integration ────────────────────────────────────────

    async def _osv_lookup(
        self,
        packages: list[tuple[str, str, str]],  # (ecosystem, name, version)
        source_url: str,
    ) -> list[ScanFinding]:
        if not packages:
            return []

        # Cache key per (ecosystem, name, version)
        results_by_pkg: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
        uncached: list[tuple[str, str, str]] = []
        for pkg in packages:
            cached = self._cache_get(pkg)
            if cached is not None:
                results_by_pkg[pkg] = cached
            else:
                uncached.append(pkg)

        if uncached:
            # Batch query OSV.dev
            queries = [
                {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": version,
                }
                for ecosystem, name, version in uncached
            ]
            try:
                r = await self._http.post(
                    _OSV_BATCH_URL,
                    headers={"Content-Type": "application/json"},
                    content=json.dumps({"queries": queries}),
                    scanner_tool=self.name,
                    check_scope=False,
                )
            except Exception:  # noqa: BLE001
                r = None
            if r is not None and r.status_code == 200:
                try:
                    data = r.json()
                    api_results = data.get("results") or []
                except Exception:
                    api_results = []
                for pkg, item in zip(uncached, api_results):
                    vulns = (item or {}).get("vulns") or []
                    results_by_pkg[pkg] = vulns
                    self._cache_put(pkg, vulns)

        # Build findings
        findings: list[ScanFinding] = []
        for (ecosystem, name, version), vulns in results_by_pkg.items():
            if not vulns:
                continue
            # Pick the highest-severity advisory
            vuln_ids = [v.get("id", "") for v in vulns if isinstance(v, dict)]
            sev = _severity_of(vulns)
            findings.append(ScanFinding(
                vuln_class="vulnerable-dependency",
                title=(
                    f"Known-vulnerable dependency: {name}@{version} "
                    f"({ecosystem}) — {len(vuln_ids)} advisories"
                ),
                severity=sev,
                affected_target=source_url,
                affected_param=f"{name}@{version}",
                description=(
                    f"OSV.dev lists {len(vuln_ids)} advisories for "
                    f"{name}@{version} in the {ecosystem} ecosystem: "
                    f"{', '.join(vuln_ids[:8])}"
                    f"{' …' if len(vuln_ids) > 8 else ''}. "
                    "Update to a non-affected version."
                ),
                cwe=["CWE-1104", "CWE-937"],
                mitre=["T1190"],
                confidence="verified",
                extra={
                    "ecosystem": ecosystem,
                    "package": name,
                    "version": version,
                    "advisory_ids": vuln_ids,
                },
            ))
        return findings

    def _cache_path(self, pkg: tuple[str, str, str]) -> Path | None:
        if self._cache_dir is None:
            return None
        eco, name, ver = pkg
        safe = re.sub(r"[^a-zA-Z0-9._@-]+", "_", f"{eco}__{name}__{ver}")
        return self._cache_dir / f"{safe}.json"

    def _cache_get(self, pkg: tuple[str, str, str]) -> list[dict[str, Any]] | None:
        p = self._cache_path(pkg)
        if p is None or not p.exists():
            return None
        try:
            mtime = p.stat().st_mtime
            if (time.time() - mtime) > _CACHE_TTL_S:
                return None
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def _cache_put(
        self, pkg: tuple[str, str, str], vulns: list[dict[str, Any]],
    ) -> None:
        p = self._cache_path(pkg)
        if p is None:
            return
        try:
            p.write_text(json.dumps(vulns), encoding="utf-8")
        except OSError:
            pass


# ── Lockfile parsers ────────────────────────────────────────────────

def _looks_like_lockfile(path: str, text: str) -> bool:
    head = text.lstrip()[:200].lower()
    if "<html" in head or "<!doctype" in head:
        return False
    if path.endswith((".json", ".lock")) and path.endswith(".json"):
        return head.startswith("{")
    if path.endswith(("yarn.lock", "Gemfile.lock", "Pipfile.lock", "Cargo.lock", "poetry.lock")):
        return True
    if path.endswith("requirements.txt"):
        return any(c.isalpha() for c in head[:80])
    if path.endswith(("go.sum", "go.mod")):
        return "module " in head or " v" in head
    if path.endswith((".env", ".env.production", ".env.local")):
        return "=" in text[:500]
    return True


_NPM_NAME_VER_RE = re.compile(r'"([^"]+)"\s*:\s*"([\^~>=<]*\d[^"]*)"')
_PIP_RE = re.compile(r"^([A-Za-z0-9._-]+)\s*[=]=\s*([^\s;#]+)", re.M)
_YARN_RE = re.compile(r'^"?([^@\s]+)@[^"]+"?:\s*\n\s+version\s+"([^"]+)"', re.M)
_COMPOSER_RE = re.compile(r'"name"\s*:\s*"([^"]+)"\s*,\s*"version"\s*:\s*"([^"]+)"')
_GO_SUM_RE = re.compile(r"^([^\s]+)\s+v([^\s]+)/go\.mod\s+", re.M)


def _extract_packages(path: str, text: str) -> list[tuple[str, str, str]]:
    """Return list of (ecosystem, name, version) tuples."""
    pkgs: list[tuple[str, str, str]] = []
    if path == "/package.json":
        try:
            obj = json.loads(text)
        except Exception:
            return pkgs
        for section in ("dependencies", "devDependencies"):
            for name, ver in (obj.get(section) or {}).items():
                ver = re.sub(r"^[\^~>=<\s]+", "", str(ver))
                if name and ver:
                    pkgs.append(("npm", name, ver))
    elif path == "/package-lock.json":
        try:
            obj = json.loads(text)
        except Exception:
            return pkgs
        # npm v7+ uses "packages": {"node_modules/foo": {"version": "1.2.3"}}
        for key, val in (obj.get("packages") or {}).items():
            if not isinstance(val, dict) or not key.startswith("node_modules/"):
                continue
            name = key.split("node_modules/")[-1]
            ver = val.get("version") or ""
            if name and ver:
                pkgs.append(("npm", name, ver))
        # legacy "dependencies" tree (npm v6)
        for name, val in (obj.get("dependencies") or {}).items():
            if isinstance(val, dict) and val.get("version"):
                pkgs.append(("npm", name, val["version"]))
    elif path == "/yarn.lock":
        for m in _YARN_RE.finditer(text):
            pkgs.append(("npm", m.group(1), m.group(2)))
    elif path == "/composer.lock":
        try:
            obj = json.loads(text)
        except Exception:
            return pkgs
        for entry in (obj.get("packages") or []) + (obj.get("packages-dev") or []):
            if isinstance(entry, dict) and entry.get("name") and entry.get("version"):
                ver = re.sub(r"^v", "", entry["version"])
                pkgs.append(("Packagist", entry["name"], ver))
    elif path == "/composer.json":
        try:
            obj = json.loads(text)
        except Exception:
            return pkgs
        for section in ("require", "require-dev"):
            for name, ver in (obj.get(section) or {}).items():
                ver = re.sub(r"^[\^~>=<\s]+v?", "", str(ver))
                if name and ver and "/" in name:
                    pkgs.append(("Packagist", name, ver))
    elif path in ("/Gemfile.lock", "/Gemfile"):
        for m in re.finditer(r"^\s+([A-Za-z0-9_-]+)\s+\(([^)]+)\)", text, re.M):
            pkgs.append(("RubyGems", m.group(1), m.group(2)))
    elif path == "/requirements.txt":
        for m in _PIP_RE.finditer(text):
            pkgs.append(("PyPI", m.group(1), m.group(2)))
    elif path in ("/poetry.lock", "/Pipfile.lock"):
        # Both contain name+version pairs in toml/json structure
        for m in re.finditer(
            r'name\s*=\s*"([^"]+)"\s*[\r\n]+\s*version\s*=\s*"([^"]+)"',
            text,
        ):
            pkgs.append(("PyPI", m.group(1), m.group(2)))
    elif path == "/go.sum":
        for m in _GO_SUM_RE.finditer(text):
            pkgs.append(("Go", m.group(1), m.group(2)))
    elif path == "/Cargo.lock":
        for m in re.finditer(
            r'name\s*=\s*"([^"]+)"\s*[\r\n]+\s*version\s*=\s*"([^"]+)"',
            text,
        ):
            pkgs.append(("crates.io", m.group(1), m.group(2)))
    # Cap to 200 packages so we don't overwhelm OSV.dev
    return pkgs[:200]


def _severity_of(vulns: list[dict[str, Any]]) -> str:
    """Pick the highest severity across an advisory list."""
    order = {"informational": 0, "low": 1, "medium": 2, "moderate": 2,
             "high": 3, "critical": 4}
    best = "medium"
    best_n = 2
    for v in vulns:
        if not isinstance(v, dict):
            continue
        for s in (v.get("database_specific") or {}).get("severity", "").split(","):
            n = order.get(s.strip().lower(), -1)
            if n > best_n:
                best_n = n
                best = s.strip().lower() if n != 2 else "medium"
        for sev in v.get("severity") or []:
            if isinstance(sev, dict) and sev.get("type") == "CVSS_V3":
                score_str = str(sev.get("score") or "")
                m = re.search(r"CVSS.*/AV.*", score_str)
                # Coarse: presence of CVSS often means H or higher
                if m and best_n < 3:
                    best, best_n = "high", 3
    return best
