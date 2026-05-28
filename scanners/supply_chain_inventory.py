"""Target-side supply-chain inventory scanner.

Inspired by Perplexity's Bumblebee (Apache-2.0). Bumblebee scans *the
operator's own machine* for compromised packages. We invert it: from
a recon'd web target, fetch any exposed dependency manifests
(``package.json``, ``package-lock.json``, ``requirements.txt``,
``Gemfile.lock``, ``go.mod``, ``composer.lock``, ``.python-version``,
``Pipfile.lock``) and match the resolved ``(ecosystem, name, version)``
tuples against the bundled threat-intel catalogs.

The catalogs are vendored verbatim from
``skills/threat_intel/*.json`` (Apache-2.0). See
``BUMBLEBEE_CATALOG_LICENSE.md`` for attribution.

Honours ``ScopeGuard`` — no out-of-scope fetches.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from network_pipeline.core.logging import get_logger
from network_pipeline.scanners._common import ScanFinding, ScanResult, truncate_for_agent

log = get_logger("scanners.supply_chain_inventory")


# ── threat-intel catalogs ─────────────────────────────────────────────


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    name: str
    ecosystem: str  # npm | pypi | go | rubygems | composer | ...
    package: str
    versions: tuple[str, ...]
    severity: str
    source: str = ""
    indicators: dict = field(default_factory=dict)


_DEFAULT_CATALOG_DIR = (
    Path(__file__).resolve().parent.parent / "skills" / "threat_intel"
)


@lru_cache(maxsize=4)
def load_catalogs(catalog_dir: Optional[str] = None) -> tuple[CatalogEntry, ...]:
    """Parse every ``*.json`` under the threat-intel directory."""
    path = Path(catalog_dir) if catalog_dir else _DEFAULT_CATALOG_DIR
    if not path.exists():
        log.warning("threat-intel dir missing: %s", path)
        return ()
    out: list[CatalogEntry] = []
    for fp in sorted(path.glob("*.json")):
        try:
            payload = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log.warning("skipping malformed catalog %s: %r", fp.name, e)
            continue
        for entry in payload.get("entries") or []:
            try:
                out.append(CatalogEntry(
                    id=str(entry["id"]),
                    name=str(entry.get("name", entry["id"])),
                    ecosystem=str(entry["ecosystem"]).lower(),
                    package=str(entry["package"]),
                    versions=tuple(str(v) for v in (entry.get("versions") or [])),
                    severity=str(entry.get("severity", "high")).lower(),
                    source=str(entry.get("source", "")),
                    indicators=dict(entry.get("indicators") or {}),
                ))
            except (KeyError, TypeError, ValueError) as e:
                log.warning("skipping malformed entry in %s: %r", fp.name, e)
    return tuple(out)


def _index_by_eco_pkg(catalog: tuple[CatalogEntry, ...]) -> dict[tuple[str, str], list[CatalogEntry]]:
    idx: dict[tuple[str, str], list[CatalogEntry]] = {}
    for e in catalog:
        idx.setdefault((e.ecosystem, e.package.lower()), []).append(e)
    return idx


# ── manifest parsers ──────────────────────────────────────────────────


@dataclass(frozen=True)
class ResolvedDep:
    ecosystem: str
    package: str
    version: str
    source_manifest: str  # e.g. "package-lock.json"


def parse_package_json(text: str, *, source: str = "package.json") -> list[ResolvedDep]:
    """Loose parse — pulls dependencies + devDependencies version pins."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[ResolvedDep] = []
    for key in ("dependencies", "devDependencies",
                "peerDependencies", "optionalDependencies"):
        for name, version in (data.get(key) or {}).items():
            if not isinstance(version, str):
                continue
            # Strip semver range tokens, keep base.
            clean = re.sub(r"^[\^~>=<]+", "", version.strip()).split(" ", 1)[0]
            out.append(ResolvedDep("npm", str(name), clean, source))
    return out


def parse_package_lock(text: str, *, source: str = "package-lock.json") -> list[ResolvedDep]:
    """v1/v2/v3 lockfile support — packages map preferred when present."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[ResolvedDep] = []
    # v2/v3 use "packages" with path keys
    for path_key, entry in (data.get("packages") or {}).items():
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not name and path_key.startswith("node_modules/"):
            name = path_key.split("node_modules/", 1)[1]
        version = entry.get("version")
        if name and version:
            out.append(ResolvedDep("npm", str(name), str(version), source))
    # v1 fallback
    for name, entry in (data.get("dependencies") or {}).items():
        if isinstance(entry, dict) and entry.get("version"):
            out.append(ResolvedDep("npm", str(name), str(entry["version"]), source))
    return out


def parse_requirements_txt(text: str, *, source: str = "requirements.txt") -> list[ResolvedDep]:
    out: list[ResolvedDep] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip env markers + extras.
        line = line.split(";", 1)[0].split("[", 1)[0].strip()
        # Match name==version exactly (the only form we can reliably pin).
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.+\-]+)\s*$", line)
        if m:
            out.append(ResolvedDep("pypi", m.group(1), m.group(2), source))
    return out


def parse_pipfile_lock(text: str, *, source: str = "Pipfile.lock") -> list[ResolvedDep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[ResolvedDep] = []
    for section in ("default", "develop"):
        for name, entry in (data.get(section) or {}).items():
            if isinstance(entry, dict) and entry.get("version"):
                version = str(entry["version"]).lstrip("=").strip()
                out.append(ResolvedDep("pypi", name, version, source))
    return out


def parse_gemfile_lock(text: str, *, source: str = "Gemfile.lock") -> list[ResolvedDep]:
    out: list[ResolvedDep] = []
    # Bundler "  package_name (version)" indented lines.
    for line in text.splitlines():
        m = re.match(r"^\s{4}([A-Za-z0-9_\-]+)\s+\(([A-Za-z0-9_.+\-]+)\)\s*$", line)
        if m:
            out.append(ResolvedDep("rubygems", m.group(1), m.group(2), source))
    return out


def parse_go_mod(text: str, *, source: str = "go.mod") -> list[ResolvedDep]:
    out: list[ResolvedDep] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        if in_block or stripped.startswith("require "):
            # "module v1.2.3" or "  module v1.2.3 // comment"
            payload = stripped[len("require "):].strip() if stripped.startswith("require ") else stripped
            payload = payload.split("//", 1)[0].strip()
            parts = payload.split()
            if len(parts) >= 2 and parts[1].startswith("v"):
                out.append(ResolvedDep("go", parts[0], parts[1], source))
    return out


def parse_composer_lock(text: str, *, source: str = "composer.lock") -> list[ResolvedDep]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[ResolvedDep] = []
    for section in ("packages", "packages-dev"):
        for entry in data.get(section) or []:
            name = entry.get("name")
            version = entry.get("version")
            if name and version:
                out.append(ResolvedDep("composer", str(name), str(version), source))
    return out


# Maps URL path → parser. The scanner tries each path against the
# target, parses successful 2xx responses, and ignores everything else.
_MANIFEST_PARSERS: tuple[tuple[str, Any, str], ...] = (
    ("/package.json", parse_package_json, "package.json"),
    ("/package-lock.json", parse_package_lock, "package-lock.json"),
    ("/requirements.txt", parse_requirements_txt, "requirements.txt"),
    ("/Pipfile.lock", parse_pipfile_lock, "Pipfile.lock"),
    ("/Gemfile.lock", parse_gemfile_lock, "Gemfile.lock"),
    ("/go.mod", parse_go_mod, "go.mod"),
    ("/composer.lock", parse_composer_lock, "composer.lock"),
)


# ── matching ──────────────────────────────────────────────────────────


def match_deps_against_catalogs(
    deps: list[ResolvedDep],
    *,
    catalogs: Optional[tuple[CatalogEntry, ...]] = None,
) -> list[tuple[ResolvedDep, CatalogEntry]]:
    """Return ``(dep, entry)`` pairs for every exact-version compromise hit."""
    if catalogs is None:
        catalogs = load_catalogs()
    idx = _index_by_eco_pkg(catalogs)
    hits: list[tuple[ResolvedDep, CatalogEntry]] = []
    for dep in deps:
        for entry in idx.get((dep.ecosystem, dep.package.lower()), []):
            # Exact-version match, with optional leading 'v' tolerated for Go.
            dep_v = dep.version.lstrip("v") if dep.ecosystem == "go" else dep.version
            ent_versions = {v.lstrip("v") if dep.ecosystem == "go" else v
                            for v in entry.versions}
            if dep_v in ent_versions:
                hits.append((dep, entry))
    return hits


# ── scanner ───────────────────────────────────────────────────────────


_CATALOG_VERSION = "bumblebee-port-2026-05-26"


class SupplyChainInventoryScanner:
    """Fetch exposed manifests from a target; match against threat-intel catalogs."""

    def __init__(self, http_client: Any) -> None:
        self._http = http_client

    async def run(self, target_url: str) -> ScanResult:
        from urllib.parse import urljoin

        result = ScanResult(scanner="supply_chain_inventory", target=target_url)
        if self._http is None:
            result.success = False
            result.error = "no HTTPClient configured"
            return result

        deps: list[ResolvedDep] = []
        fetched: list[str] = []
        for path, parser, label in _MANIFEST_PARSERS:
            endpoint = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = await self._http.request(
                    "GET", endpoint,
                    scanner_tool="supply_chain_inventory",
                    agent="recon", objective_id="",
                )
            except Exception as e:  # noqa: BLE001
                log.debug("manifest fetch failed %s: %r", endpoint, e)
                continue
            if resp is None or resp.status_code != 200 or not resp.text:
                continue
            fetched.append(label)
            try:
                deps.extend(parser(resp.text, source=label))
            except Exception as e:  # noqa: BLE001
                log.warning("manifest parse failed %s: %r", label, e)

        hits = match_deps_against_catalogs(deps)
        for dep, entry in hits:
            sev = entry.severity if entry.severity in (
                "critical", "high", "medium", "low", "informational",
            ) else "high"
            # Auto-supply two verified_methods for the schema gate (catalog + manifest).
            verified_methods = [f"catalog:{entry.id}", f"manifest:{dep.source_manifest}"]
            result.findings.append(ScanFinding(
                vuln_class="supply_chain.compromised_dependency",
                title=f"compromised {dep.ecosystem} dep: {dep.package}@{dep.version}",
                severity=sev,
                confidence="verified",
                affected_target=target_url,
                affected_param=dep.source_manifest,
                description=(
                    f"Exposed {dep.source_manifest} declares "
                    f"{dep.package}@{dep.version} ({dep.ecosystem}), which matches "
                    f"threat-intel catalog entry {entry.id}. Source: {entry.source}"
                ),
                cwe=["CWE-1357", "CWE-829"],
                mitre=["T1195.002"],
                remediation=(
                    f"Pin {dep.package} to a known-good version (NOT {dep.version}); "
                    f"rotate any credentials accessible to processes that loaded the "
                    f"compromised package; remove the manifest from public-web exposure."
                ),
                extra={
                    "attack_type": "supply_chain_inventory",
                    "ecosystem": dep.ecosystem,
                    "package": dep.package,
                    "version": dep.version,
                    "manifest": dep.source_manifest,
                    "catalog_id": entry.id,
                    "catalog_source": entry.source,
                    "indicators": entry.indicators,
                    "verified_methods": verified_methods,
                },
            ))

        result.data = {
            "manifests_fetched": fetched,
            "deps_resolved": len(deps),
            "compromised_hits": len(hits),
            "catalog_version": _CATALOG_VERSION,
        }
        result.raw_text = truncate_for_agent(
            f"manifests={fetched} deps={len(deps)} hits={len(hits)}",
            cap=512,
        )
        return result


__all__ = [
    "CatalogEntry",
    "ResolvedDep",
    "SupplyChainInventoryScanner",
    "load_catalogs",
    "match_deps_against_catalogs",
    "parse_composer_lock",
    "parse_gemfile_lock",
    "parse_go_mod",
    "parse_package_json",
    "parse_package_lock",
    "parse_pipfile_lock",
    "parse_requirements_txt",
]
