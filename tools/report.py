"""Adapter — convert network_pipeline Findings to the existing Security_module
reporting format and hand off to the existing SARIF/JUnit/HTML/JSON emitters.

Keeps the dependency one-way: network_pipeline imports from
``Security_module.reporting``, not the reverse.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import Finding as NPFinding, FindingSeverity

log = get_logger("tools.report")


# Mapping from network_pipeline FindingSeverity (lowercase) to the
# Security_module.models.enums.Severity (UPPERCASE + "INFO").
_SEV_MAP = {
    FindingSeverity.CRITICAL: "CRITICAL",
    FindingSeverity.HIGH: "HIGH",
    FindingSeverity.MEDIUM: "MEDIUM",
    FindingSeverity.LOW: "LOW",
    FindingSeverity.INFORMATIONAL: "INFO",
}


def _import_security_module_reporting():
    """Import the Security_module reporting package.

    Assumes network_pipeline is run from inside the Security_module
    install. If not available we fall back to JSON-only reporting.
    """
    # network_pipeline lives at Security_module/network_pipeline/...
    sm_root = Path(__file__).resolve().parents[2]
    if str(sm_root) not in sys.path:
        sys.path.insert(0, str(sm_root))
    try:
        import reporting  # type: ignore[import-not-found]
        return reporting
    except ImportError:
        return None


def to_security_module_finding(np_finding: NPFinding) -> dict:
    """Shape a network_pipeline finding into a dict the Security_module
    reporters can consume.

    We emit a dict rather than importing Security_module's Finding
    pydantic class so this module stays decoupled even when the two
    schemas drift.
    """
    return {
        "id": np_finding.id,
        "title": np_finding.title,
        "severity": _SEV_MAP.get(np_finding.severity, "INFO"),
        "status": "FAILED",  # A finding means the defence failed
        "description": np_finding.description,
        "cwe": np_finding.cwe,
        "category": "NETWORK",
        "affected_target": np_finding.affected_target,
        "affected_component": np_finding.affected_component,
        "steps_to_reproduce": np_finding.steps_to_reproduce,
        "impact": np_finding.impact,
        "remediation": np_finding.remediation,
        "evidence": [e.model_dump() for e in np_finding.evidence],
        "agent": np_finding.agent,
        "objective_id": np_finding.objective_id,
        "discovered_at": np_finding.discovered_at,
    }


def collect_audit_payload(workspace: Path) -> dict:
    """Phase-4: surface evidence-chain root + purple-team score in reports.

    Returns ``{}`` when neither is configured. Plugged into the
    JSON / SARIF report writers below.
    """
    out: dict = {}
    root_path = workspace / "evidence_root.json"
    if root_path.exists():
        try:
            out["evidence_root"] = json.loads(
                root_path.read_text(encoding="utf-8"),
            )
        except (json.JSONDecodeError, OSError):
            pass
    purple_path = workspace / "purple_score.json"
    if purple_path.exists():
        try:
            out["purple_score"] = json.loads(
                purple_path.read_text(encoding="utf-8"),
            )
        except (json.JSONDecodeError, OSError):
            pass
    return out


def write_json_report(
    findings: list[NPFinding],
    out_path: Path,
    *,
    workspace: Path | None = None,
) -> Path:
    """Rich JSON report (schema v2).

    Structure:
        engagement          - identity + duration + counters
        executive_summary   - one-paragraph narrative
        summary             - histograms by severity / confidence / phase / scanner
        top_priority        - top 5 most actionable findings
        coverage            - which scanners ran, what was tested
        next_steps          - operator-actionable remediation queue
        findings            - full sorted list (highest priority first)
        audit               - optional evidence-chain + purple-score
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # --- Sort findings: severity desc, confidence desc, EPSS desc -----
    findings_sorted = sorted(findings, key=_priority_key, reverse=True)

    # --- Build histograms -------------------------------------------
    sev_hist = _histogram(findings_sorted)
    conf_hist = _confidence_histogram(findings_sorted)
    phase_hist = _phase_histogram(findings_sorted)
    scanner_hist = _scanner_histogram(findings_sorted)

    # --- Engagement metadata + counters -----------------------------
    engagement_meta = (
        _read_engagement_meta(workspace) if workspace is not None else {}
    )
    coverage = _build_coverage(workspace, findings_sorted, scanner_hist)

    # --- Top-5 priority + executive summary -------------------------
    top_priority = _build_top_priority(findings_sorted, k=5)
    exec_summary = _build_executive_summary(
        engagement_meta, sev_hist, conf_hist, phase_hist, top_priority,
    )
    next_steps = _build_next_steps(findings_sorted, top_priority)

    payload = {
        "schema_version": "v2",
        "engagement": engagement_meta,
        "executive_summary": exec_summary,
        "summary": {
            "total": len(findings_sorted),
            "by_severity": sev_hist,
            "by_confidence": conf_hist,
            "by_phase": phase_hist,
            "by_scanner": scanner_hist,
        },
        "top_priority": top_priority,
        "coverage": coverage,
        "next_steps": next_steps,
        "findings": [to_security_module_finding(f) for f in findings_sorted],
    }

    if workspace is not None:
        audit = collect_audit_payload(workspace)
        if audit:
            payload["audit"] = audit

    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out_path


# ── Sorting / histograms / metadata helpers ─────────────────────────

_SEV_RANK = {
    FindingSeverity.CRITICAL: 4,
    FindingSeverity.HIGH: 3,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 1,
    FindingSeverity.INFORMATIONAL: 0,
}

_CONF_RANK = {
    "verified": 3,
    "probable": 2,
    "tentative": 1,
    "unverified": 0,
}


def _priority_key(f: NPFinding) -> tuple[int, int, float]:
    """Higher tuple = higher priority. Order: severity, confidence, EPSS."""
    sev = _SEV_RANK.get(f.severity, 0)
    conf = _CONF_RANK.get(
        getattr(getattr(f, "confidence", None), "value", "") or "", 0,
    )
    epss = 0.0
    extra = getattr(f, "extra", {}) or {}
    if isinstance(extra, dict):
        try:
            epss = float(extra.get("epss_max_percentile") or 0.0)
        except (TypeError, ValueError):
            pass
    return (sev, conf, epss)


def _confidence_histogram(findings: list[NPFinding]) -> dict[str, int]:
    h: dict[str, int] = {}
    for f in findings:
        c = getattr(getattr(f, "confidence", None), "value", "") or "unknown"
        h[c] = h.get(c, 0) + 1
    return h


def _phase_histogram(findings: list[NPFinding]) -> dict[str, int]:
    h: dict[str, int] = {}
    for f in findings:
        ph = getattr(getattr(f, "phase", None), "value", "") or "unknown"
        h[ph] = h.get(ph, 0) + 1
    return h


def _scanner_histogram(findings: list[NPFinding]) -> dict[str, int]:
    h: dict[str, int] = {}
    for f in findings:
        # The scanner name is conventionally the 'agent' field on Finding.
        agent = getattr(f, "agent", "") or "unknown"
        h[agent] = h.get(agent, 0) + 1
    return h


def _read_engagement_meta(workspace: Path) -> dict:
    """Pull engagement-level identity + counters from disk artefacts."""
    meta: dict = {}
    meta_path = workspace / "engagement.meta.json"
    if meta_path.exists():
        try:
            raw = json.loads(meta_path.read_text(encoding="utf-8"))
            meta["id"] = raw.get("engagement_id", "")
            meta["name"] = raw.get("engagement_name", "")
            meta["target"] = raw.get("target", "")
            meta["started_at"] = raw.get("started_at", "")
            meta["ended_at"] = raw.get("ended_at", "")
            try:
                from datetime import datetime
                if meta["started_at"] and meta["ended_at"]:
                    t0 = datetime.fromisoformat(meta["started_at"])
                    t1 = datetime.fromisoformat(meta["ended_at"])
                    meta["duration_seconds"] = round((t1 - t0).total_seconds(), 1)
            except (ValueError, TypeError):
                pass
            stages = raw.get("stages", {}) or {}
            run_stage = stages.get("run", {}) or {}
            summary = run_stage.get("summary") or raw.get("summary") or {}
            if summary:
                meta["iterations_completed"] = summary.get("completed", 0)
                meta["iterations_blocked"] = summary.get("blocked", 0)
                meta["max_iterations"] = summary.get("max_iterations", 0)
            report_stage = stages.get("report", {}) or {}
            if "duplicates_merged" in report_stage:
                meta["duplicates_merged"] = report_stage["duplicates_merged"]
        except (OSError, ValueError):
            pass

    # Evidence file count
    ev_dir = workspace / "evidence"
    if ev_dir.is_dir():
        try:
            meta["evidence_files"] = sum(
                1 for p in ev_dir.rglob("*") if p.is_file()
            )
        except OSError:
            pass

    return meta


def _build_coverage(
    workspace: Path | None,
    findings: list[NPFinding],
    scanner_hist: dict[str, int],
) -> dict:
    """Surface which scanners ran and what they tested."""
    cov: dict = {
        "scanners_with_findings": sorted(scanner_hist.keys()),
        "endpoints_tested": 0,
        "evidence_captured": 0,
    }
    if workspace is None:
        return cov
    # Endpoints derived from KG host/endpoint nodes
    kg_path = workspace / "kg.json"
    if kg_path.exists():
        try:
            kg = json.loads(kg_path.read_text(encoding="utf-8"))
            nodes = kg.get("nodes", []) or []
            cov["endpoints_tested"] = sum(
                1 for n in nodes if n.get("type") == "endpoint"
            )
            cov["hosts_discovered"] = sum(
                1 for n in nodes if n.get("type") == "host"
            )
            cov["services_discovered"] = sum(
                1 for n in nodes if n.get("type") == "service"
            )
        except (OSError, ValueError):
            pass
    # Evidence files = HTTP exchanges captured
    ev_dir = workspace / "evidence"
    if ev_dir.is_dir():
        try:
            cov["evidence_captured"] = sum(
                1 for p in ev_dir.rglob("*.req") if p.is_file()
            )
        except OSError:
            pass
    return cov


def _build_top_priority(findings: list[NPFinding], *, k: int = 5) -> list[dict]:
    """Top-k findings with a one-line rationale for each."""
    out: list[dict] = []
    for f in findings[:k]:
        sev = _SEV_MAP.get(f.severity, "INFO")
        conf = getattr(getattr(f, "confidence", None), "value", "") or "?"
        extra = getattr(f, "extra", {}) or {}
        epss_pct = 0.0
        if isinstance(extra, dict):
            try:
                epss_pct = float(extra.get("epss_max_percentile") or 0.0)
            except (TypeError, ValueError):
                pass
        rationale_parts = [f"{sev} severity", f"confidence={conf}"]
        if epss_pct > 0.5:
            rationale_parts.append(
                f"EPSS {epss_pct * 100:.0f}th percentile (exploit-in-the-wild signal)"
            )
        out.append({
            "id": f.id,
            "title": f.title,
            "severity": sev,
            "confidence": conf,
            "affected_target": f.affected_target,
            "cwe": list(f.cwe or []),
            "epss_max_percentile": round(epss_pct, 3) if epss_pct else None,
            "rationale": " · ".join(rationale_parts),
        })
    return out


def _build_executive_summary(
    eng: dict,
    sev_hist: dict[str, int],
    conf_hist: dict[str, int],
    phase_hist: dict[str, int],
    top: list[dict],
) -> str:
    """Single-paragraph plain-English summary."""
    target = eng.get("target", "the target")
    duration = eng.get("duration_seconds")
    iters = eng.get("iterations_completed", 0)
    crit = sev_hist.get("CRITICAL", 0)
    high = sev_hist.get("HIGH", 0)
    med = sev_hist.get("MEDIUM", 0)
    low = sev_hist.get("LOW", 0)
    info = sev_hist.get("INFO", 0)
    verified = conf_hist.get("verified", 0)
    total = sum(sev_hist.values())
    severity_phrase = (
        f"{crit} critical, {high} high, {med} medium, {low} low, {info} informational"
    )
    duration_phrase = (
        f" in {duration:.0f}s across {iters} iterations" if duration else ""
    )
    top_phrase = ""
    if top:
        leading = top[0]
        top_phrase = (
            f" The most pressing issue is {leading['id']}: "
            f"{leading['title']} (severity={leading['severity']}, "
            f"confidence={leading['confidence']})."
        )
    return (
        f"Engagement against {target} produced {total} findings ({severity_phrase}); "
        f"{verified} were independently verified by replay"
        f"{duration_phrase}.{top_phrase}"
    )


def _build_next_steps(
    findings: list[NPFinding], top_priority: list[dict],
) -> list[str]:
    """Operator-actionable next steps."""
    steps: list[str] = []
    for entry in top_priority:
        sev = entry.get("severity", "INFO")
        if sev in ("CRITICAL", "HIGH"):
            steps.append(
                f"[{sev}] Patch {entry['id']} ({entry['title']}) on "
                f"{entry['affected_target']} immediately."
            )
        elif sev == "MEDIUM":
            steps.append(
                f"[{sev}] Triage {entry['id']} this sprint: {entry['title']}."
            )
    if not steps and findings:
        steps.append("No critical/high findings — review medium/low items in the report.")
    if not findings:
        steps.append(
            "Zero findings produced. Re-check engagement scope, confirm "
            "targets resolved, and verify scanners ran (see "
            "engagement.meta.json stages)."
        )
    return steps


def _histogram(findings: list[NPFinding]) -> dict[str, int]:
    h: dict[str, int] = {}
    for f in findings:
        k = _SEV_MAP.get(f.severity, "INFO")
        h[k] = h.get(k, 0) + 1
    return h


def write_sarif_report(
    findings: list[NPFinding],
    out_path: Path,
    *,
    workspace: Path | None = None,
) -> Path:
    """Minimal SARIF 2.1.0 writer (no Security_module reporting dep).

    If Security_module.reporting.sarif_reporter is importable, prefer it
    so the network and ASI reports share shape.
    """
    reporting = _import_security_module_reporting()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if reporting is not None and hasattr(reporting, "sarif_reporter"):
        try:
            # Best-effort call into the existing reporter. The exact
            # signature may differ; we fall through to local SARIF on
            # any mismatch rather than hard-erroring.
            sarif_fn = getattr(reporting.sarif_reporter, "write_sarif", None)
            if callable(sarif_fn):
                sarif_fn(
                    [to_security_module_finding(f) for f in findings],
                    out_path,
                )
                return out_path
        except Exception as e:
            log.warning("existing sarif_reporter failed, falling back: %r", e)

    # Local minimal SARIF
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "network_pipeline",
                        "informationUri": "https://github.com/your-org/Security_module",
                        "rules": [],
                    }
                },
                "results": [
                    {
                        "ruleId": "NET-" + (f.cwe[0] if f.cwe else "GENERIC"),
                        "level": _sarif_level(f.severity),
                        "message": {"text": f.title + "\n\n" + f.description},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.affected_target},
                                }
                            }
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }
    # Phase-4: attach evidence root + purple score under the run's
    # ``properties`` field — SARIF 2.1.0 allows arbitrary properties.
    if workspace is not None:
        audit = collect_audit_payload(workspace)
        if audit:
            sarif["runs"][0]["properties"] = {"network_pipeline_audit": audit}

    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return out_path


def _sarif_level(sev: FindingSeverity) -> str:
    return {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
        FindingSeverity.INFORMATIONAL: "note",
    }.get(sev, "note")


# ── EPSS enrichment (Phase J — 2026 prioritisation) ─────────────────
#
# EPSS = Exploit Prediction Scoring System (FIRST.org). 0-1 score for
# the probability a CVE is exploited in the wild within 30 days. CVSS
# alone is not enough in 2026 — operators want ``epss_percentile`` to
# triage what to fix THIS WEEK.

_EPSS_API = "https://api.first.org/data/v1/epss"
_EPSS_TIMEOUT_S = 10.0
_CVE_RE = __import__("re").compile(r"\bCVE-\d{4}-\d{4,7}\b")


def _extract_cves(finding) -> list[str]:
    """Pull CVE-IDs from a finding's title/description/cwe/extra fields."""
    haystack_parts: list[str] = []
    for attr in ("title", "description", "remediation"):
        v = getattr(finding, attr, "") or ""
        if isinstance(v, str):
            haystack_parts.append(v)
    for v in (getattr(finding, "cwe", []) or []):
        if isinstance(v, str):
            haystack_parts.append(v)
    extra = getattr(finding, "extra", None)
    if isinstance(extra, dict):
        for v in extra.values():
            if isinstance(v, (str, int, float)):
                haystack_parts.append(str(v))
            elif isinstance(v, list):
                haystack_parts.extend(str(x) for x in v if isinstance(x, str))
    found = set()
    for s in haystack_parts:
        for m in _CVE_RE.findall(s):
            found.add(m.upper())
    return sorted(found)


def enrich_with_epss(findings: list, *, workspace: Path | None = None) -> dict:
    """Look up EPSS scores for every CVE referenced by any finding.

    Mutates each finding's ``extra`` dict in-place with::

        extra["epss"] = {
            "CVE-2021-44228": {"score": 0.97, "percentile": 0.999},
            ...
        }

    Returns the aggregated mapping for inclusion in the report.
    Network-disabled / DNS-failed lookups silently no-op.
    """
    cves: set[str] = set()
    finding_cves: list[tuple[Any, list[str]]] = []
    for f in findings:
        c = _extract_cves(f)
        finding_cves.append((f, c))
        cves.update(c)

    if not cves:
        return {}

    # Cache file
    cache_path = None
    if workspace is not None:
        cache_dir = workspace / "cache" / "epss"
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_path = cache_dir / "scores.json"
        except OSError:
            cache_path = None

    cache: dict[str, dict[str, float]] = {}
    if cache_path is not None and cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            cache = {}

    uncached = [c for c in cves if c not in cache]
    if uncached:
        try:
            import urllib.parse as _u
            import urllib.request as _r

            # FIRST.org accepts comma-separated CVE list, max ~80 per call
            for batch_start in range(0, len(uncached), 80):
                batch = uncached[batch_start:batch_start + 80]
                qs = _u.urlencode({"cve": ",".join(batch)})
                url = f"{_EPSS_API}?{qs}"
                try:
                    with _r.urlopen(url, timeout=_EPSS_TIMEOUT_S) as resp:  # noqa: S310
                        if resp.status != 200:
                            continue
                        data = json.loads(resp.read().decode("utf-8"))
                except Exception as e:
                    log.debug("epss lookup failed for batch: %r", e)
                    continue
                for item in (data.get("data") or []):
                    cve = (item.get("cve") or "").upper()
                    if not cve:
                        continue
                    try:
                        cache[cve] = {
                            "score": float(item.get("epss") or 0.0),
                            "percentile": float(item.get("percentile") or 0.0),
                        }
                    except (TypeError, ValueError):
                        pass
        except Exception as e:  # noqa: BLE001
            log.warning("epss enrichment skipped (network or parse error): %r", e)

    # Persist cache
    if cache_path is not None:
        try:
            cache_path.write_text(json.dumps(cache), encoding="utf-8")
        except OSError:
            pass

    # Annotate findings in place
    for f, cs in finding_cves:
        if not cs:
            continue
        scores = {c: cache[c] for c in cs if c in cache}
        if not scores:
            continue
        try:
            extra = getattr(f, "extra", None)
            if not isinstance(extra, dict):
                # Attempt to set a new dict (works on pydantic v2 with
                # Config(extra='allow') or plain dataclasses)
                try:
                    f.extra = {}
                    extra = f.extra
                except Exception:
                    continue
            extra["epss"] = scores
            # Also surface the max for quick filtering
            top = max(scores.values(), key=lambda v: v.get("percentile", 0))
            extra["epss_max_percentile"] = top.get("percentile", 0)
        except Exception:  # noqa: BLE001
            continue

    return cache


# ── CycloneDX-VEX 1.5 output (Phase J) ──────────────────────────────
#
# CycloneDX-VEX is the 2026 default ingestion format for AppSec
# aggregators (DefectDojo, ASOC platforms). It's a CycloneDX BOM
# extended with vulnerability + analysis fields per finding.

def _cdx_severity(sev: FindingSeverity) -> str:
    return {
        FindingSeverity.CRITICAL: "critical",
        FindingSeverity.HIGH: "high",
        FindingSeverity.MEDIUM: "medium",
        FindingSeverity.LOW: "low",
        FindingSeverity.INFORMATIONAL: "info",
    }.get(sev, "info")


def write_cyclonedx_vex(
    findings: list[NPFinding],
    out_path: Path,
    *,
    workspace: Path | None = None,
    component_name: str = "engagement-target",
    component_version: str = "1.0.0",
) -> Path:
    """Write a CycloneDX-VEX 1.5 JSON document.

    Spec: https://cyclonedx.org/docs/1.5/json/#vulnerabilities
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    import uuid as _uuid
    from datetime import datetime, timezone

    doc_id = f"urn:uuid:{_uuid.uuid4()}"
    target_ref = f"pkg:generic/{component_name}@{component_version}"

    vulns = []
    for f in findings:
        cves = _extract_cves(f)
        epss = ((getattr(f, "extra", {}) or {}).get("epss") or {}) if hasattr(f, "extra") else {}
        v = {
            "id": f.id,
            "source": {"name": "network_pipeline"},
            "ratings": [
                {
                    "source": {"name": "network_pipeline"},
                    "severity": _cdx_severity(f.severity),
                    "method": "other",
                }
            ],
            "cwes": [
                int(cwe.replace("CWE-", "")) for cwe in (f.cwe or [])
                if isinstance(cwe, str) and cwe.startswith("CWE-")
                and cwe.replace("CWE-", "").isdigit()
            ],
            "description": f.title,
            "detail": f.description,
            "recommendation": f.remediation,
            "affects": [{"ref": target_ref}],
        }
        if cves:
            # Each CVE gets its own ratings entry with EPSS score if known
            for cve in cves:
                rating = {
                    "source": {"name": "FIRST.org"},
                    "severity": _cdx_severity(f.severity),
                    "method": "other",
                    "vector": cve,
                }
                if cve in epss:
                    rating["score"] = epss[cve].get("score")
                v["ratings"].append(rating)
            v["references"] = [
                {"id": cve, "source": {"name": "NVD",
                 "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}}
                for cve in cves
            ]
        # Analysis (VEX core)
        v["analysis"] = {
            "state": (
                "exploitable"
                if f.confidence and getattr(f.confidence, "value", "") == "verified"
                else "in_triage"
            ),
            "justification": f"confidence={getattr(f.confidence, 'value', f.confidence)}",
        }
        vulns.append(v)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": doc_id,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"name": "network_pipeline", "version": "phase-j"}],
            "component": {
                "type": "application",
                "bom-ref": target_ref,
                "name": component_name,
                "version": component_version,
            },
        },
        "vulnerabilities": vulns,
    }

    if workspace is not None:
        audit = collect_audit_payload(workspace)
        if audit:
            bom["properties"] = [
                {"name": k, "value": json.dumps(v)} for k, v in audit.items()
            ]

    out_path.write_text(json.dumps(bom, indent=2), encoding="utf-8")
    return out_path


# ── Phase-8: HackerOne Markdown reporter ──────────────────────────────


_HACKERONE_SEVERITY = {
    FindingSeverity.CRITICAL: "Critical (9.0–10.0)",
    FindingSeverity.HIGH: "High (7.0–8.9)",
    FindingSeverity.MEDIUM: "Medium (4.0–6.9)",
    FindingSeverity.LOW: "Low (0.1–3.9)",
    FindingSeverity.INFORMATIONAL: "None / Informational",
}


def _slug(text: str, *, max_len: int = 48) -> str:
    """Filesystem-safe slug — letters/digits/dash only, lowercased."""
    import re as _re
    s = _re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    if not s:
        s = "untitled"
    return s[:max_len]


def _hackerone_body(f: NPFinding) -> str:
    """Render one finding as HackerOne-style Markdown."""
    sev_label = _HACKERONE_SEVERITY.get(f.severity, "Informational")
    cwe = ", ".join(f.cwe or []) or "n/a"
    mitre = ", ".join(f.mitre or []) or "n/a"
    steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(f.steps_to_reproduce or [])) \
        or "_The finding was discovered by automated scanning; reproduction steps were not authored._"
    evidence = "\n".join(f"- `{e.path}` — {e.description}" for e in (f.evidence or [])) \
        or "_No artefacts attached._"
    impact = f.impact or "_Not specified._"
    remediation = f.remediation or "_Not specified._"
    conf = getattr(getattr(f, "confidence", None), "value", "") or "unknown"
    return (
        f"# {f.title}\n\n"
        f"**Finding ID:** `{f.id}`  \n"
        f"**Severity:** {sev_label}  \n"
        f"**Confidence:** {conf}  \n"
        f"**CWE:** {cwe}  \n"
        f"**MITRE ATT&CK:** {mitre}  \n"
        f"**Affected target:** `{f.affected_target}`  \n"
        f"**Affected component:** `{f.affected_component}`  \n\n"
        f"## Summary\n\n{f.description}\n\n"
        f"## Steps to Reproduce\n\n{steps}\n\n"
        f"## Impact\n\n{impact}\n\n"
        f"## Suggested Fix\n\n{remediation}\n\n"
        f"## Evidence\n\n{evidence}\n"
    )


def write_hackerone_md(
    findings: list[NPFinding],
    out_dir: Path,
    *,
    workspace: Path | None = None,
    severity_floor: FindingSeverity = FindingSeverity.HIGH,
) -> Path:
    """Write one Markdown file per finding ≥ ``severity_floor``.

    Returns the output directory. Always emits ``index.md`` linking
    every per-finding file in priority order. When no qualifying
    findings exist, ``index.md`` says so explicitly so the operator
    knows the run is intentional.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    threshold = _SEV_RANK.get(severity_floor, 3)
    qualifying = [
        f for f in sorted(findings, key=_priority_key, reverse=True)
        if _SEV_RANK.get(f.severity, 0) >= threshold
    ]

    written: list[tuple[str, Path]] = []
    for f in qualifying:
        fname = f"{f.id}-{_slug(f.title)}.md"
        target = out_dir / fname
        target.write_text(_hackerone_body(f), encoding="utf-8")
        written.append((f.title, target))

    lines = ["# HackerOne-style report\n"]
    if not written:
        lines.append(
            f"_No findings at or above `{severity_floor.value}` severity._\n"
            f"\nTotal findings in engagement: **{len(findings)}**.\n"
        )
    else:
        lines.append(f"{len(written)} finding(s) at or above "
                     f"`{severity_floor.value}` severity:\n")
        for title, path in written:
            lines.append(f"- [{title}]({path.name})")
    (out_dir / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_dir


# ── Phase-8: Bugcrowd CSV reporter ────────────────────────────────────


# Bugcrowd VRT (Vulnerability Rating Taxonomy) bucket — best-effort
# mapping from CWE / scanner output. Operators can override per-row by
# editing the resulting CSV before uploading.
_VRT_BY_CWE = {
    "CWE-77": "command_injection.generic",
    "CWE-78": "command_injection.os_command",
    "CWE-79": "cross_site_scripting.reflected",
    "CWE-89": "sql_injection.generic",
    "CWE-94": "code_injection.generic",
    "CWE-200": "sensitive_data_exposure",
    "CWE-269": "broken_access_control.privilege_escalation",
    "CWE-287": "broken_authentication_and_session_management",
    "CWE-352": "cross_site_request_forgery_csrf",
    "CWE-434": "insecure_file_upload",
    "CWE-502": "insecure_deserialization",
    "CWE-611": "xml_external_entities_xxe",
    "CWE-639": "insecure_direct_object_reference_idor",
    "CWE-918": "server_side_request_forgery_ssrf",
    "CWE-1357": "ai_application_issue",
    "CWE-1426": "ai_application_issue",
}


def _vrt_for(f: NPFinding) -> str:
    for c in f.cwe or []:
        if c in _VRT_BY_CWE:
            return _VRT_BY_CWE[c]
    return "other"


_BUGCROWD_SEVERITY = {
    FindingSeverity.CRITICAL: "P1",
    FindingSeverity.HIGH: "P2",
    FindingSeverity.MEDIUM: "P3",
    FindingSeverity.LOW: "P4",
    FindingSeverity.INFORMATIONAL: "P5",
}


def write_bugcrowd_csv(
    findings: list[NPFinding],
    out_path: Path,
    *,
    workspace: Path | None = None,
) -> Path:
    """Write a Bugcrowd-style CSV (VRT bucket + P1–P5 priority).

    Columns: id, title, vrt, priority, affected_url, affected_component,
    description, steps, impact, recommendation, evidence_paths.
    Empty findings → header-only CSV (still a valid file).
    """
    import csv

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow([
            "id", "title", "vrt", "priority",
            "affected_url", "affected_component",
            "description", "steps", "impact",
            "recommendation", "evidence_paths",
        ])
        for f in sorted(findings, key=_priority_key, reverse=True):
            writer.writerow([
                f.id,
                f.title,
                _vrt_for(f),
                _BUGCROWD_SEVERITY.get(f.severity, "P5"),
                f.affected_target,
                f.affected_component,
                f.description,
                " | ".join(f.steps_to_reproduce or []),
                f.impact,
                f.remediation,
                " | ".join(e.path for e in (f.evidence or [])),
            ])
    return out_path


# ── Phase-7: Mermaid attack-chain graph ───────────────────────────────


def _mermaid_safe_id(raw: str, *, prefix: str = "n") -> str:
    """Mermaid node ids must be alphanumeric (or underscore). Slugify."""
    import re as _re
    s = _re.sub(r"[^A-Za-z0-9_]", "_", raw or "")[:60]
    if not s or not s[0].isalpha():
        s = f"{prefix}_{s}"
    return s or f"{prefix}_unknown"


def _mermaid_safe_label(raw: str, *, cap: int = 56) -> str:
    """Escape characters that break Mermaid node-label parsing."""
    s = (raw or "").replace('"', "'").replace("\n", " ").strip()
    if len(s) > cap:
        s = s[: cap - 1] + "…"
    return s


def write_mermaid_attack_chain(
    workspace: Path,
    out_path: Path,
) -> Path:
    """Emit a Mermaid ``flowchart LR`` of the attack graph.

    Reads the JSON KG directly (no NetworkX dependency required).
    Renders:

      * ``finding:*`` nodes as rounded boxes coloured by severity if
        the corresponding finding is present in ``findings.jsonl``.
      * ``defense:*`` nodes as hexagons.
      * MITIGATES edges as solid arrows ``-->``.
      * VERIFIED edges (verified=True) as bold arrows ``==>``.
      * VERIFIED edges (verified=False) as dotted arrows ``-.->``.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    kg_path = workspace / "kg.json"
    if not kg_path.exists():
        out_path.write_text("flowchart LR\n  empty[\"(no kg.json yet)\"]\n",
                            encoding="utf-8")
        return out_path

    try:
        data = json.loads(kg_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        out_path.write_text("flowchart LR\n  err[\"(kg.json unreadable)\"]\n",
                            encoding="utf-8")
        return out_path

    # Hydrate severity per finding id for nicer styling.
    severity_by_fid: dict[str, str] = {}
    findings_path = workspace / "findings.jsonl"
    if findings_path.exists():
        try:
            for line in findings_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                if "\t__sig__=" in line:
                    line = line.split("\t__sig__=", 1)[0]
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                fid = obj.get("id")
                sev = (obj.get("severity") or "").lower()
                if fid and sev:
                    severity_by_fid[fid] = sev
        except OSError:
            pass

    nodes = data.get("nodes", []) or []
    edges = data.get("edges", []) or []

    # We render only the attack-graph slice: defense_action + finding
    # nodes + any *vulnerability* nodes touched by MITIGATES/VERIFIED
    # edges. Host/port/service noise would overwhelm the visual.
    keep_types = {"defense_action", "finding", "vulnerability"}
    kept_ids: set[str] = {
        n["id"] for n in nodes if n.get("type") in keep_types
    }
    # Pull in any edge endpoints we'd otherwise drop.
    relevant_edges = []
    for e in edges:
        if e.get("relation") in ("mitigates", "responds_to", "verified"):
            relevant_edges.append(e)
            kept_ids.add(e["src"])
            kept_ids.add(e["dst"])

    # Build a NodeType lookup for unseen ids.
    type_by_id = {n["id"]: n.get("type", "") for n in nodes}

    lines: list[str] = ["flowchart LR"]
    classes: dict[str, str] = {}

    for nid in sorted(kept_ids):
        ntype = type_by_id.get(nid, "")
        slug = _mermaid_safe_id(nid)
        if ntype == "defense_action":
            # Pull title from properties for nicer label.
            title = ""
            for n in nodes:
                if n["id"] == nid:
                    title = (n.get("properties") or {}).get("title", "") or nid
                    break
            label = _mermaid_safe_label(f"DEF {title}")
            lines.append(f'  {slug}{{{{"{label}"}}}}')   # hexagon
            classes[slug] = "defense"
        elif ntype == "finding" or nid.startswith("finding:"):
            fid = nid.split(":", 1)[-1]
            sev = severity_by_fid.get(fid, "")
            label = _mermaid_safe_label(f"FIND {fid} [{sev}]" if sev else f"FIND {fid}")
            lines.append(f'  {slug}(["{label}"])')          # rounded
            classes[slug] = f"sev_{sev or 'unknown'}"
        elif ntype == "vulnerability":
            label = _mermaid_safe_label(f"VULN {nid}")
            lines.append(f'  {slug}[/"{label}"/]')          # parallelogram
            classes[slug] = "vuln"
        else:
            lines.append(f'  {slug}["{_mermaid_safe_label(nid)}"]')

    seen_edges: set[tuple[str, str, str]] = set()
    for e in relevant_edges:
        rel = e.get("relation", "")
        src = _mermaid_safe_id(e["src"])
        dst = _mermaid_safe_id(e["dst"])
        key = (src, dst, rel)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        props = e.get("properties") or {}
        if rel == "verified":
            arrow = "==>" if props.get("verified") else "-.->|unverified|"
            lines.append(f"  {src} {arrow}|verified| {dst}")
        elif rel == "mitigates":
            lines.append(f"  {src} -->|mitigates| {dst}")
        elif rel == "responds_to":
            # Less interesting than mitigates; render dashed.
            lines.append(f"  {src} -.->|responds_to| {dst}")

    # classDef styling
    style_block = [
        "  classDef defense fill:#dff,stroke:#08a,stroke-width:2px;",
        "  classDef vuln fill:#fef,stroke:#a08,stroke-width:1px;",
        "  classDef sev_critical fill:#fdd,stroke:#a00,stroke-width:2px;",
        "  classDef sev_high fill:#fee,stroke:#c33;",
        "  classDef sev_medium fill:#ffd,stroke:#a83;",
        "  classDef sev_low fill:#efe,stroke:#373;",
        "  classDef sev_informational fill:#eef,stroke:#778;",
        "  classDef sev_unknown fill:#eee,stroke:#777;",
    ]
    lines.extend(style_block)
    for slug, cls in classes.items():
        lines.append(f"  class {slug} {cls};")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path
