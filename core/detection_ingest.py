"""Blue-team detection-signal ingestion (Plan B.3.3).

When the operator runs the engagement next to a SOC pipeline, they can
mount Suricata ``eve.json`` and Zeek ``conn.log`` (or any compatible
JSONL telemetry) under ``workspace/blue_telemetry/``. This module
correlates each finding's ``discovered_at`` timestamp + affected
target with alert events nearby in the telemetry, and updates the
existing ``Finding.detected`` / ``Finding.detection_notes`` fields
(both already in the schema since Phase 1).

A purple-team score ``findings_detected / findings_total`` is computed
at the end and surfaced through the report writer (TIBER-EU "purple
efficacy" metric).

Correlation heuristics — kept conservative to avoid false-positive
"detected" markings:

* **5-tuple (host)**: alert ``src_ip`` / ``dest_ip`` / ``host`` field
  must match the finding's ``affected_target`` (canonicalised host).
* **Time window**: alert timestamp within ±5 minutes of
  ``discovered_at``.
* **Multiple alerts**: notes are joined with ``|`` so the analyst can
  see all matching rules.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from network_pipeline.core.logging import get_logger
from network_pipeline.core.rate_limit import host_of

log = get_logger("core.detection_ingest")


DEFAULT_WINDOW_S = 300  # ±5 minutes


# ── Telemetry record shapes ──────────────────────────────────────────


@dataclass
class TelemetryEvent:
    ts: datetime
    host: str  # canonicalised
    rule: str  # human-readable identifier
    severity: str = ""
    raw: dict = field(default_factory=dict)


# ── Parsers ──────────────────────────────────────────────────────────


def _parse_iso(ts: str) -> datetime | None:
    try:
        # Suricata uses ISO with offset; .fromisoformat handles it on 3.11+.
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def parse_suricata_eve(path: Path) -> Iterable[TelemetryEvent]:
    """Yield events from a Suricata ``eve.json`` file (alert events only)."""
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Only care about alert / dns / http events with a host.
            ev_type = rec.get("event_type", "")
            if ev_type not in ("alert", "dns", "http"):
                continue
            ts = _parse_iso(rec.get("timestamp", "") or "")
            if ts is None:
                continue
            # Pull host: HTTP hostname → DNS rrname → dest_ip → src_ip
            host = ""
            http = rec.get("http") or {}
            dns = rec.get("dns") or {}
            host = (
                http.get("hostname")
                or dns.get("rrname")
                or rec.get("dest_ip")
                or rec.get("src_ip")
                or ""
            )
            host = host_of(str(host))
            alert = rec.get("alert") or {}
            rule = alert.get("signature") or rec.get("event_type", "?")
            sev = str(alert.get("severity", ""))
            yield TelemetryEvent(ts=ts, host=host, rule=rule, severity=sev, raw=rec)


def parse_zeek_conn(path: Path) -> Iterable[TelemetryEvent]:
    """Yield events from a Zeek ``conn.log`` (TSV or JSON)."""
    if not path.exists():
        return
    # JSON variant first
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts_raw = rec.get("ts")
                ts: datetime | None = None
                if isinstance(ts_raw, (int, float)):
                    ts = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
                elif isinstance(ts_raw, str):
                    ts = _parse_iso(ts_raw)
                if ts is None:
                    continue
                host = host_of(rec.get("id.resp_h") or rec.get("id.orig_h") or "")
                yield TelemetryEvent(
                    ts=ts, host=host, rule="zeek/conn",
                    severity="", raw=rec,
                )
    except OSError as e:  # pragma: no cover - defensive
        log.warning("zeek conn read failed: %r", e)


def load_all_telemetry(blue_telemetry_dir: Path) -> list[TelemetryEvent]:
    """Best-effort scan of common telemetry filenames under ``dir``."""
    out: list[TelemetryEvent] = []
    if not blue_telemetry_dir.exists():
        return out
    eve = blue_telemetry_dir / "eve.json"
    if eve.exists():
        out.extend(parse_suricata_eve(eve))
    conn = blue_telemetry_dir / "conn.log"
    if conn.exists():
        out.extend(parse_zeek_conn(conn))
    # Allow arbitrary ``*.eve.json`` and ``*.conn.log`` for multi-host
    for p in blue_telemetry_dir.glob("*.eve.json"):
        out.extend(parse_suricata_eve(p))
    for p in blue_telemetry_dir.glob("*.conn.log"):
        out.extend(parse_zeek_conn(p))
    log.info("loaded %d telemetry events from %s", len(out), blue_telemetry_dir)
    return out


# ── Correlation ──────────────────────────────────────────────────────


@dataclass
class PurpleScore:
    findings_total: int = 0
    findings_detected: int = 0

    @property
    def ratio(self) -> float:
        return self.findings_detected / max(1, self.findings_total)


def correlate(
    *,
    findings: list,
    events: list[TelemetryEvent],
    window_seconds: int = DEFAULT_WINDOW_S,
) -> PurpleScore:
    """Mutate findings in place: set ``detected`` + ``detection_notes``.

    Returns a ``PurpleScore`` summarising the pass.
    """
    score = PurpleScore(findings_total=len(findings))
    if not findings or not events:
        return score
    win = timedelta(seconds=window_seconds)
    for f in findings:
        ts = _parse_iso(getattr(f, "discovered_at", "") or "")
        if ts is None:
            continue
        target_host = host_of(getattr(f, "affected_target", "") or "")
        if not target_host:
            continue
        matches: list[TelemetryEvent] = []
        for ev in events:
            if ev.host != target_host:
                continue
            if abs(ev.ts - ts) > win:
                continue
            matches.append(ev)
        if matches:
            f.detected = True
            note = " | ".join(
                f"{m.rule}@{m.ts.isoformat()}"
                + (f" sev={m.severity}" if m.severity else "")
                for m in matches[:5]
            )
            f.detection_notes = (
                (f.detection_notes + " | " if f.detection_notes else "")
                + note
            )
            score.findings_detected += 1
    log.info(
        "purple correlation: %d/%d findings detected (%.0f%%)",
        score.findings_detected, score.findings_total, score.ratio * 100,
    )
    return score


def correlate_workspace(
    *,
    workspace: Path,
    findings_log,
    blue_telemetry_dir: Path | None = None,
    window_seconds: int = DEFAULT_WINDOW_S,
) -> PurpleScore:
    """Convenience: load telemetry from ``workspace/blue_telemetry`` (or an
    explicit dir) and correlate against the findings log.

    The findings log is rewritten atomically so updated
    ``detected`` / ``detection_notes`` fields persist.
    """
    blue_dir = blue_telemetry_dir or (workspace / "blue_telemetry")
    events = load_all_telemetry(blue_dir)
    findings = findings_log.all()
    score = correlate(findings=findings, events=events, window_seconds=window_seconds)
    if score.findings_detected:
        # Bug-fix A: route through ``rewrite_all`` so HMAC signatures
        # are preserved (re-signed when a key is set). The previous
        # implementation silently wiped signatures and broke the
        # ``verify-evidence`` chain.
        findings_log.rewrite_all(findings)
    return score


__all__ = [
    "DEFAULT_WINDOW_S",
    "PurpleScore",
    "TelemetryEvent",
    "correlate",
    "correlate_workspace",
    "load_all_telemetry",
    "parse_suricata_eve",
    "parse_zeek_conn",
]
