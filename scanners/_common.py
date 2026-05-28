"""Shared utilities for all scanner modules.

- ScanResult / ScanFinding — structured Pydantic results
- truncate_for_agent() — cap text for LLM context windows
- load_wordlist() — importlib.resources loader for bundled wordlists
- attach_evidence() — helper to add evidence paths to a ScanFinding
"""

from __future__ import annotations

import importlib.resources
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

# ── Result models ─────────────────────────────────────────────────────────────


class ScanFinding(BaseModel):
    """A single structured finding emitted by a scanner."""

    vuln_class: str
    title: str
    severity: str = "informational"
    affected_target: str = ""
    affected_param: str = ""
    description: str = ""
    evidence_paths: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    remediation: str = ""
    confidence: str = "probable"
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Top-level result returned by a scanner's main entry-point."""

    scanner: str
    target: str
    success: bool = True
    error: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    findings: list[ScanFinding] = Field(default_factory=list)
    raw_text: str = ""

    def to_agent_text(self, cap: int = 4096) -> str:
        """Summarise for an LLM agent — capped at cap bytes."""
        lines = [f"scanner={self.scanner} target={self.target} ok={self.success}"]
        if self.error:
            lines.append(f"error: {self.error}")
        if self.data:
            lines.append(f"data: {self.data}")
        if self.findings:
            lines.append(f"findings ({len(self.findings)}):")
            for f in self.findings:
                lines.append(f"  [{f.severity}] {f.vuln_class}: {f.title} @ {f.affected_target}")
        if self.raw_text:
            lines.append("raw:")
            lines.append(self.raw_text[:1024])
        return truncate_for_agent("\n".join(lines), cap=cap)


# ── Text utilities ─────────────────────────────────────────────────────────────


def truncate_for_agent(text: Any, cap: int = 4096) -> str:
    """Encode to UTF-8, cap at ``cap`` bytes, return decoded string."""
    s = str(text)
    encoded = s.encode("utf-8")
    if len(encoded) <= cap:
        return s
    return encoded[:cap].decode("utf-8", errors="ignore") + "\n…[truncated]"


# ── Wordlist loader ────────────────────────────────────────────────────────────

_WORDLIST_CACHE: dict[str, list[str]] = {}

# Wordlist names that live in skills/checks/wordlists/
_BUNDLED_WORDLISTS = {
    "common": "common.txt",
    "raft-small": "raft-small.txt",
    "dirbuster-medium": "dirbuster-medium.txt",
}

_NETWORK_PIPELINE_ROOT = Path(__file__).parent.parent


def load_wordlist(name: str) -> list[str]:
    """Load a bundled wordlist by name; returns list of non-empty, non-comment lines.

    Names: 'common', 'raft-small', 'dirbuster-medium'.

    Uses importlib.resources so this works both for editable and wheel installs,
    provided skills/checks/wordlists/ is listed under [tool.setuptools.package-data].
    Falls back to direct path resolution for editable installs.
    """
    if name in _WORDLIST_CACHE:
        return _WORDLIST_CACHE[name]

    filename = _BUNDLED_WORDLISTS.get(name, f"{name}.txt")

    # Primary: importlib.resources (works after pip install)
    lines: list[str] | None = None
    try:
        pkg = importlib.resources.files("network_pipeline.skills.checks.wordlists")
        resource = pkg.joinpath(filename)
        text = resource.read_text(encoding="utf-8", errors="replace")
        lines = _parse_wordlist(text)
    except (FileNotFoundError, ModuleNotFoundError, TypeError, AttributeError):
        pass

    # Fallback: direct path (editable installs without package-data configured)
    if lines is None:
        direct = _NETWORK_PIPELINE_ROOT / "skills" / "checks" / "wordlists" / filename
        if direct.exists():
            lines = _parse_wordlist(direct.read_text(encoding="utf-8", errors="replace"))

    if lines is None:
        lines = []

    _WORDLIST_CACHE[name] = lines
    return lines


def _parse_wordlist(text: str) -> list[str]:
    result = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            result.append(line)
    return result


def load_params_wordlist() -> list[str]:
    """Load skills/checks/params.txt — common parameter names for brute-force."""
    if "params" in _WORDLIST_CACHE:
        return _WORDLIST_CACHE["params"]

    lines: list[str] | None = None
    try:
        pkg = importlib.resources.files("network_pipeline.skills.checks")
        resource = pkg.joinpath("params.txt")
        text = resource.read_text(encoding="utf-8", errors="replace")
        lines = _parse_wordlist(text)
    except Exception:
        pass

    if lines is None:
        direct = _NETWORK_PIPELINE_ROOT / "skills" / "checks" / "params.txt"
        if direct.exists():
            lines = _parse_wordlist(direct.read_text(encoding="utf-8", errors="replace"))

    if lines is None:
        lines = []

    _WORDLIST_CACHE["params"] = lines
    return lines


# ── Evidence helpers ──────────────────────────────────────────────────────────


def attach_evidence(finding: ScanFinding, path: str | Path) -> None:
    """Append an evidence path to a finding (string form)."""
    finding.evidence_paths.append(str(path))


# ── URL normalisation ─────────────────────────────────────────────────────────

_DIGIT_SEG = re.compile(r"\d+")


def normalize_endpoint(url: str) -> str:
    """Normalise a URL for dedup: strip query values, replace numeric path segments.

    Also collapses bare-hostname vs full-URL forms so the same finding
    surfaced by Phase-L (``"scanme.nmap.org"``) and the LLM agent
    (``"http://scanme.nmap.org"``) deduplicates correctly.

    Examples:
      /users/123?id=5&page=2          ->  //users/{n}?id=&page=
      scanme.nmap.org                 ->  //scanme.nmap.org/
      http://scanme.nmap.org          ->  //scanme.nmap.org/
      http://scanme.nmap.org/admin    ->  //scanme.nmap.org/admin
    """
    from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
    if not url:
        return ""
    try:
        s = url.strip().rstrip("/")
        # If no scheme, prepend a placeholder so urlparse still picks
        # up the host correctly. We strip the scheme at the end so
        # bare-hostname and URL forms collapse to the same key.
        had_scheme = "://" in s
        if not had_scheme:
            s = "scheme://" + s
        parsed = urlparse(s)
        host = (parsed.hostname or "").lower()
        if parsed.port and parsed.port not in (80, 443):
            host = f"{host}:{parsed.port}"
        path = parsed.path or "/"
        # Replace digit-only path segments with {n}
        path = _DIGIT_SEG.sub("{n}", path)
        if not path.startswith("/"):
            path = "/" + path
        # Strip query values, keep keys
        qs = parse_qs(parsed.query, keep_blank_values=True)
        stripped_qs = urlencode({k: "" for k in qs}, doseq=False)
        # Use empty scheme so bare-host vs URL-form findings
        # produce identical normalised keys.
        return urlunparse(("", host, path, "", stripped_qs, ""))
    except Exception:
        return url


def normalize_finding_key(
    vuln_class: str,
    target: str,
    param: str = "",
) -> tuple[str, str, str]:
    """Return a (vuln_class, normalized_endpoint, normalized_param) dedup key."""
    return (
        vuln_class.lower().strip(),
        normalize_endpoint(target),
        (param or "").strip(),
    )


# ── WAF-evasion retry helpers ────────────────────────────────────────
#
# 2026 autonomous-pentest leaders (XBOW, ARTEMIS) all describe a "retry
# with progressive evasion" loop on first 403/406/429. Pipeline now ships
# the same: scanners call ``await with_evasion_retries(send_payload,
# payload, ...)`` — on a blocked response the helper retries with one of
# the canonical evasion mutations (percent-encode, double-percent-encode,
# case-flip, comment injection, unicode normalisation, query splitting).
# Returns the FIRST 2xx/3xx/4xx-non-WAF response and reports which
# evasion (if any) succeeded so reports can include "blocked by WAF
# until X bypass" findings.

import urllib.parse as _urlparse_mod
import unicodedata


# Status codes that look like a WAF / DoS-protection block, not a real
# application response. 418 is Cloudflare's "I'm a teapot".
_WAF_STATUSES = frozenset({403, 406, 412, 418, 429, 451, 501, 503})


def _evade_percent(payload: str) -> str:
    return _urlparse_mod.quote(payload, safe="")


def _evade_double_percent(payload: str) -> str:
    return _urlparse_mod.quote(_urlparse_mod.quote(payload, safe=""), safe="")


def _evade_case_flip(payload: str) -> str:
    return "".join(
        c.upper() if c.islower() else c.lower() for c in payload
    )


def _evade_comment(payload: str) -> str:
    """Insert SQL-style `/**/` between every two chars in keywords."""
    keywords = ("SELECT", "UNION", "WHERE", "FROM", "OR", "AND", "<script>")
    out = payload
    for kw in keywords:
        if kw.lower() in payload.lower():
            replaced = "/**/".join(kw)
            out = re.sub(re.escape(kw), replaced, out, flags=re.I)
    return out


def _evade_unicode(payload: str) -> str:
    """NFKD normalise so e.g. fullwidth chars decompose to ASCII at the WAF."""
    return unicodedata.normalize("NFKD", payload)


def _evade_query_split(payload: str) -> str:
    """Insert a stray `&x=` to break naive token-based WAF rules."""
    return payload.replace(" ", "%20") + "&_=" + str(hash(payload) & 0xFFFF)


_EVASIONS = (
    ("percent_encode", _evade_percent),
    ("double_percent", _evade_double_percent),
    ("case_flip", _evade_case_flip),
    ("comment_inject", _evade_comment),
    ("unicode_nfkd", _evade_unicode),
    ("query_split", _evade_query_split),
)


async def with_evasion_retries(
    send: Any,
    payload: str,
    *,
    max_retries: int = 3,
    waf_statuses: frozenset[int] = _WAF_STATUSES,
) -> tuple[Any, str]:
    """Send ``payload`` through ``send(payload) -> response``; on a WAF
    block status, retry with progressive evasion mutations.

    Returns a tuple ``(response, evasion_used)``. ``evasion_used`` is
    "" when no evasion was needed (or when nothing worked).

    ``send`` MUST be an async callable that accepts a single positional
    payload string and returns an httpx Response (or None).
    """
    resp = await send(payload)
    if resp is None or resp.status_code not in waf_statuses:
        return resp, ""
    tried = 0
    last = resp
    for label, mutate in _EVASIONS:
        if tried >= max_retries:
            break
        try:
            mutated = mutate(payload)
        except Exception:  # noqa: BLE001
            continue
        if mutated == payload:
            continue
        r = await send(mutated)
        tried += 1
        if r is None:
            continue
        if r.status_code not in waf_statuses:
            return r, label
        last = r
    return last, ""
