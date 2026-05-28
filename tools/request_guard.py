"""HTTP request RoE guard — replaces core/argv_guard.py.

check_request(method, url, body, roe) → refusal reason string | None

Two checks:
1. RoE.prohibited_actions keyword → HTTP-method + URL-pattern match.
2. Per-target paranoid mode — strips offensive scanners by class when the
   target's ScopeEntry has mode='paranoid'.

The argv_guard module is kept as a thin shim that imports from here so
existing callers (tests) don't break.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from network_pipeline.core.logging import get_logger

if TYPE_CHECKING:
    from network_pipeline.core.schemas import RoE, ScopeEntry

log = get_logger("tools.request_guard")


# ── HTTP prohibition rules (keyword → list of (method_pattern, url_pattern)) ──

_HTTP_PROHIBITION_RULES: list[tuple[str, list[tuple[re.Pattern[str] | None, re.Pattern[str]]]]] = [
    (
        "denial of service",
        [
            # Block patterns that suggest flood-style operation; individual
            # request-level checks can't catch rate — rate_limit handles that.
            (None, re.compile(r"(flood|dos|ddos)", re.IGNORECASE)),
        ],
    ),
    (
        "modification",
        [
            # Block mutating HTTP methods to production paths
            (re.compile(r"^(POST|PUT|DELETE|PATCH)$"), re.compile(r"/(admin|api/v\d+/users|api/v\d+/delete)", re.IGNORECASE)),
        ],
    ),
    (
        "exfiltration",
        [
            # Block bulk-dump endpoints
            (None, re.compile(r"(dump|export|backup)\.(sql|zip|tar|gz)$", re.IGNORECASE)),
        ],
    ),
]


# Scanners blocked in paranoid mode (by scanner class name string)
_PARANOID_BLOCKED_SCANNERS: frozenset[str] = frozenset({
    "ContentScanner",
    "SQLiScanner",
    "XSSScanner",
    "WebAuditScanner",
    "AuthAuditScanner",
    "CVECheckScanner",
})

# URL paths that are explicitly never allowed (e.g. actual OS-level endpoints)
_ALWAYS_BLOCKED_URL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"file:///", re.IGNORECASE),
]


def check_request(
    method: str,
    url: str,
    body: bytes | str | None,
    roe: "RoE | None",
) -> str | None:
    """Return a refusal reason, or None if the call is permitted.

    Checks:
    1. Always-blocked URL patterns (file:// etc.)
    2. RoE prohibited_actions vs HTTP method + URL pattern
    """
    # Always-blocked schemes
    for pat in _ALWAYS_BLOCKED_URL_PATTERNS:
        if pat.search(url):
            return f"blocked URL scheme/pattern: {url}"

    if roe is None:
        return None

    for prohibition in roe.prohibited_actions:
        plower = prohibition.lower()
        for keyword, rules in _HTTP_PROHIBITION_RULES:
            if keyword not in plower:
                continue
            for method_pat, url_pat in rules:
                method_match = method_pat is None or method_pat.match(method.upper())
                url_match = url_pat.search(url)
                if method_match and url_match:
                    return (
                        f"request matches prohibited action {prohibition!r} "
                        f"(method={method}, url_pattern={url_pat.pattern!r})"
                    )
    return None


def is_paranoid_target(target: str, roe: "RoE | None") -> bool:
    """Return True if the target's ScopeEntry has mode='paranoid'."""
    if roe is None:
        return False
    entry = _scope_entry_for(target, roe)
    if entry is None:
        return False
    return (entry.mode or "normal").lower() == "paranoid"


def is_scanner_blocked_paranoid(scanner_class_name: str, target: str, roe: "RoE | None") -> bool:
    """Return True if a scanner should be blocked for a paranoid target."""
    if not is_paranoid_target(target, roe):
        return False
    return scanner_class_name in _PARANOID_BLOCKED_SCANNERS


def _scope_entry_for(target: str, roe: "RoE") -> "ScopeEntry | None":
    """Find the best-matching ScopeEntry for target."""
    target_n = (target or "").strip().rstrip("/").lower()
    if "://" in target_n:
        host = target_n.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    else:
        host = target_n.split("/", 1)[0].split(":", 1)[0]

    def _is_paranoid(e: "ScopeEntry") -> bool:
        return (e.mode or "normal").lower() == "paranoid"

    exact_target: list["ScopeEntry"] = []
    exact_host: list["ScopeEntry"] = []
    suffix_matches: list[tuple[int, "ScopeEntry"]] = []

    for entry in roe.in_scope:
        et = entry.target.strip().rstrip("/").lower()
        if et == target_n:
            exact_target.append(entry)
        elif et == host:
            exact_host.append(entry)
        elif entry.type.lower() == "domain" and host.endswith("." + et):
            suffix_matches.append((len(et), entry))

    def _pick(entries: list["ScopeEntry"]) -> "ScopeEntry | None":
        if not entries:
            return None
        paranoid = [e for e in entries if _is_paranoid(e)]
        return paranoid[0] if paranoid else entries[0]

    pick = _pick(exact_target) or _pick(exact_host)
    if pick is not None:
        return pick
    if suffix_matches:
        suffix_matches.sort(key=lambda t: (-t[0], 0 if _is_paranoid(t[1]) else 1))
        return suffix_matches[0][1]
    return None
