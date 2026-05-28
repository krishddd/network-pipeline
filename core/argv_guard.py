"""Differential RoE check + per-target paranoid sandbox (Plan B.4.3 + B.4.4).

The shell runner already enforces a binary allowlist, dangerous-token
filter, scope guard, and OPSEC tool gate. This module layers two more
checks that none of those catch:

* **Argv vs RoE.prohibited_actions** — a regex matrix that turns the
  RoE's free-text prohibitions ("no Denial of Service") into hard argv
  refusals. e.g. ``nmap -T5 --max-rate=10000`` against an RoE that lists
  "Denial of Service" → refused before subprocess spawn.

* **Per-target paranoid mode** — a target marked ``ScopeEntry.mode =
  "paranoid"`` always runs as if OPSEC=silent for THAT target only, even
  when the engagement-wide OPSEC is loud. Useful when a customer has
  explicitly authorised a target but asked us to be gentle.

The check returns ``None`` when the call is permitted, or a string
reason when refused. ``ShellRunner.run`` will translate the latter into
a typed error result without calling subprocess.
"""

from __future__ import annotations

import re

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import RoE, ScopeEntry

log = get_logger("core.argv_guard")


# Each rule maps a free-text prohibited-action keyword (substring,
# case-insensitive) → list of regex patterns that, if any matches a
# joined argv string, indicate the call would violate that prohibition.
#
# Keep these conservative: it's better to under-match (miss a violation
# the agent still attempts) than over-match (refuse legitimate calls).
_PROHIBITION_RULES: list[tuple[str, list[re.Pattern[str]]]] = [
    # Denial of Service — aggressive timing on nmap, masscan high rates,
    # nuclei concurrency knobs, sqlmap level 5, etc.
    (
        "denial of service",
        [
            re.compile(r"\s-T5\b"),                     # nmap insane timing
            re.compile(r"--max-rate(?:=|\s+)\d{4,}"),   # nmap >999 pps
            re.compile(r"\s--rate(?:=|\s+)\d{4,}"),     # masscan/nuclei
            re.compile(r"-c\s+\d{3,}"),                 # nuclei concurrency
            re.compile(r"--threads(?:=|\s+)\d{3,}"),    # general threading
            re.compile(r"\bhping3\b"),                  # never allowed
        ],
    ),
    # Modification or deletion of production data — sqlmap dangerous
    # OS-side flags, nuclei "intrusive" templates, dd / mkfs would be
    # caught earlier by the dangerous-token filter but list them anyway.
    (
        "modification",
        [
            re.compile(r"--os-shell\b"),
            re.compile(r"--os-pwn\b"),
            re.compile(r"--os-cmd\b"),
            re.compile(r"-(D|-drop-set|-flush-session)\b"),
            re.compile(r"--script(?:=|\s+)[^ ]*intrusive"),
            re.compile(r"--script(?:=|\s+)[^ ]*exploit"),
        ],
    ),
    (
        "deletion",
        [
            re.compile(r"--os-shell\b"),
            re.compile(r"--os-pwn\b"),
        ],
    ),
    # Exfiltration of real customer data — sqlmap full dump flags.
    (
        "exfiltration",
        [
            re.compile(r"--dump-all\b"),
            re.compile(r"--dump\b\s+--threads"),
        ],
    ),
]


# Tools that are always blocked under paranoid mode. Anything web-noisy,
# active, or that produces a non-trivial network footprint. The legit
# observation tools (curl, dig, whois, dnsx) remain available so the
# agent can still do *passive* checks against the paranoid target.
_PARANOID_BLOCKED_BINARIES: frozenset[str] = frozenset({
    "masscan", "nuclei", "wapiti", "nikto", "feroxbuster",
    "ffuf", "sqlmap", "dalfox", "jwt_tool", "zap-baseline.py",
    # nmap is allowed but only when scope-checked elsewhere; argv guard
    # below catches the truly aggressive flag combinations.
})


def _scope_entry_for(target: str, roe: RoE) -> ScopeEntry | None:
    """Find the in_scope entry that matches ``target`` (best-effort).

    Match preference (so a more-specific paranoid entry beats a less-
    specific normal one):
      1. Exact target string match.
      2. Exact host match.
      3. Longest domain-suffix match — picks ``paranoid.example.com``
         over ``example.com`` for ``host=paranoid.example.com``.
    Within each tier, paranoid-mode entries beat normal-mode entries.
    """
    target_n = (target or "").strip().rstrip("/").lower()
    if "://" in target_n:
        host = target_n.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    else:
        host = target_n.split("/", 1)[0].split(":", 1)[0]

    def _is_paranoid(e: ScopeEntry) -> bool:
        return (e.mode or "normal").lower() == "paranoid"

    exact_target: list[ScopeEntry] = []
    exact_host: list[ScopeEntry] = []
    suffix_matches: list[tuple[int, ScopeEntry]] = []  # (suffix_length, entry)
    for entry in roe.in_scope:
        et = entry.target.strip().rstrip("/").lower()
        if et == target_n:
            exact_target.append(entry)
            continue
        if et == host:
            exact_host.append(entry)
            continue
        if entry.type.lower() == "domain" and host.endswith("." + et):
            suffix_matches.append((len(et), entry))

    def _pick(entries: list[ScopeEntry]) -> ScopeEntry | None:
        if not entries:
            return None
        paranoid = [e for e in entries if _is_paranoid(e)]
        return paranoid[0] if paranoid else entries[0]

    pick = _pick(exact_target) or _pick(exact_host)
    if pick is not None:
        return pick
    if suffix_matches:
        # Longest suffix wins; ties broken by paranoid-mode preference.
        suffix_matches.sort(key=lambda t: (-t[0], 0 if _is_paranoid(t[1]) else 1))
        return suffix_matches[0][1]
    return None


def is_paranoid_target(target: str, roe: RoE | None) -> bool:
    """Return True if the target's ScopeEntry has ``mode == 'paranoid'``."""
    if roe is None:
        return False
    entry = _scope_entry_for(target, roe)
    if entry is None:
        return False
    return (entry.mode or "normal").lower() == "paranoid"


def check_argv(
    binary: str,
    argv: list[str],
    *,
    roe: RoE | None = None,
    targets: list[str] | None = None,
) -> str | None:
    """Return a refusal reason, or None if the call is permitted.

    * Cross-references ``RoE.prohibited_actions`` against the joined
      argv via the rule table above.
    * Refuses any call that would target a paranoid-mode entry with a
      blocked binary.
    """
    # 1. Per-target paranoid sandbox
    if roe is not None and targets:
        for t in targets:
            if is_paranoid_target(t, roe) and binary in _PARANOID_BLOCKED_BINARIES:
                return (
                    f"target {t!r} is in paranoid mode; binary "
                    f"{binary!r} not allowed against it"
                )

    # 2. Argv-vs-prohibited-action check
    if roe is None:
        return None
    joined = " " + " ".join(str(a) for a in argv) + " "
    joined_lower = joined.lower()
    for prohibition in roe.prohibited_actions:
        plower = prohibition.lower()
        for keyword, patterns in _PROHIBITION_RULES:
            if keyword not in plower:
                continue
            for pat in patterns:
                if pat.search(joined_lower):
                    return (
                        f"argv matches prohibited action "
                        f"{prohibition!r} (pattern: {pat.pattern!r})"
                    )
    return None
