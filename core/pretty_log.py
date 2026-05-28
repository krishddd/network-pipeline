"""Decepticon-style pretty logger for the CLI.

The default ``logging`` output dumps every HTTP error as its own
WARNING line, which floods the terminal during a baseline scan (one
line per probed URL × tens of probes per scanner). For demos, we want
the operator to see *what's happening at the engagement level*:

  - bold banners for ATTACK / VACCINE / COMPLETE transitions
  - per-iteration headers (1/15 → recon (OBJ-001))
  - findings announced inline, severity-coloured
  - live cost ticker
  - condensed counter for ConnectError / timeout / scope-deny noise
    (e.g. "·· 30 connect errors against http://localhost ··")

Implementation: a custom ``logging.Handler`` filters the verbose
events, increments counters, and emits compact ``rich``-styled output
when ``rich`` is installed (otherwise it falls back to plain ANSI).

Activated via ``cli autopilot --pretty`` (default ON) and any CLI
command that calls ``install_pretty_logging()``.
"""

from __future__ import annotations

import logging
import re
import sys
import threading
import time
from typing import Optional


# ── style helpers (rich-optional) ─────────────────────────────────────


try:
    from rich.console import Console  # type: ignore[import-not-found]
    _console: Optional["Console"] = Console(stderr=True, soft_wrap=True)
except ImportError:  # pragma: no cover - rich is optional
    _console = None


# ANSI fallbacks for when rich isn't installed (or stdout isn't a TTY).
_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "br_red": "\033[91m",
    "br_yellow": "\033[93m",
    "br_cyan": "\033[96m",
}


def _emit(message: str, *, style: str = "") -> None:
    """Print to stderr — use rich Console when available, ANSI fallback otherwise."""
    if _console is not None:
        _console.print(message, style=style or None, highlight=False)
        return
    # Plain ANSI fallback. `style` may be a single name like "red" or "bold cyan".
    codes: list[str] = []
    for token in (style or "").split():
        if token in _ANSI:
            codes.append(_ANSI[token])
    prefix = "".join(codes)
    suffix = _ANSI["reset"] if prefix else ""
    print(f"{prefix}{message}{suffix}", file=sys.stderr, flush=True)


_SEVERITY_STYLE = {
    "critical": "bold red",
    "high":     "bold br_red",
    "medium":   "bold yellow",
    "low":      "cyan",
    "info":     "dim white",
    "informational": "dim white",
}


# ── pattern matchers for log lines we want to compress / pretty-print ─


_PHASE_BANNER_RE = re.compile(r"Phase-L stage (\d)/(\d): (.+)")
_BASELINE_DONE_RE = re.compile(r"baseline ([\w_]+): (\d+) findings? \(([\d.]+)s\)")
_BASELINE_START_RE = re.compile(r"baseline ([\w_]+): starting")
_BASELINE_TIMEOUT_RE = re.compile(r"baseline ([\w_]+): TIMED OUT")
_ITER_RE = re.compile(r"iteration (\d+): (\S+) \((\S+)\)")
_FINDING_RE = re.compile(r"finding logged: (FIND-[\w-]+) \[FindingSeverity\.(\w+)\] (.+)")
_PROBE_OK_RE = re.compile(r"LLM probe OK \(profile=ModelProfile\.(\w+), providers=(.+)\)")
_HTTP_ERR_RE = re.compile(
    r"http_client: (GET|POST|PUT|DELETE|HEAD|PATCH) (\S+) (FAILED|UNEXPECTED ERROR|scope denied)"
)
_ENG_TRANS_RE = re.compile(r"transitioning to (ATTACK|VACCINE|COMPLETE)")


# ── the handler ──────────────────────────────────────────────────────


class PrettyHandler(logging.Handler):
    """Filters + re-formats noisy events for a Decepticon-style demo log."""

    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self._lock = threading.Lock()
        self._http_err_counter: dict[str, int] = {}
        self._last_flush = time.time()
        self._flush_every_seconds = 4.0

    # ── public flush ─────────────────────────────────────────────

    def flush_http_errors(self) -> None:
        """Emit the suppressed-error counter line and reset."""
        with self._lock:
            if not self._http_err_counter:
                return
            total = sum(self._http_err_counter.values())
            hosts = list(self._http_err_counter)
            self._http_err_counter.clear()
            self._last_flush = time.time()
        sample = ", ".join(hosts[:2]) + ("…" if len(hosts) > 2 else "")
        _emit(f"  ·· {total} connect errors suppressed ({sample}) ··",
              style="dim")

    # ── handler API ──────────────────────────────────────────────

    def emit(self, record: logging.LogRecord) -> None:  # noqa: D401
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover
            return

        # Suppress / count repetitive HTTP failures.
        m = _HTTP_ERR_RE.search(message)
        if m:
            verb, url, _kind = m.groups()
            host = url.split("/", 3)[2] if "//" in url else url.split("/", 1)[0]
            with self._lock:
                self._http_err_counter[host] = self._http_err_counter.get(host, 0) + 1
                if time.time() - self._last_flush > self._flush_every_seconds:
                    self._last_flush = time.time()
                    # Snapshot + flush inline (avoid recursive lock).
                    total = sum(self._http_err_counter.values())
                    hosts = list(self._http_err_counter)
                    self._http_err_counter.clear()
                    snapshot = (total, hosts)
                else:
                    snapshot = None
            if snapshot:
                total, hosts = snapshot
                sample = ", ".join(hosts[:2]) + ("…" if len(hosts) > 2 else "")
                _emit(f"  ·· {total} connect errors suppressed ({sample}) ··",
                      style="dim")
            return

        # Pattern-based pretty handlers.
        if m := _PHASE_BANNER_RE.search(message):
            n, total, label = m.groups()
            _emit("")
            _emit(f"━━━ Phase-L stage {n}/{total}: {label} ━━━",
                  style="bold cyan")
            return

        if m := _BASELINE_START_RE.search(message):
            scanner, = m.groups()
            _emit(f"  ▶ {scanner}", style="dim")
            return

        if m := _BASELINE_DONE_RE.search(message):
            scanner, count, elapsed = m.groups()
            count_i = int(count)
            if count_i:
                _emit(f"  ✓ {scanner:<22} {count_i:>3} findings  ({elapsed}s)",
                      style="bold green")
            else:
                _emit(f"  · {scanner:<22} {count_i:>3} findings  ({elapsed}s)",
                      style="dim green")
            return

        if m := _BASELINE_TIMEOUT_RE.search(message):
            scanner, = m.groups()
            _emit(f"  ⏱ {scanner:<22}   timeout", style="yellow")
            return

        if m := _ITER_RE.search(message):
            iter_n, obj, phase = m.groups()
            _emit("")
            _emit(f"━━━ Iteration {iter_n} · {obj} · {phase} ━━━",
                  style="bold magenta")
            return

        if m := _FINDING_RE.search(message):
            fid, sev_enum, title = m.groups()
            sev = sev_enum.lower()
            style = _SEVERITY_STYLE.get(sev, "white")
            _emit(f"  ⚑ {fid} [{sev.upper()}] {title}", style=style)
            return

        if m := _PROBE_OK_RE.search(message):
            profile, providers = m.groups()
            _emit(f"  LLM profile: {profile.lower()}  ({providers})",
                  style="bold green")
            return

        if m := _ENG_TRANS_RE.search(message):
            phase, = m.groups()
            color = {"ATTACK": "bold yellow", "VACCINE": "bold cyan",
                     "COMPLETE": "bold green"}.get(phase, "bold")
            _emit("")
            _emit(f"═══ {phase} phase ═══", style=color)
            return

        # Phase-L summary line.
        if "Phase-L baseline persisted" in message:
            _emit("")
            _emit("✓ baseline scan complete", style="bold green")
            return

        # Errors / warnings of any other kind: show but condensed.
        if record.levelno >= logging.ERROR:
            _emit(f"  ✗ {message}", style="red")
        elif record.levelno == logging.WARNING:
            # Hide low-value warnings unless verbose.
            if any(noisy in message for noisy in (
                "TCPConnectProbe: scope denied",
                "http_client: scope denied",
                "could not parse",
                "lock timeout",
            )):
                return
            _emit(f"  ! {message}", style="yellow")
        # INFO that didn't match a pattern → drop on the floor (the
        # JSONL trace log keeps the full record).


# ── install ──────────────────────────────────────────────────────────


_INSTALLED = False


def install_pretty_logging(level: int = logging.INFO) -> None:
    """Idempotently swap the root logger's handlers for the pretty one.

    Existing file handlers (pipeline.log, agent_traces.log) are NOT
    touched — they still get the full firehose. Only the console
    handler is replaced.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    root = logging.getLogger()
    # Remove any StreamHandler that writes to stderr/stdout.
    for h in list(root.handlers):
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            root.removeHandler(h)
    root.addHandler(PrettyHandler())
    root.setLevel(level)
    _INSTALLED = True


def banner(text: str, *, style: str = "bold cyan") -> None:
    """Manually emit a banner from CLI commands (outside the logger)."""
    bar = "═" * max(20, min(60, len(text) + 4))
    _emit("")
    _emit(bar, style=style)
    _emit(f"  {text}", style=style)
    _emit(bar, style=style)


def section(text: str, *, style: str = "bold magenta") -> None:
    _emit("")
    _emit(f"━━━ {text} ━━━", style=style)


def kv(label: str, value: str, *, style: str = "") -> None:
    _emit(f"  {label:<14} {value}", style=style)


__all__ = ["PrettyHandler", "banner", "install_pretty_logging", "kv", "section"]
