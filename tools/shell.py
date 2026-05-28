"""Jailed subprocess runner for security-tool invocations.

Design (per the implementation plan):
  1. Binary allowlist, not string blocklist. Agents do not get freeform
     bash. They get narrowly-typed wrappers per binary.
  2. ``shell=False`` everywhere. argv lists only.
  3. Working-directory jail: subprocess cwd is locked to the engagement
     workspace; any path argument is resolved and rejected if it
     escapes the jail.
  4. Pre-flighted binaries: at engagement start we resolve each
     allowlisted binary via ``shutil.which`` and store the absolute
     path. A missing binary becomes a clean "tool unavailable" result.
  5. Target-scope enforcement: every invocation validates the target
     against the RoE in_scope list (CIDR / domain match) before
     spawning.
  6. Hard limits: per-call timeout, stdout truncated to disk at 5 MB.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from typing import TYPE_CHECKING

from network_pipeline.core.argv_guard import check_argv as _check_argv_vs_roe
from network_pipeline.core.logging import get_logger
from network_pipeline.core.rate_limit import GLOBAL_RATE_LIMITS, RateLimitRegistry

if TYPE_CHECKING:
    from network_pipeline.core.c2_profile import CallbackProfile
    from network_pipeline.core.evidence_chain import EvidenceChain
    from network_pipeline.core.schemas import RoE

log = get_logger("tools.shell")


# Allowlist: only these binaries can ever be spawned, even if a future tool
# wrapper tries. Add new entries deliberately.
ALLOWED_BINARIES = (
    # Phase-1 set
    "nmap",
    "masscan",
    "httpx",
    "nuclei",
    "subfinder",
    "dnsx",
    "curl",
    "whois",
    "dig",
    # Phase-2 web tooling (see tools/web/)
    "ffuf",
    "feroxbuster",
    "wapiti",
    "nikto",
    "zap-baseline.py",
    "getJS",
    "linkfinder",
    "paramspider",
    "arjun",
    "dalfox",
    "sqlmap",
    "jwt_tool",
)


MAX_OUTPUT_BYTES = 5 * 1024 * 1024  # 5 MB on disk per invocation


# Dangerous argv substrings / tokens. These are an extra defense on top of
# the binary allowlist — even if an allowed binary is spawned, these tokens
# indicate an attempt to do something destructive.
_DANGEROUS_TOKENS = ("pkill", "killall", "shutdown", "reboot", "mkfs")

# ANSI escape sequences to strip from captured output before persistence.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mK]")


class ShellDenied(RuntimeError):
    """Raised when a ShellRunner rejects an invocation on safety grounds."""


def _argv_is_dangerous(argv: list[str]) -> str | None:
    """Return a reason string if argv contains a dangerous token, else None."""
    for tok in argv:
        tok_s = str(tok)
        low = tok_s.lower()
        for bad in _DANGEROUS_TOKENS:
            if bad in low:
                return f"dangerous token {bad!r} in argv"
        # `dd if=...` style destructive usage
        if low.startswith("if=") or "dd if=" in low:
            return "dangerous `dd if=` pattern in argv"
        # nmap NSE abuse: `--script=<inline lua>` with script contents inline
        # (legitimate use is `--script=name,name`, not an inline Lua body).
        if tok_s.startswith("--script="):
            body = tok_s[len("--script="):]
            # Heuristic: any of these tokens in the value strongly suggests
            # an inline Lua string rather than a script name list.
            if any(k in body for k in ("function", "require(", "os.execute", "io.popen", ";", "\n")):
                return "inline Lua in --script= is not permitted"
    return None


def _strip_ansi_and_compress(path: Path) -> None:
    """Strip ANSI escapes and compress runs of >20 identical lines.

    Best-effort: silently returns on any error. Applied before the 5 MB
    truncation so the truncation happens against the already-cleaned file.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    cleaned = _ANSI_RE.sub("", raw)
    lines = cleaned.split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        j = i
        while j < n and lines[j] == lines[i]:
            j += 1
        run = j - i
        if run > 20:
            out.append(lines[i])
            out.append(f"...(repeated {run} times)...")
        else:
            out.extend(lines[i:j])
        i = j
    try:
        path.write_text("\n".join(out), encoding="utf-8")
    except OSError:
        return


# ── data types ─────────────────────────────────────────────────────


@dataclass
class ShellResult:
    """Outcome of one subprocess invocation."""

    binary: str
    argv: list[str]
    returncode: int
    duration_s: float
    stdout_path: Path
    stderr_path: Path
    truncated: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.returncode == 0


@dataclass
class ScopeGuard:
    """RoE-derived in-scope set. Every shell call validates against this."""

    domains: tuple[str, ...] = ()
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    raw_targets: tuple[str, ...] = ()

    def allows(self, target: str) -> bool:
        target = target.strip().rstrip("/")
        # Exact raw match (URLs, hostnames as given)
        if target in self.raw_targets:
            return True
        # Strip scheme/path for host-level checks
        host = target.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        # Domain suffix match
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        # IP / CIDR match
        try:
            ip = ipaddress.ip_address(host)
            for net in self.networks:
                if ip in net:
                    return True
        except ValueError:
            pass
        return False

    @classmethod
    def from_in_scope(cls, in_scope: list) -> "ScopeGuard":
        """Build from RoE in_scope ScopeEntry list."""
        domains: list[str] = []
        networks: list = []
        raw: list[str] = []
        for entry in in_scope:
            t = entry.target.strip().rstrip("/")
            kind = entry.type.lower()
            if kind in ("cidr", "ip-range", "ip"):
                try:
                    networks.append(ipaddress.ip_network(t, strict=False))
                except ValueError:
                    log.warning("invalid CIDR in RoE: %s", t)
            elif kind == "domain":
                domains.append(t)
            else:
                raw.append(t)
            # Also try to parse anything that looks like an IP/CIDR
            try:
                networks.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                pass
        return cls(
            domains=tuple(domains),
            networks=tuple(networks),
            raw_targets=tuple(raw),
        )


# ── runner ─────────────────────────────────────────────────────────


class ShellRunner:
    """Per-engagement jailed subprocess runner.

    Construct one per engagement, share across all agent tool wrappers.
    """

    def __init__(
        self,
        workspace: Path,
        scope: ScopeGuard | None = None,
        *,
        roe: "RoE | None" = None,
        rate_limits: "RateLimitRegistry | None" = None,
        callback_profile: "CallbackProfile | None" = None,
        evidence_chain: "EvidenceChain | None" = None,
    ) -> None:
        self._workspace = workspace.resolve()
        self._scope = scope or ScopeGuard()
        # RoE drives the argv-guard's prohibited-action + paranoid-target
        # checks. Optional so tests / CLI plan-only flows can still
        # construct a runner without an RoE.
        self._roe = roe
        # Rate limiter — defaults to the process-global registry so caps
        # configured via CLI flags apply automatically.
        self._rate_limits = rate_limits if rate_limits is not None else GLOBAL_RATE_LIMITS
        # Phase-3 callback profile (sleep / jitter / UA pool). Optional
        # — None means "no shaping", matching Phase-1 behaviour.
        self._callback_profile = callback_profile
        # Phase-4 evidence chain — when attached, every captured stdout
        # gets a SHA-256 sidecar + a Merkle leaf is appended.
        self._evidence_chain = evidence_chain
        self._resolved: dict[str, str] = {}
        for b in ALLOWED_BINARIES:
            path = shutil.which(b)
            if path:
                self._resolved[b] = path
            else:
                log.info("binary unavailable: %s (tool wrappers will skip)", b)
        (self._workspace / "tool_io").mkdir(parents=True, exist_ok=True)

    # ── public ─────────────────────────────────────────────────────

    @property
    def available_binaries(self) -> list[str]:
        return sorted(self._resolved.keys())

    def run(
        self,
        binary: str,
        argv: list[str],
        *,
        targets: list[str] | None = None,
        timeout_s: int = 300,
        agent: str = "unknown",
        objective_id: str = "",
    ) -> ShellResult:
        """Spawn a binary with a jailed cwd and capture output to files."""
        if binary not in ALLOWED_BINARIES:
            return self._error(binary, [], f"binary not in allowlist: {binary}")
        if binary not in self._resolved:
            return self._error(binary, [], f"binary not installed: {binary}")
        # Dangerous argv check (extra layer on top of allowlist).
        danger = _argv_is_dangerous(list(argv))
        if danger is not None:
            raise ShellDenied(f"refusing to run {binary}: {danger}")
        # Scope check on every target
        for t in targets or ():
            if not self._scope.allows(t):
                return self._error(
                    binary, [], f"target out of RoE scope: {t}"
                )
        # RoE prohibited-action + paranoid-target check (Plan B.4.3 + B.4.4)
        argv_refusal = _check_argv_vs_roe(
            binary, list(argv), roe=self._roe, targets=list(targets or ()),
        )
        if argv_refusal is not None:
            return self._error(binary, list(argv), f"argv refused: {argv_refusal}")
        # Per-(binary, host) rate limit (Plan B.4.1). One acquire per
        # target — usually one but tools like httpx accept many.
        for t in targets or ():
            self._rate_limits.acquire(binary, t)
        # Phase-3 callback profile: sleep + jitter before every spawn.
        # No-op when no profile attached.
        if self._callback_profile is not None:
            self._callback_profile.apply_pacing()

        # Build absolute argv with the resolved binary path; agents cannot
        # influence the binary path itself.
        full_argv = [self._resolved[binary], *map(str, argv)]
        out_dir = self._workspace / "tool_io" / agent
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        stem = f"{ts}_{objective_id or 'noobj'}_{binary}"
        stdout_path = out_dir / f"{stem}.stdout"
        stderr_path = out_dir / f"{stem}.stderr"
        argv_path = out_dir / f"{stem}.argv"
        argv_path.write_text("\n".join(full_argv), encoding="utf-8")

        t0 = time.time()
        truncated = False
        try:
            with open(stdout_path, "wb") as so, open(stderr_path, "wb") as se:
                proc = subprocess.run(
                    full_argv,
                    cwd=str(self._workspace),
                    stdout=so,
                    stderr=se,
                    timeout=timeout_s,
                    shell=False,  # never
                    check=False,
                )
            # ANSI strip + repetitive-line compression (best-effort, before truncation).
            _strip_ansi_and_compress(stdout_path)
            _strip_ansi_and_compress(stderr_path)
            # Truncate if huge
            try:
                if stdout_path.stat().st_size > MAX_OUTPUT_BYTES:
                    _truncate(stdout_path, MAX_OUTPUT_BYTES)
                    truncated = True
            except OSError as e:
                log.warning("stdout truncate failed (%s): %r", stdout_path, e)
            # Phase-4 integrity sidecars + Merkle leaf. Failures here
            # never break the run — audit chain is best-effort and the
            # chain verifier reports them as "missing sidecars" later.
            try:
                from network_pipeline.tools.integrity import (
                    sha256_file, write_sidecar,
                )
                sidecar = write_sidecar(
                    source_path=stdout_path,
                    workspace=self._workspace,
                    argv_path=argv_path,
                    kind="tool-output",
                )
                if sidecar is not None and self._evidence_chain is not None:
                    payload = sha256_file(stdout_path)
                    if payload:
                        from datetime import datetime, timezone
                        self._evidence_chain.add_sidecar_leaf(
                            sidecar_path=sidecar,
                            content_sha256=payload,
                            ts=datetime.now(timezone.utc).isoformat(),
                            kind="tool-output",
                        )
            except Exception as e:  # pragma: no cover - audit-only
                log.warning("evidence sidecar emit failed: %r", e)
            return ShellResult(
                binary=binary,
                argv=full_argv,
                returncode=proc.returncode,
                duration_s=time.time() - t0,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                truncated=truncated,
            )
        except subprocess.TimeoutExpired:
            return ShellResult(
                binary=binary,
                argv=full_argv,
                returncode=-1,
                duration_s=time.time() - t0,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                error=f"timeout after {timeout_s}s",
            )
        except Exception as e:  # pragma: no cover - defensive
            return ShellResult(
                binary=binary,
                argv=full_argv,
                returncode=-1,
                duration_s=time.time() - t0,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                error=repr(e),
            )

    def jailed_path(self, candidate: str | Path) -> Path:
        """Resolve a path under the workspace; reject any escape.

        Uses ``os.path.realpath`` to resolve symlinks so an agent can't
        point a symlink inside the workspace at ``/etc/passwd`` and
        sneak past a lexical ``relative_to()`` check.
        """
        # Resolve the workspace once so the comparison is symlink-safe
        # on both sides even if the workspace itself is under a symlink.
        workspace_real = Path(os.path.realpath(self._workspace))
        candidate_path = self._workspace / candidate
        real = Path(os.path.realpath(candidate_path))
        if not _is_under(real, workspace_real):
            raise PermissionError(f"path escapes workspace jail: {candidate}")
        return real

    # ── helpers ────────────────────────────────────────────────────

    def _error(self, binary: str, argv: list[str], msg: str) -> ShellResult:
        log.warning("shell rejected: %s", msg)
        return ShellResult(
            binary=binary,
            argv=argv,
            returncode=-1,
            duration_s=0.0,
            stdout_path=Path("/dev/null"),
            stderr_path=Path("/dev/null"),
            error=msg,
        )


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _truncate(path: Path, max_bytes: int) -> None:
    with open(path, "rb+") as f:
        f.truncate(max_bytes)
