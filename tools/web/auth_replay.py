"""Authenticated session state — host-keyed, replay-safe.

Captures cookies + headers + JWT bearer tokens during recon and
replays them on subsequent web tool calls. Strictly host-keyed: an
AuthState for ``a.example.com`` will never be replayed against
``b.example.com``, preventing cross-target cred leakage (Plan risk #5).

State is persisted to ``workspace/auth/<host>.json`` so a resumed
engagement keeps the captured tokens. Tokens are NEVER logged in full
— only fingerprints (last 8 chars + length).
"""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from network_pipeline.core.logging import get_logger

log = get_logger("tools.web.auth_replay")


def _canonical_host(target: str) -> str:
    t = (target or "").strip().rstrip("/")
    if "://" in t:
        host = urllib.parse.urlparse(t).hostname or t
    else:
        host = t.split("/")[0].split(":", 1)[0]
    return host.lower()


class AuthState(BaseModel):
    """Captured per-host authentication artefacts."""

    host: str
    cookies: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    bearer_tokens: list[str] = Field(default_factory=list)
    csrf_token: str = ""
    last_updated: str = ""

    def fingerprint(self) -> dict[str, Any]:
        """Safe-to-log summary — never returns full token bodies."""
        def _fp(s: str) -> str:
            return f"...{s[-8:]} (len={len(s)})" if len(s) > 8 else f"(len={len(s)})"

        return {
            "host": self.host,
            "cookies": {k: _fp(v) for k, v in self.cookies.items()},
            "header_keys": sorted(self.headers.keys()),
            "bearer_tokens": [_fp(t) for t in self.bearer_tokens],
            "csrf_present": bool(self.csrf_token),
        }


class AuthStore:
    """Host-keyed AuthState persistence under ``workspace/auth/``."""

    def __init__(self, workspace: Path) -> None:
        self._dir = workspace / "auth"
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, host: str) -> Path:
        # Replace path-illegal chars; lowercased + stripped of port.
        safe = host.replace("/", "_").replace(":", "_")
        return self._dir / f"{safe}.json"

    def get(self, target: str) -> AuthState | None:
        host = _canonical_host(target)
        p = self._path_for(host)
        if not p.exists():
            return None
        try:
            return AuthState.model_validate_json(p.read_text(encoding="utf-8"))
        except Exception as e:  # pragma: no cover - defensive
            log.warning("auth_replay: bad JSON for %s (%r) — discarding", host, e)
            return None

    def save(self, state: AuthState) -> None:
        from datetime import datetime, timezone

        state.last_updated = datetime.now(timezone.utc).isoformat()
        p = self._path_for(state.host)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(state.model_dump_json(indent=2), encoding="utf-8")
        tmp.replace(p)

    def update_from_cookie_header(self, target: str, cookie_header: str) -> AuthState:
        """Merge a ``name=value; name=value`` cookie string into the state."""
        host = _canonical_host(target)
        state = self.get(target) or AuthState(host=host)
        for pair in cookie_header.split(";"):
            pair = pair.strip()
            if not pair or "=" not in pair:
                continue
            k, _, v = pair.partition("=")
            state.cookies[k.strip()] = v.strip()
        self.save(state)
        return state

    def set_bearer(self, target: str, token: str) -> AuthState:
        host = _canonical_host(target)
        state = self.get(target) or AuthState(host=host)
        token = token.strip()
        if token and token not in state.bearer_tokens:
            state.bearer_tokens.append(token)
        self.save(state)
        return state

    def set_cookies(self, target: str, cookies: dict[str, str]) -> AuthState:
        """Merge a dict of cookies into the host's AuthState."""
        host = _canonical_host(target)
        state = self.get(target) or AuthState(host=host)
        for k, v in (cookies or {}).items():
            if k:
                state.cookies[str(k).strip()] = str(v).strip()
        self.save(state)
        return state

    def summarize(self, target: str | None = None) -> dict[str, Any]:
        """Return a safe-to-log summary of stored auth state.

        If ``target`` is given, returns the fingerprint for that one host.
        Otherwise returns a mapping of host → fingerprint for all hosts.
        """
        if target:
            state = self.get(target)
            return state.fingerprint() if state else {"host": _canonical_host(target), "empty": True}
        out: dict[str, Any] = {}
        for host in self.list_hosts():
            p = self._path_for(host)
            try:
                state = AuthState.model_validate_json(p.read_text(encoding="utf-8"))
                out[host] = state.fingerprint()
            except Exception:
                continue
        return out

    def list_hosts(self) -> list[str]:
        return sorted(p.stem for p in self._dir.glob("*.json"))


def authorized_curl_args(state: AuthState) -> list[str]:
    """Return curl argv fragments that replay the captured auth state.

    Used by exploit/postexploit wrappers that delegate to ``run_curl``.
    """
    args: list[str] = []
    if state.cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in state.cookies.items())
        args.extend(["-H", f"Cookie: {cookie_str}"])
    for k, v in state.headers.items():
        args.extend(["-H", f"{k}: {v}"])
    if state.bearer_tokens:
        # Use the most recent bearer token by convention.
        args.extend(["-H", f"Authorization: Bearer {state.bearer_tokens[-1]}"])
    return args


def replay_for(
    workspace: Path, target: str,
) -> tuple[AuthState | None, list[str]]:
    """Convenience: load AuthState for target and return curl-args.

    Returns ``(state, [])`` when no state exists for the target's host —
    callers should treat that as "no auth yet, do an unauth probe".
    Refuses cross-host replay implicitly because ``get`` keys by host.
    """
    store = AuthStore(workspace)
    state = store.get(target)
    if state is None:
        return None, []
    return state, authorized_curl_args(state)
