"""Tests for tools.web.auth_replay — host-keyed AuthState."""

from __future__ import annotations

from pathlib import Path


def test_cookie_capture_and_load(workspace: Path):
    from network_pipeline.tools.web.auth_replay import AuthStore

    store = AuthStore(workspace)
    state = store.update_from_cookie_header(
        "https://app.example.com/login",
        "session=abc123; lang=en",
    )
    assert state.host == "app.example.com"
    assert state.cookies["session"] == "abc123"
    assert state.cookies["lang"] == "en"

    reloaded = store.get("https://app.example.com")
    assert reloaded is not None
    assert reloaded.cookies == state.cookies


def test_cross_host_isolation(workspace: Path):
    from network_pipeline.tools.web.auth_replay import AuthStore

    store = AuthStore(workspace)
    store.update_from_cookie_header("https://a.example.com", "x=1")
    # Different host — no leak
    other = store.get("https://b.example.com")
    assert other is None


def test_bearer_token_dedup(workspace: Path):
    from network_pipeline.tools.web.auth_replay import AuthStore

    store = AuthStore(workspace)
    s1 = store.set_bearer("https://api.example.com", "tok-A")
    s2 = store.set_bearer("https://api.example.com", "tok-A")  # duplicate
    s3 = store.set_bearer("https://api.example.com", "tok-B")
    assert s1.bearer_tokens == ["tok-A"]
    assert s2.bearer_tokens == ["tok-A"]
    assert s3.bearer_tokens == ["tok-A", "tok-B"]


def test_fingerprint_never_leaks_full_token(workspace: Path):
    from network_pipeline.tools.web.auth_replay import AuthStore

    secret = "supersecretsessioncookievalue"
    store = AuthStore(workspace)
    state = store.update_from_cookie_header(
        "https://app.example.com", f"session={secret}",
    )
    fp = state.fingerprint()
    s = repr(fp)
    assert secret not in s
    # but length is recorded
    assert "len=" in s


def test_authorized_curl_args_includes_cookie_and_bearer(workspace: Path):
    from network_pipeline.tools.web.auth_replay import AuthStore, authorized_curl_args

    store = AuthStore(workspace)
    state = store.update_from_cookie_header("https://api.example.com", "s=1")
    state = store.set_bearer("https://api.example.com", "tok-X")
    args = authorized_curl_args(state)
    # ['-H', 'Cookie: s=1', '-H', 'Authorization: Bearer tok-X']
    assert "-H" in args
    joined = " ".join(args)
    assert "Cookie: s=1" in joined
    assert "Authorization: Bearer tok-X" in joined


def test_replay_for_returns_none_when_no_state(workspace: Path):
    from network_pipeline.tools.web.auth_replay import replay_for

    state, args = replay_for(workspace, "https://newhost.example.com")
    assert state is None
    assert args == []
