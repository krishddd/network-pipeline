"""Intentionally vulnerable Flask app for integration testing.

Exposes 8 deliberate vulnerabilities for scanner validation:
1. SQLi at GET /products?id= (concatenated SQL, returns DB error on ')
2. Reflected XSS at GET /search?q= (echoes raw query into HTML)
3. Exposed .git/HEAD
4. Default creds at /admin (admin:admin Basic Auth)
5. Path traversal at GET /file?p=
6. Missing security headers on every response
7. Misconfigured CORS at /api/me (ACAO:* + credentials)
8. JWT with weak secret at POST /login, accepted at GET /profile

pytest_plugins = ["network_pipeline.tests.fixtures.vuln_app"]
"""

from __future__ import annotations

import base64
import os
import socket
import sqlite3
import threading
from typing import Iterator

import pytest

try:
    from flask import Flask, request, jsonify, Response
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

_JWT_SECRET = "secret"  # deliberately weak


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _create_app() -> "Flask":
    app = Flask(__name__)

    # ── 1. SQLi ───────────────────────────────────────────────────────
    @app.route("/products")
    def products():
        pid = request.args.get("id", "1")
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE p (id INT, name TEXT); INSERT INTO p VALUES (1,'Widget')")
        try:
            # deliberately vulnerable
            rows = conn.execute(f"SELECT * FROM p WHERE id = {pid}").fetchall()
            return "<html>" + str(rows) + "</html>"
        except sqlite3.OperationalError as e:
            return f"<html>DB Error: {e}</html>", 200

    # ── 2. Reflected XSS ──────────────────────────────────────────────
    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # deliberately echoes raw without escaping
        return f"<html><body>Results for: {q}</body></html>", 200

    # ── 3. Exposed .git/HEAD ──────────────────────────────────────────
    @app.route("/.git/HEAD")
    def git_head():
        return "ref: refs/heads/main\n", 200

    # ── 4. Default credentials at /admin ─────────────────────────────
    @app.route("/admin")
    @app.route("/admin/")
    def admin():
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode()
                if decoded == "admin:admin":
                    return "<html>Admin panel</html>", 200
            except Exception:
                pass
        return Response("Unauthorized", status=401, headers={"WWW-Authenticate": "Basic"})

    # ── 5. Path traversal ─────────────────────────────────────────────
    @app.route("/file")
    def file_read():
        p = request.args.get("p", "index.html")
        try:
            # deliberately vulnerable
            with open(p, "r", errors="replace") as f:
                return f"<html>{f.read()}</html>", 200
        except Exception as e:
            return f"<html>Error: {e}</html>", 200

    # ── 6. Missing headers (all routes — no security header middleware) ─
    # (no headers set = missing by default)

    # ── 7. Misconfigured CORS ─────────────────────────────────────────
    @app.route("/api/me")
    def api_me():
        resp = jsonify({"user": "testuser"})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    # ── 8. JWT with weak secret ────────────────────────────────────────
    @app.route("/login", methods=["POST"])
    def login():
        try:
            import jwt as pyjwt
        except ImportError:
            return jsonify({"error": "pyjwt not installed"}), 500
        token = pyjwt.encode({"sub": "user", "role": "user"}, _JWT_SECRET, algorithm="HS256")
        return jsonify({"token": token})

    @app.route("/profile")
    def profile():
        try:
            import jwt as pyjwt
        except ImportError:
            return jsonify({"error": "pyjwt not installed"}), 500
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            try:
                data = pyjwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
                return jsonify({"profile": data})
            except Exception as e:
                return jsonify({"error": str(e)}), 401
        return jsonify({"error": "no token"}), 401

    return app


@pytest.fixture(scope="session")
def vuln_app_url() -> Iterator[str]:
    """Start the vulnerable Flask app and yield its base URL."""
    if not HAS_FLASK:
        pytest.skip("Flask not installed — run: pip install flask")

    app = _create_app()
    port = _find_free_port()

    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, threaded=True, debug=False),
        daemon=True,
    )
    server_thread.start()

    import time
    # Wait for server to start
    for _ in range(20):
        try:
            import socket as _s
            with _s.create_connection(("127.0.0.1", port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.1)

    yield f"http://127.0.0.1:{port}"
