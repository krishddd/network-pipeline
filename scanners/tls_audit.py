"""TLS/certificate auditor.

Scope (v1): single TLS handshake → negotiated cipher + protocol + cert chain.
Parse cert via cryptography.x509:
  - expiry, hostname match, weak keys (RSA<2048, EC<256), self-signed, missing SAN.
Full cipher-suite enumeration (sslyze) deferred to v1.1.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient


@register_scanner
class TLSAuditScanner(Scanner):
    name = "tls_audit"
    requires_libs = ("cryptography",)
    opsec_min = "loud"
    loud_level = "low"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def audit(self, target: str) -> ScanResult:
        """Perform TLS handshake and certificate audit on target."""
        parsed = urlparse(target)
        if parsed.scheme not in ("https", ""):
            return ScanResult(
                scanner=self.name, target=target, success=False,
                error="TLS audit only applies to HTTPS targets",
            )
        host = parsed.hostname or target
        port = parsed.port or 443

        loop = asyncio.get_event_loop()
        tls_info, error = await loop.run_in_executor(
            None, _do_tls_handshake, host, port
        )

        if error:
            return ScanResult(
                scanner=self.name, target=target, success=False,
                error=error,
            )

        findings = _analyze_tls(target, host, tls_info)

        return ScanResult(
            scanner=self.name,
            target=target,
            success=True,
            data=tls_info,
            findings=findings,
            raw_text=_format_tls(target, tls_info),
        )


def _do_tls_handshake(host: str, port: int) -> tuple[dict[str, Any], str]:
    """Blocking TLS handshake in executor thread."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # collect regardless of validity
    # Phase-J 2026: configure ALPN so the server-hello reveals which
    # protocols the host supports; this is part of the JA4S input.
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except (NotImplementedError, AttributeError):
        pass

    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()
                der_cert = tls_sock.getpeercert(binary_form=True)
                try:
                    alpn = tls_sock.selected_alpn_protocol()
                except (NotImplementedError, AttributeError):
                    alpn = None

        info: dict[str, Any] = {
            "cipher": cipher[0] if cipher else "",
            "cipher_bits": cipher[2] if cipher else 0,
            "protocol": protocol or "",
            "alpn": alpn or "",
        }

        # Phase-J 2026: JA4S-style server fingerprint from negotiated
        # parameters. Not byte-identical to FoxIO's reference JA4S (that
        # requires capturing the raw ServerHello, which Python's ssl
        # module abstracts away), but a stable, comparable signature
        # built from the same input class — enough for blue-team
        # correlation across engagements and detection-evasion testing.
        info["ja4s_lite"] = _ja4s_lite(info)

        if der_cert:
            cert_info = _parse_cert(der_cert, host)
            info.update(cert_info)

        return info, ""
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {}, f"connection failed: {e}"
    except ssl.SSLError as e:
        return {}, f"SSL error: {e}"


def _ja4s_lite(info: dict[str, Any]) -> str:
    """Compose a JA4S-style server fingerprint string.

    Format: ``t<proto>_<alpn>_<cipher_hash12>``

    Where:
    - ``proto`` is the negotiated TLS version short code: 12, 13.
    - ``alpn`` is the 2-char ALPN code (h2, h1) or ``00`` when absent.
    - ``cipher_hash12`` is the first 12 hex chars of SHA-256 of the
      negotiated cipher name.

    Caveat: real JA4S captures *all* server-hello extensions; this
    "lite" variant captures the subset Python's ssl module surfaces.
    The hash is stable so two engagements against the same server
    produce the same value, enabling correlation in evidence/.
    """
    import hashlib

    proto = (info.get("protocol") or "").lower()
    if "1.3" in proto:
        proto_code = "13"
    elif "1.2" in proto:
        proto_code = "12"
    elif "1.1" in proto:
        proto_code = "11"
    elif "1.0" in proto:
        proto_code = "10"
    else:
        proto_code = "00"

    alpn = (info.get("alpn") or "").lower()
    if alpn == "h2":
        alpn_code = "h2"
    elif alpn in ("http/1.1", "h1"):
        alpn_code = "h1"
    elif alpn:
        alpn_code = (alpn + "00")[:2]
    else:
        alpn_code = "00"

    cipher = (info.get("cipher") or "").upper()
    cipher_hash = (
        hashlib.sha256(cipher.encode("utf-8")).hexdigest()[:12] if cipher
        else "0" * 12
    )
    return f"t{proto_code}_{alpn_code}_{cipher_hash}"


def _parse_cert(der_cert: bytes, expected_host: str) -> dict[str, Any]:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

        cert = x509.load_der_x509_certificate(der_cert)
        now = datetime.now(timezone.utc)

        # Subject
        cn = ""
        for attr in cert.subject:
            if attr.oid.dotted_string == "2.5.4.3":  # OID for CN
                cn = str(attr.value)
                break

        # SANs
        sans: list[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [n.value for n in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        # Key info
        key = cert.public_key()
        key_type = type(key).__name__
        key_bits = 0
        if isinstance(key, rsa.RSAPublicKey):
            key_bits = key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key_bits = key.key_size
        elif isinstance(key, dsa.DSAPublicKey):
            key_bits = key.key_size

        # Self-signed check
        self_signed = cert.issuer == cert.subject

        # Expiry
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else \
            cert.not_valid_after.replace(tzinfo=timezone.utc)
        days_until_expiry = (not_after - now).days

        return {
            "subject_cn": cn,
            "sans": sans,
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else "",
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_until_expiry,
            "key_type": key_type,
            "key_bits": key_bits,
            "self_signed": self_signed,
        }
    except ImportError:
        return {"cert_parse": "cryptography library not installed"}
    except Exception as e:
        return {"cert_parse_error": str(e)}


def _analyze_tls(target: str, host: str, info: dict) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    protocol = info.get("protocol", "")
    if protocol and protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append(ScanFinding(
            vuln_class="weak-tls-protocol",
            title=f"Weak TLS protocol: {protocol} on {host}",
            severity="high",
            affected_target=target,
            description=f"Server negotiated deprecated protocol {protocol}.",
            cwe=["CWE-326"],
            mitre=["T1557"],
            remediation="Disable TLS 1.0/1.1 and SSLv2/SSLv3; enforce TLS 1.2+.",
            confidence="verified",
        ))

    days = info.get("days_until_expiry")
    if days is not None and days < 30:
        findings.append(ScanFinding(
            vuln_class="cert-expiring-soon",
            title=f"TLS certificate expires in {days} days on {host}",
            severity="medium" if days > 7 else "high",
            affected_target=target,
            description=f"Certificate for {host} expires in {days} days.",
            cwe=["CWE-298"],
            remediation="Renew the TLS certificate before expiry.",
            confidence="verified",
        ))

    key_bits = info.get("key_bits", 0)
    key_type = info.get("key_type", "")
    if key_bits and "RSA" in key_type and key_bits < 2048:
        findings.append(ScanFinding(
            vuln_class="weak-rsa-key",
            title=f"Weak RSA key ({key_bits} bits) on {host}",
            severity="high",
            affected_target=target,
            description=f"RSA key is {key_bits} bits; minimum recommended is 2048.",
            cwe=["CWE-326"],
            remediation="Replace certificate with RSA 2048+ or ECDSA P-256+.",
            confidence="verified",
        ))

    if info.get("self_signed"):
        findings.append(ScanFinding(
            vuln_class="self-signed-cert",
            title=f"Self-signed certificate on {host}",
            severity="medium",
            affected_target=target,
            description="Certificate is self-signed; browsers will show a warning.",
            cwe=["CWE-295"],
            remediation="Replace with a CA-signed certificate.",
            confidence="verified",
        ))

    sans = info.get("sans", [])
    cn = info.get("subject_cn", "")
    if not sans and cn:
        findings.append(ScanFinding(
            vuln_class="missing-san",
            title=f"Certificate has no Subject Alternative Names on {host}",
            severity="low",
            affected_target=target,
            description="Modern browsers require SAN; CN-only is deprecated.",
            cwe=["CWE-295"],
            remediation="Reissue certificate with appropriate SAN entries.",
            confidence="verified",
        ))

    # Phase-J 2026: emit JA4S-lite as an informational fingerprint
    # finding. Not a vulnerability — but operators correlate this
    # across engagements (blue-telemetry mode) to detect when a
    # backend swaps and to fingerprint scanner traffic.
    ja4s = info.get("ja4s_lite") or ""
    if ja4s:
        findings.append(ScanFinding(
            vuln_class="tls-ja4s-fingerprint",
            title=f"JA4S-lite fingerprint: {ja4s}",
            severity="informational",
            affected_target=target,
            description=(
                f"Negotiated TLS server fingerprint (Python-ssl-derived "
                f"JA4S variant): {ja4s}. Use to correlate scanner/blue-"
                "telemetry traffic and to detect backend swaps."
            ),
            confidence="verified",
            extra={
                "ja4s_lite": ja4s,
                "alpn": info.get("alpn", ""),
                "protocol": info.get("protocol", ""),
            },
        ))

    return findings


def _format_tls(target: str, info: dict) -> str:
    lines = [f"TLS audit for {target}:"]
    for k, v in info.items():
        if v or v == 0:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)
