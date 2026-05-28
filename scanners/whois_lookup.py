"""WHOIS / RDAP scanner — replaces whois binary.

Primary: RDAP (https://rdap.org/) — no third-party lib, standard protocol.
Fallback: python-whois or raw socket whois.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import HTTPClient

_RDAP_URL = "https://rdap.org/domain/{domain}"


@register_scanner
class WhoisScanner(Scanner):
    name = "whois_lookup"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "passive"

    def __init__(self, http_client: "HTTPClient") -> None:
        self._http = http_client

    async def lookup(self, domain: str) -> ScanResult:
        """WHOIS/RDAP lookup for a domain."""
        data: dict[str, Any] = {}

        # Try RDAP first (no extra lib)
        rdap_url = _RDAP_URL.format(domain=domain)
        resp = await self._http.get(
            rdap_url,
            scanner_tool=self.name,
            check_scope=False,  # RDAP is always external
        )
        if resp is not None and resp.status_code == 200:
            try:
                rdap = resp.json()
                data["rdap"] = _parse_rdap(rdap)
                data["source"] = "rdap"
            except Exception:
                data["raw"] = resp.text[:2048]
                data["source"] = "rdap-raw"
        else:
            # Fallback: python-whois
            data = await _try_python_whois(domain)

        findings = _check_expiry(domain, data)

        return ScanResult(
            scanner=self.name,
            target=domain,
            success=bool(data),
            data=data,
            findings=findings,
            raw_text=_format_whois(domain, data),
        )


def _parse_rdap(rdap: dict) -> dict:
    out: dict[str, Any] = {}
    out["name"] = rdap.get("ldhName", "")
    out["status"] = rdap.get("status", [])
    out["registrar"] = _extract_entity_role(rdap, "registrar")
    out["registrant"] = _extract_entity_role(rdap, "registrant")
    for ev in rdap.get("events", []):
        action = ev.get("eventAction", "")
        date = ev.get("eventDate", "")
        if action == "expiration":
            out["expiry"] = date
        elif action == "registration":
            out["registered"] = date
        elif action == "last changed":
            out["updated"] = date
    out["nameservers"] = [
        ns.get("ldhName", "") for ns in rdap.get("nameservers", [])
    ]
    return out


def _extract_entity_role(rdap: dict, role: str) -> str:
    for entity in rdap.get("entities", []):
        if role in (entity.get("roles") or []):
            fn = entity.get("vcardArray", [None, []])[1]
            for item in fn or []:
                if item[0] == "fn":
                    return item[3]
    return ""


async def _try_python_whois(domain: str) -> dict:
    """Try python-whois library as fallback."""
    try:
        import whois  # type: ignore[import]
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, whois.whois, domain)
        return {
            "registrar": str(getattr(result, "registrar", "") or ""),
            "expiry": str(getattr(result, "expiration_date", "") or ""),
            "registered": str(getattr(result, "creation_date", "") or ""),
            "nameservers": list(getattr(result, "name_servers", []) or []),
            "source": "python-whois",
        }
    except Exception:
        return {"source": "unavailable"}


def _check_expiry(domain: str, data: dict) -> list[ScanFinding]:
    """Flag if domain expiry is within 30 days."""
    findings = []
    expiry_str = data.get("rdap", {}).get("expiry", "") or data.get("expiry", "")
    if not expiry_str:
        return findings
    try:
        from datetime import datetime, timezone
        if isinstance(expiry_str, str):
            for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d"):
                try:
                    exp = datetime.strptime(expiry_str[:19], fmt[:len(expiry_str[:19])])
                    exp = exp.replace(tzinfo=timezone.utc)
                    delta = exp - datetime.now(timezone.utc)
                    if delta.days < 30:
                        findings.append(ScanFinding(
                            vuln_class="domain-expiry",
                            title=f"Domain {domain} expires in {delta.days} days",
                            severity="medium" if delta.days < 7 else "low",
                            affected_target=domain,
                            description=f"Domain expires on {expiry_str}.",
                            remediation="Renew domain registration.",
                            confidence="verified",
                        ))
                    break
                except ValueError:
                    continue
    except Exception:
        pass
    return findings


def _format_whois(domain: str, data: dict) -> str:
    lines = [f"WHOIS for {domain}:"]
    rd = data.get("rdap", data)
    for k, v in rd.items():
        if v:
            lines.append(f"  {k}: {v}")
    return "\n".join(lines)
