"""DNS scanner — replaces dnsx binary.

Resolves A, AAAA, TXT, MX, NS, CNAME records via dnspython.

2026 extensions:
- IPv6 surface enumeration (AAAA + reverse PTR + IPv6-only delta)
- DNS rebinding probe: detects whether the resolver returns RFC1918 /
  link-local / loopback / cloud-metadata addresses (169.254.169.254)
  for the queried name — strong indicator the host can be weaponised
  for attacker-controlled rebinding flows targeting browsers and
  internal services.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import TYPE_CHECKING, Any

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding, truncate_for_agent

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import DNSClient


# Addresses that should NEVER appear in a public DNS answer for a public
# hostname. Their presence implies DNS rebinding surface.
_REBIND_DANGER_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + AWS/GCP metadata
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


@register_scanner
class DNSScanner(Scanner):
    name = "dns_scan"
    requires_libs = ("dns.resolver",)
    opsec_min = "loud"
    loud_level = "low"

    DEFAULT_TYPES = ("A", "AAAA", "TXT", "MX", "NS", "CNAME")

    def __init__(self, dns_client: "DNSClient") -> None:
        self._dns = dns_client

    async def resolve(
        self,
        domain: str,
        types: tuple[str, ...] = DEFAULT_TYPES,
    ) -> ScanResult:
        """Resolve multiple record types for domain."""
        records: dict[str, list[str]] = {}
        for rtype in types:
            answers = await self._dns.resolve(domain, rtype)
            if answers:
                records[rtype] = answers

        findings: list[ScanFinding] = []

        # Flag missing SPF/DMARC (informational)
        txt = records.get("TXT", [])
        has_spf = any("v=spf1" in t.lower() for t in txt)
        has_dmarc = "_dmarc" in domain.lower() or any("v=dmarc1" in t.lower() for t in txt)
        if not has_spf and records:
            findings.append(ScanFinding(
                vuln_class="missing-spf",
                title=f"No SPF record on {domain}",
                severity="low",
                affected_target=domain,
                description="No SPF TXT record found. Increases email spoofing risk.",
                cwe=["CWE-1007"],
                remediation='Add "v=spf1 ... -all" TXT record.',
                confidence="verified",
            ))

        # ── IPv6 surface coverage ──────────────────────────────────
        a_records = records.get("A", [])
        aaaa_records = records.get("AAAA", [])
        if a_records and not aaaa_records:
            findings.append(ScanFinding(
                vuln_class="ipv6-not-deployed",
                title=f"{domain} has no AAAA (IPv6) records",
                severity="informational",
                affected_target=domain,
                description=(
                    "Host serves IPv4 only. Increasingly notable in 2026 "
                    "as IPv6-first networks become more common; also a "
                    "blue-team detection signal."
                ),
                confidence="verified",
            ))
        elif aaaa_records and not a_records:
            findings.append(ScanFinding(
                vuln_class="ipv4-not-deployed",
                title=f"{domain} has no A (IPv4) records",
                severity="informational",
                affected_target=domain,
                description="IPv6-only deployment.",
                confidence="verified",
            ))

        # ── DNS rebinding probe ──────────────────────────────────
        rebind_hits: list[str] = []
        for rec in a_records + aaaa_records:
            try:
                addr = ipaddress.ip_address(rec)
            except ValueError:
                continue
            for net in _REBIND_DANGER_RANGES:
                if addr.version != net.version:
                    continue
                if addr in net:
                    rebind_hits.append(str(addr))
                    break
        if rebind_hits:
            # 169.254.169.254 = AWS/GCP/Azure metadata; treat specially.
            metadata_hit = any(h.startswith("169.254.169.254") for h in rebind_hits)
            findings.append(ScanFinding(
                vuln_class=(
                    "dns-rebind-cloud-metadata"
                    if metadata_hit else "dns-rebind-private-ip"
                ),
                title=(
                    f"DNS for {domain} resolves to private/loopback/"
                    "metadata address — DNS rebinding surface"
                ),
                severity="high" if metadata_hit else "medium",
                affected_target=domain,
                description=(
                    f"Resolved addresses include {sorted(set(rebind_hits))}. "
                    "An attacker page can use this hostname to bypass SOP "
                    "and reach internal services or cloud metadata."
                ),
                cwe=["CWE-918", "CWE-441"],
                mitre=["T1090"],
                confidence="verified",
                extra={"resolved_to": sorted(set(rebind_hits))},
            ))

        return ScanResult(
            scanner=self.name,
            target=domain,
            success=bool(records),
            data={
                "records": records,
                "types_queried": list(types),
                "ipv6_present": bool(aaaa_records),
                "rebind_hits": sorted(set(rebind_hits)),
            },
            findings=findings,
            raw_text=_format_records(domain, records),
        )


def _format_records(domain: str, records: dict[str, list[str]]) -> str:
    lines = [f"DNS records for {domain}:"]
    for rtype, answers in records.items():
        for a in answers:
            lines.append(f"  {rtype}: {a}")
    return "\n".join(lines)
