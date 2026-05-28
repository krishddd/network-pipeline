"""Port scanner — replaces nmap basic connect-scan.

Public-facing scanner class. Composes TCPConnectProbe from tools/runtime.py.
Returns open ports with banners; no deep OS fingerprinting (out of scope).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from network_pipeline.scanners import Scanner, register_scanner
from network_pipeline.scanners._common import ScanResult, ScanFinding
from network_pipeline.tools.runtime import TCPConnectProbe, PortResult

if TYPE_CHECKING:
    from network_pipeline.tools.runtime import ScopeGuard, CallbackProfile

# Common ports to scan by default
_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9200, 27017,
]


def _parse_port_range(ports_spec: str) -> list[int]:
    """Parse '1-1024' or '80,443,8080' or 'common' to a list of ints."""
    if ports_spec == "common":
        return list(_COMMON_PORTS)
    ports: list[int] = []
    for part in ports_spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(part))
    return ports


@register_scanner
class PortScanner(Scanner):
    """Pure-Python TCP connect-scan — distinct from TCPConnectProbe runtime primitive."""

    name = "port_scan"
    requires_libs = ()
    opsec_min = "loud"
    loud_level = "medium"

    def __init__(
        self,
        scope: "ScopeGuard | None" = None,
        callback_profile: "CallbackProfile | None" = None,
        *,
        concurrency: int = 200,
        timeout: float = 2.0,
    ) -> None:
        self._probe = TCPConnectProbe(
            scope=scope,
            callback_profile=callback_profile,
            concurrency=concurrency,
            timeout=timeout,
        )

    async def scan(
        self,
        target: str,
        ports: str = "common",
        timeout: float = 2.0,
    ) -> ScanResult:
        """Scan ports on target; return open ports with banners."""
        port_list = _parse_port_range(ports)
        open_ports = await self._probe.scan_ports(target, port_list)

        findings = _make_findings(target, open_ports)

        port_data = [
            {"port": r.port, "banner": r.banner, "duration_ms": round(r.duration_ms, 1)}
            for r in open_ports
        ]

        return ScanResult(
            scanner=self.name,
            target=target,
            success=True,
            data={
                "open_ports": port_data,
                "total_scanned": len(port_list),
                "total_open": len(open_ports),
            },
            findings=findings,
            raw_text=_format_ports(target, open_ports, len(port_list)),
        )


def _make_findings(target: str, open_ports: list[PortResult]) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    risky = {21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS",
             445: "SMB", 1433: "MSSQL", 3389: "RDP", 5900: "VNC"}
    for r in open_ports:
        if r.port in risky:
            findings.append(ScanFinding(
                vuln_class=f"exposed-service-{risky[r.port].lower()}",
                title=f"Exposed {risky[r.port]} service on {target}:{r.port}",
                severity="medium",
                affected_target=f"{target}:{r.port}",
                description=(
                    f"{risky[r.port]} (port {r.port}) is open. "
                    f"Banner: {r.banner[:100] if r.banner else 'none'}"
                ),
                cwe=["CWE-200"],
                remediation=f"Restrict access to port {r.port} via firewall if not required.",
                confidence="verified",
            ))
    return findings


def _format_ports(target: str, open_ports: list[PortResult], total: int) -> str:
    lines = [f"Port scan {target} ({total} ports):"]
    for r in open_ports:
        banner = f"  banner: {r.banner[:80]}" if r.banner else ""
        lines.append(f"  {r.port}/tcp OPEN{banner}")
    if not open_ports:
        lines.append("  (no open ports found)")
    return "\n".join(lines)
