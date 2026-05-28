"""Scanner tool wrappers — nmap / masscan / httpx.

Critical: never feed raw nmap XML or massive httpx output back to the
model. Each wrapper parses, condenses to <4 KB, and persists raw output
to disk. The disk path is included in the return so the analyst can
ingest into the KG via tools.kg.ingest_nmap_xml.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from network_pipeline.core.logging import get_logger
from network_pipeline.tools.output_schemas import HttpxLine, parse_jsonl
from network_pipeline.tools.recon import _truncate
from network_pipeline.tools.shell import ShellRunner

log = get_logger("tools.scan")


def run_nmap(
    runner: ShellRunner,
    target: str,
    *,
    ports: str = "1-1000",
    flags: list[str] | None = None,
    agent: str = "scanner",
    objective_id: str = "",
) -> str:
    """Run nmap, write XML to disk, return a compact host:port summary."""
    flags = flags or ["-sV", "-T4"]
    # We always emit XML for downstream KG ingest.
    xml_out = (runner._workspace / "tool_io" / agent
               / f"nmap_{objective_id or 'noobj'}.xml")
    xml_out.parent.mkdir(parents=True, exist_ok=True)
    res = runner.run(
        "nmap",
        [*flags, "-p", ports, "-oX", str(xml_out), target],
        targets=[target],
        timeout_s=600,
        agent=agent,
        objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[nmap skipped] {res.error}"

    summary = _summarise_nmap_xml(xml_out)
    summary += f"\nraw XML: {xml_out}"
    text, _ = _truncate(summary)
    return text


def _summarise_nmap_xml(xml_path: Path) -> str:
    """Best-effort condensed summary — works without python-libnmap."""
    if not xml_path.exists():
        return "(nmap produced no XML)"
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        return f"(nmap XML parse error: {e})"
    root = tree.getroot()
    lines: list[str] = []
    for host in root.findall("host"):
        addr_el = host.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "?"
        ports = []
        for port in host.findall("./ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port.get("portid")
            proto = port.get("protocol")
            svc_el = port.find("service")
            svc = svc_el.get("name", "?") if svc_el is not None else "?"
            product = svc_el.get("product", "") if svc_el is not None else ""
            version = svc_el.get("version", "") if svc_el is not None else ""
            label = f"{portid}/{proto} {svc}"
            if product:
                label += f" ({product} {version})".rstrip()
            ports.append(label)
        if ports:
            lines.append(f"{addr}: " + ", ".join(ports))
        else:
            lines.append(f"{addr}: no open ports")
    if not lines:
        return "nmap: no hosts up"
    return "\n".join(lines)


def run_httpx(
    runner: ShellRunner,
    targets: list[str],
    *,
    flags: list[str] | None = None,
    agent: str = "scanner",
    objective_id: str = "",
) -> str:
    """Probe URLs with httpx in JSON mode and parse via Pydantic schema.

    The Phase-1 audit flagged the original plain-text parser as fragile;
    we now invoke httpx with ``-json`` so each line is a structured
    record validated by ``HttpxLine`` (extra fields ignored ⇒ forward-
    compat). Bad lines surface as typed ``ParseError`` records instead
    of disappearing into "unknown".
    """
    # ``-json`` is the canonical flag for projectdiscovery/httpx; falls
    # back to ``-jsonl`` on older builds — both produce JSONL.
    flags = flags or [
        "-status-code", "-title", "-tech-detect",
        "-json", "-silent", "-no-color",
    ]
    list_file = (runner._workspace / "tool_io" / agent
                 / f"httpx_targets_{objective_id or 'noobj'}.txt")
    list_file.parent.mkdir(parents=True, exist_ok=True)
    list_file.write_text("\n".join(targets), encoding="utf-8")
    res = runner.run(
        "httpx",
        ["-l", str(list_file), *flags],
        targets=targets,
        timeout_s=300,
        agent=agent,
        objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[httpx skipped] {res.error}"
    raw = res.stdout_path.read_text(errors="replace") if res.stdout_path.exists() else ""
    hits, errs = parse_jsonl(raw, HttpxLine, tool="httpx")
    if errs:
        log.warning("httpx: %d malformed lines (sample: %s)",
                    len(errs), errs[0].error[:200])
    lines = [
        f"  [{h.status_code}] {h.url}"
        + (f"  webserver={h.webserver}" if h.webserver else "")
        + (f"  tech={','.join(h.tech)}" if h.tech else "")
        + (f"  title={h.title[:60]}" if h.title else "")
        for h in hits
    ]
    summary = (
        f"httpx: {len(hits)} live hosts of {len(targets)} probed\n"
        + "\n".join(lines[:30])
        + (f"\n[parse-errors: {len(errs)}]" if errs else "")
        + f"\nfull JSONL: {res.stdout_path}"
    )
    text, _ = _truncate(summary)
    return text
