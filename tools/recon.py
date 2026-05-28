"""Recon tool wrappers — subfinder / dnsx / whois / dig.

Each wrapper invokes the corresponding binary via ShellRunner, parses
the raw output, and returns a *condensed* agent-facing string capped at
4 KB. Raw output is always preserved on disk; the path is included in
the return so the analyst agent can ingest it later.
"""

from __future__ import annotations

from pathlib import Path

from network_pipeline.core.logging import get_logger
from network_pipeline.tools.output_schemas import DnsxLine, parse_jsonl
from network_pipeline.tools.shell import ShellRunner

log = get_logger("tools.recon")

MAX_AGENT_BYTES = 4 * 1024  # 4 KB cap on every model-facing return


def _truncate(text: str, max_bytes: int = MAX_AGENT_BYTES) -> tuple[str, bool]:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    cut = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return cut + "\n…[truncated]", True


def run_subfinder(runner: ShellRunner, domain: str, *, agent: str = "recon",
                  objective_id: str = "") -> str:
    """Enumerate subdomains; returns sorted unique list, capped at 200."""
    res = runner.run(
        "subfinder",
        ["-d", domain, "-silent"],
        targets=[domain],
        timeout_s=120,
        agent=agent,
        objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[subfinder skipped] {res.error}"
    raw = res.stdout_path.read_text(errors="replace") if res.stdout_path.exists() else ""
    hosts = sorted({line.strip() for line in raw.splitlines() if line.strip()})
    total = len(hosts)
    head = hosts[:200]
    summary = (
        f"subfinder for {domain}: {total} unique subdomains "
        f"(showing first {len(head)})\n"
        + "\n".join(head)
        + f"\nfull list: {res.stdout_path}"
    )
    text, _ = _truncate(summary)
    return text


def run_dnsx(runner: ShellRunner, domain: str, *, record_type: str = "A",
             agent: str = "recon", objective_id: str = "") -> str:
    """Resolve DNS records for ``domain`` via dnsx in JSON mode.

    Output is parsed through ``DnsxLine`` so each record (A / AAAA /
    CNAME / MX / NS / TXT) is typed; bad lines surface as
    ``ParseError`` rather than disappearing into "unknown".
    """
    res = runner.run(
        "dnsx",
        ["-d", domain, "-resp", "-silent", "-t", record_type, "-json"],
        targets=[domain],
        timeout_s=60,
        agent=agent,
        objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[dnsx skipped] {res.error}"
    raw = res.stdout_path.read_text(errors="replace") if res.stdout_path.exists() else ""
    hits, errs = parse_jsonl(raw, DnsxLine, tool="dnsx")
    if errs:
        log.warning("dnsx: %d malformed lines (sample: %s)",
                    len(errs), errs[0].error[:200])
    formatted: list[str] = []
    for h in hits[:100]:
        recs: list[str] = []
        for kind, vals in (
            ("A", h.a), ("AAAA", h.aaaa), ("CNAME", h.cname),
            ("MX", h.mx), ("NS", h.ns), ("TXT", h.txt),
        ):
            if vals:
                recs.append(f"{kind}={','.join(vals)}")
        formatted.append(f"  {h.host or '?'}: " + "; ".join(recs))
    summary = (
        f"dnsx {record_type} for {domain}: {len(hits)} records\n"
        + "\n".join(formatted)
        + (f"\n[parse-errors: {len(errs)}]" if errs else "")
        + f"\nfull JSONL: {res.stdout_path}"
    )
    text, _ = _truncate(summary)
    return text


def run_whois(runner: ShellRunner, domain: str, *, agent: str = "recon",
              objective_id: str = "") -> str:
    res = runner.run(
        "whois", [domain],
        targets=[domain], timeout_s=30, agent=agent, objective_id=objective_id,
    )
    if not res.ok and res.error:
        return f"[whois skipped] {res.error}"
    raw = res.stdout_path.read_text(errors="replace") if res.stdout_path.exists() else ""
    interesting_keys = (
        "Registrar:", "Creation Date:", "Updated Date:", "Registry Expiry Date:",
        "Name Server:", "OrgName:", "NetRange:", "Country:",
    )
    keep = [
        line.strip()
        for line in raw.splitlines()
        if any(line.lstrip().startswith(k) for k in interesting_keys)
    ]
    summary = f"whois {domain}:\n" + "\n".join(keep) + f"\nfull output: {res.stdout_path}"
    text, _ = _truncate(summary)
    return text
