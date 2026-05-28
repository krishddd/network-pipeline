"""Pydantic-validated tool-output schemas (Plan B.4.2).

The first port copied Decepticon's defensive-coding style — every
parser had ``obj.get("info", {}).get("severity", "unknown")`` chains
that quietly produced ``severity="unknown"`` rows when the upstream
tool's JSONL was malformed (and silently masked schema drift between
tool versions).

This module makes parsing typed: each tool's output line / record gets
a Pydantic model. Bad lines surface as ``ParseError`` objects that the
caller can log and skip, instead of disappearing into the stats.

The models intentionally use ``model_config = {"extra": "ignore"}`` so
*forward* compatibility holds: a future nuclei version that adds a new
top-level field doesn't break the parser, only fields we already named
must validate.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, TypeVar

from pydantic import BaseModel, Field, ValidationError


# ── Common parse-error envelope ───────────────────────────────────────


class ParseError(BaseModel):
    """One malformed input line / record — surfaced rather than dropped."""

    tool: str
    raw: str
    error: str

    model_config = {"extra": "ignore"}


# ── nuclei -jsonl ─────────────────────────────────────────────────────


class NucleiInfo(BaseModel):
    name: str = "?"
    severity: str = "unknown"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    classification: dict[str, Any] = Field(default_factory=dict)

    model_config = {"extra": "ignore"}


class NucleiHit(BaseModel):
    template_id: str = Field(default="", alias="template-id")
    info: NucleiInfo = Field(default_factory=NucleiInfo)
    host: str = ""
    matched_at: str = Field(default="", alias="matched-at")
    type: str = ""

    model_config = {"extra": "ignore", "populate_by_name": True}


# ── httpx -json ───────────────────────────────────────────────────────


class HttpxLine(BaseModel):
    url: str = ""
    status_code: int = Field(default=0, alias="status-code")
    title: str = ""
    tech: list[str] = Field(default_factory=list)
    content_length: int = Field(default=0, alias="content-length")
    webserver: str = ""

    model_config = {"extra": "ignore", "populate_by_name": True}


# ── subfinder ─────────────────────────────────────────────────────────


class SubfinderLine(BaseModel):
    """Subfinder default output is one host per line. With ``-json`` it
    emits ``{"host": "...", "source": "..."}`` records."""

    host: str
    source: str = ""

    model_config = {"extra": "ignore"}


# ── dnsx -json ────────────────────────────────────────────────────────


class DnsxLine(BaseModel):
    host: str = ""
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    cname: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    txt: list[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ── masscan -oJ ───────────────────────────────────────────────────────


class MasscanPort(BaseModel):
    port: int
    proto: str = "tcp"
    status: str = ""
    reason: str = ""

    model_config = {"extra": "ignore"}


class MasscanLine(BaseModel):
    ip: str = ""
    timestamp: str = ""
    ports: list[MasscanPort] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ── nmap (XML parsed via python-libnmap, but we expose a clean shape) ─


class NmapPort(BaseModel):
    port: int
    proto: str = "tcp"
    state: str = "unknown"
    service: str = ""
    product: str = ""
    version: str = ""

    model_config = {"extra": "ignore"}


class NmapHost(BaseModel):
    address: str
    hostname: str = ""
    state: str = "unknown"
    ports: list[NmapPort] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class NmapXmlResult(BaseModel):
    hosts: list[NmapHost] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ── whois / dig (free-text wrappers — keep loose) ─────────────────────


class WhoisRecord(BaseModel):
    domain: str
    raw: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""

    model_config = {"extra": "ignore"}


class DigRecord(BaseModel):
    name: str
    record_type: str
    answers: list[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ── helpers ───────────────────────────────────────────────────────────


M = TypeVar("M", bound=BaseModel)


def parse_jsonl(
    text: str | Iterable[str], model: type[M], tool: str,
) -> tuple[list[M], list[ParseError]]:
    """Parse a JSONL blob into a list of ``model`` + a list of errors.

    Lines that aren't valid JSON or don't validate produce a typed
    ``ParseError``. Callers should log the count of errors but emit the
    typed hits to the agent.
    """
    if isinstance(text, str):
        lines: Iterable[str] = text.splitlines()
    else:
        lines = text
    hits: list[M] = []
    errs: list[ParseError] = []
    for raw in lines:
        s = raw.strip() if isinstance(raw, str) else str(raw).strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as e:
            errs.append(ParseError(tool=tool, raw=s[:200], error=f"json: {e}"))
            continue
        try:
            hits.append(model.model_validate(obj))
        except ValidationError as e:
            errs.append(ParseError(tool=tool, raw=s[:200], error=f"schema: {e}"))
    return hits, errs
