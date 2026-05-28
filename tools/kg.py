"""Concurrency-safe JSON knowledge graph + append-only findings log.

Replaces Decepticon's Neo4j-backed KG with a single-file JSON store.
Mutations are guarded by ``filelock.FileLock`` (cross-process,
flock-backed on POSIX) and writes are atomic via tmp-file + os.replace,
so readers never see a half-written file.

Findings live in a separate JSONL file and rely on POSIX O_APPEND
atomicity (small line writes are atomic on Linux), so no lock is needed
on the hot path.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from filelock import FileLock, Timeout as FileLockTimeout
except ImportError:  # pragma: no cover - lazy import for partial installs
    FileLock = None  # type: ignore[assignment,misc]
    FileLockTimeout = Exception  # type: ignore[assignment,misc]

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import Finding

log = get_logger("tools.kg")


SCHEMA_VERSION = 1
LOCK_TIMEOUT = 30  # seconds


# ── Phase-7: typed node + edge vocabulary ─────────────────────────────
#
# The flat JSON KG already stores ``type`` as a free-form string. These
# constants formalise the *attack-graph* vocabulary so the defender,
# verifier, and Mermaid reporter can build/walk a typed graph without
# hard-coding strings in three places. Existing ingestors continue to
# emit their own type names (``host``, ``http_service``, ``vulnerability``,
# ``dns_record``, ``port``) — the constants below are the *additional*
# attack-graph types layered on top.


class NodeType:
    """Attack-graph node-type vocabulary (Phase-7).

    These are class attributes rather than an Enum so existing free-form
    type strings (``host``, ``http_service``, ``dns_record``) keep
    working unchanged. The Phase-7 additions are ``vulnerability``,
    ``attack_step``, ``defense_action``, and ``finding``.
    """

    HOST = "host"
    PORT = "port"
    SERVICE = "http_service"
    VULNERABILITY = "vulnerability"
    ATTACK_STEP = "attack_step"
    DEFENSE_ACTION = "defense_action"
    FINDING = "finding"


class EdgeType:
    """Attack-graph edge-relation vocabulary (Phase-7)."""

    RUNS = "runs"                  # host RUNS service
    EXPLOITS = "exploits"          # attack_step EXPLOITS vulnerability
    CHAINS_TO = "chains_to"        # attack_step CHAINS_TO attack_step
    MITIGATES = "mitigates"        # defense_action MITIGATES vulnerability/finding
    RESPONDS_TO = "responds_to"    # defense_action RESPONDS_TO finding
    EVIDENCED_BY = "evidenced_by"  # vulnerability EVIDENCED_BY finding
    VERIFIED = "verified"          # defense_action VERIFIED vulnerability (re-attack-blocked)


# ── KG primitives ──────────────────────────────────────────────────


@dataclass
class KGNode:
    id: str
    type: str  # host, port, service, finding, credential, ...
    properties: dict[str, Any] = field(default_factory=dict)


@dataclass
class KGEdge:
    src: str
    dst: str
    relation: str
    properties: dict[str, Any] = field(default_factory=dict)


def _empty_kg() -> dict[str, Any]:
    return {"version": SCHEMA_VERSION, "nodes": [], "edges": []}


# ── Store ──────────────────────────────────────────────────────────


class KnowledgeGraph:
    """File-backed knowledge graph with cross-process locking."""

    def __init__(self, path: Path) -> None:
        if FileLock is None:
            raise RuntimeError(
                "filelock not installed. `pip install filelock` "
                "or install the [network] extra."
            )
        self._path = Path(path)
        self._lock_path = str(self._path) + ".lock"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._atomic_write(_empty_kg())

    # ── locking helpers ────────────────────────────────────────────

    def _lock(self) -> "FileLock":
        return FileLock(self._lock_path, timeout=LOCK_TIMEOUT)

    def _atomic_write(self, payload: dict[str, Any]) -> None:
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)

    def _read_locked(self) -> dict[str, Any]:
        if not self._path.exists():
            return _empty_kg()
        try:
            return json.loads(self._path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError:
            log.error("kg.json corrupted, reinitialising")
            self._atomic_write(_empty_kg())
            return _empty_kg()

    # ── mutations ──────────────────────────────────────────────────

    def add_node(self, node: KGNode) -> None:
        with self._lock():
            data = self._read_locked()
            for existing in data["nodes"]:
                if existing["id"] == node.id:
                    existing["properties"].update(node.properties)
                    self._atomic_write(data)
                    return
            data["nodes"].append(
                {"id": node.id, "type": node.type, "properties": node.properties}
            )
            self._atomic_write(data)

    def add_edge(self, edge: KGEdge) -> None:
        with self._lock():
            data = self._read_locked()
            data["edges"].append(
                {
                    "src": edge.src,
                    "dst": edge.dst,
                    "relation": edge.relation,
                    "properties": edge.properties,
                }
            )
            self._atomic_write(data)

    def add_nodes(self, nodes: list[KGNode]) -> None:
        with self._lock():
            data = self._read_locked()
            existing = {n["id"]: n for n in data["nodes"]}
            for node in nodes:
                if node.id in existing:
                    existing[node.id]["properties"].update(node.properties)
                else:
                    data["nodes"].append(
                        {
                            "id": node.id,
                            "type": node.type,
                            "properties": node.properties,
                        }
                    )
            self._atomic_write(data)

    # ── queries ────────────────────────────────────────────────────

    def query(self, node_type: str | None = None) -> list[dict[str, Any]]:
        with self._lock():
            data = self._read_locked()
        if node_type is None:
            return data["nodes"]
        return [n for n in data["nodes"] if n["type"] == node_type]

    def neighbors(self, node_id: str) -> list[dict[str, Any]]:
        with self._lock():
            data = self._read_locked()
        nbrs = []
        for e in data["edges"]:
            if e["src"] == node_id:
                nbrs.append({"direction": "out", **e})
            elif e["dst"] == node_id:
                nbrs.append({"direction": "in", **e})
        return nbrs

    def stats(self) -> dict[str, int]:
        with self._lock():
            data = self._read_locked()
        types: dict[str, int] = {}
        for n in data["nodes"]:
            types[n["type"]] = types.get(n["type"], 0) + 1
        return {
            "nodes": len(data["nodes"]),
            "edges": len(data["edges"]),
            "by_type": types,
        }

    # ── Phase-7: NetworkX view + attack-graph writers ──────────────

    def snapshot(self) -> dict[str, Any]:
        """Locked read of the full {nodes, edges, version} payload."""
        with self._lock():
            return self._read_locked()

    def as_networkx(self):
        """Return a read-only NetworkX MultiDiGraph view of the KG.

        Optional dependency — ``networkx`` is not required by the
        rest of the pipeline. Raises ``RuntimeError`` if not installed
        so the caller can surface a clean error instead of an opaque
        ImportError.
        """
        try:
            import networkx as nx  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "networkx is not installed. `pip install networkx` "
                "to use the attack-graph view."
            ) from e
        data = self.snapshot()
        g = nx.MultiDiGraph()
        for node in data.get("nodes", []):
            g.add_node(
                node["id"],
                type=node.get("type", ""),
                **(node.get("properties") or {}),
            )
        for edge in data.get("edges", []):
            g.add_edge(
                edge["src"],
                edge["dst"],
                key=edge.get("relation"),
                relation=edge.get("relation", ""),
                **(edge.get("properties") or {}),
            )
        return g

    def add_defense_action(
        self,
        *,
        action_id: str,
        title: str,
        finding_ids: list[str],
        root_cause: str = "",
        patch: str = "",
        detection: str = "",
        hardening: str = "",
    ) -> None:
        """Phase-7: append a DefenseAction node + MITIGATES/RESPONDS_TO
        edges back to each ``finding_id``.

        The node id is namespaced ``defense:<action_id>`` to avoid
        colliding with finding/host ids. Edges use the EdgeType
        vocabulary (mitigates + responds_to — both relations are
        useful when querying the graph for ``what defended us against X``
        vs ``what was triggered by X``).
        """
        node_id = f"defense:{action_id}"
        self.add_node(KGNode(
            id=node_id,
            type=NodeType.DEFENSE_ACTION,
            properties={
                "title": title,
                "root_cause": root_cause,
                "patch": patch,
                "detection": detection,
                "hardening": hardening,
                "finding_ids": list(finding_ids),
            },
        ))
        for fid in finding_ids:
            finding_node = f"finding:{fid}"
            # Ensure the finding node exists so downstream queries
            # don't drop the edge — emit a stub with type=finding.
            self.add_node(KGNode(
                id=finding_node,
                type=NodeType.FINDING,
                properties={"finding_id": fid},
            ))
            self.add_edge(KGEdge(
                src=node_id, dst=finding_node,
                relation=EdgeType.MITIGATES,
            ))
            self.add_edge(KGEdge(
                src=node_id, dst=finding_node,
                relation=EdgeType.RESPONDS_TO,
            ))

    def add_verification(
        self,
        *,
        action_id: str,
        finding_id: str,
        verified: bool,
        notes: str = "",
    ) -> None:
        """Phase-7: emit a VERIFIED edge when the verifier re-attack-checks
        a defense and confirms the original vuln is now blocked.

        ``verified=False`` still records the edge (with a ``verified``
        property=False) so reports can show *attempted* mitigations that
        didn't hold up against re-attack.
        """
        self.add_edge(KGEdge(
            src=f"defense:{action_id}",
            dst=f"finding:{finding_id}",
            relation=EdgeType.VERIFIED,
            properties={"verified": bool(verified), "notes": notes},
        ))


# ── Findings (append-only) ─────────────────────────────────────────


class FindingsLog:
    """Append-only JSONL findings log. No KG lock needed.

    Phase-4: when an ``EvidenceChain`` is attached via ``attach_chain``,
    every appended line is HMAC-signed (when a key is present) and a
    Merkle leaf is added. Operates transparently — readers that ignore
    the trailing ``\\t__sig__=...`` see plain JSON unchanged.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._counter_lock_path = str(self._path) + ".idlock"
        self._chain = None  # set via attach_chain() (avoids circular import)
        self._hmac_key = None

    def attach_chain(self, chain, *, hmac_key: bytes | None = None) -> None:
        """Attach an EvidenceChain (and optional HMAC key) for audit."""
        self._chain = chain
        self._hmac_key = hmac_key

    def next_id(self) -> str:
        """Sequential FIND-NNN id. Cross-process safe via filelock.

        If the lock can't be acquired within ``LOCK_TIMEOUT`` (contention
        or a stale lockfile), fall back to a timestamp-suffixed id so the
        caller still gets a unique value rather than crashing the agent
        iteration. Duplicate avoidance is best-effort under contention.
        """
        try:
            with FileLock(self._counter_lock_path, timeout=LOCK_TIMEOUT):
                count = 0
                if self._path.exists():
                    with open(self._path, "rb") as f:
                        count = sum(1 for _ in f)
                return f"FIND-{count + 1:03d}"
        except FileLockTimeout:
            from datetime import datetime, timezone
            suffix = datetime.now(timezone.utc).strftime("%H%M%S%f")
            log.warning("findings lock timeout; falling back to FIND-T%s", suffix)
            return f"FIND-T{suffix}"

    def rewrite_all(self, items: list) -> None:
        """Atomic rewrite of findings.jsonl preserving HMAC signatures.

        Bug-fix: Phase-3 analyst tools and Phase-4 detection_ingest
        previously rewrote the file with plain ``model_dump_json``
        which silently wiped every HMAC signature and broke the
        evidence chain on the next ``verify-evidence`` run. Routing
        every rewrite through this method guarantees that:

        1. Each line is re-signed when ``self._hmac_key`` is set.
        2. Tmp + os.replace is used so a crash mid-write cannot
           leave the file half-truncated.
        3. The leaves list in the EvidenceChain is NOT touched —
           rewrites preserve existing leaves; only NEW lines (e.g.
           critic-modified findings) are also re-leaved by the
           caller if needed.

        ``items`` is a list of Pydantic models with ``model_dump_json``.
        """
        import os as _os

        # Build the lines first so a failed sign / serialise doesn't
        # produce a half-rewritten file.
        try:
            from network_pipeline.core.evidence_chain import sign_finding_line
        except ImportError:  # pragma: no cover - audit module missing
            sign_finding_line = None  # type: ignore[assignment]

        lines: list[str] = []
        for item in items:
            body = item.model_dump_json()
            if self._hmac_key is not None and sign_finding_line is not None:
                try:
                    lines.append(sign_finding_line(self._hmac_key, body))
                except Exception as e:  # pragma: no cover - audit-only
                    log.warning("rewrite_all sign failed (line unsigned): %r", e)
                    lines.append(body + "\n")
            else:
                lines.append(body + "\n")

        tmp = self._path.with_suffix(".jsonl.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.writelines(lines)
        _os.replace(tmp, self._path)

    @staticmethod
    def _strip_signature(line: str) -> str:
        """Drop the trailing ``\\t__sig__=...`` HMAC suffix if present.

        Phase-4 signed lines are appended as ``<json>\\t__sig__=<hex>``
        so plain JSON parsers still work after a slice. Reading helpers
        canonicalise to body-only before json.loads.
        """
        if "\t__sig__=" in line:
            return line.split("\t__sig__=", 1)[0]
        return line

    def snapshot_ids(self) -> list[str]:
        """Return the current ordered list of finding ids.

        Taken under the counter lock so the caller gets a consistent
        before/after sample across an iteration, instead of racing with
        concurrent appends. Safe to call frequently — it only reads the
        JSONL and pulls the ``id`` field.
        """
        if not self._path.exists():
            return []
        try:
            with FileLock(self._counter_lock_path, timeout=LOCK_TIMEOUT):
                ids: list[str] = []
                with open(self._path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = self._strip_signature(line.strip())
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        fid = obj.get("id")
                        if fid:
                            ids.append(fid)
                return ids
        except FileLockTimeout:
            log.warning("snapshot_ids lock timeout; returning best-effort")
            return []

    def append(self, finding: Finding) -> None:
        # POSIX O_APPEND makes single-line writes atomic; no lock needed
        # for the line write itself.
        body = finding.model_dump_json()
        # Phase-4 HMAC sign when a key is present. The signed line is
        # still parseable as plain JSON when sliced before ``\t``.
        if self._hmac_key is not None:
            try:
                from network_pipeline.core.evidence_chain import sign_finding_line
                line = sign_finding_line(self._hmac_key, body)
            except Exception as e:  # pragma: no cover - audit-only
                log.warning("HMAC sign failed (writing unsigned): %r", e)
                line = body + "\n"
        else:
            line = body + "\n"
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line)
        # Phase-4 Merkle leaf — leaf hash is over the BODY (not the
        # signature) so a key rotation never invalidates the root.
        if self._chain is not None:
            try:
                self._chain.add_finding_leaf(body, finding_path=self._path)
            except Exception as e:  # pragma: no cover - audit-only
                log.warning("evidence_chain.add_finding_leaf failed: %r", e)
        log.info("finding logged: %s [%s] %s",
                 finding.id, finding.severity, finding.title)

    def all(self) -> list[Finding]:
        if not self._path.exists():
            return []
        out: list[Finding] = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = self._strip_signature(line.strip())
                if not line:
                    continue
                try:
                    out.append(Finding.model_validate_json(line))
                except Exception as e:
                    log.warning("skipping malformed finding line: %s", e)
        return out


# ── Ingestion helpers ──────────────────────────────────────────────


def ingest_nmap_xml(kg: KnowledgeGraph, xml_path: Path) -> dict[str, int]:
    """Parse an nmap XML file and add hosts/ports/services to the KG."""
    try:
        from libnmap.parser import NmapParser  # type: ignore[import-not-found]
    except ImportError:
        log.warning("python-libnmap not installed; skipping nmap ingest")
        return {"hosts": 0, "ports": 0}
    report = NmapParser.parse_fromfile(str(xml_path))
    hosts_added = 0
    ports_added = 0
    nodes: list[KGNode] = []
    edges: list[KGEdge] = []
    for host in report.hosts:
        host_id = f"host:{host.address}"
        nodes.append(KGNode(id=host_id, type="host", properties={"address": host.address}))
        hosts_added += 1
        for svc in host.services:
            port_id = f"port:{host.address}:{svc.port}/{svc.protocol}"
            nodes.append(
                KGNode(
                    id=port_id,
                    type="port",
                    properties={
                        "host": host.address,
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "state": svc.state,
                        "service": svc.service,
                        "banner": svc.banner,
                    },
                )
            )
            edges.append(KGEdge(src=host_id, dst=port_id, relation="exposes"))
            ports_added += 1
    kg.add_nodes(nodes)
    for e in edges:
        kg.add_edge(e)
    return {"hosts": hosts_added, "ports": ports_added}


def ingest_nuclei_jsonl(kg: KnowledgeGraph, path: Path) -> dict[str, int]:
    """Parse a nuclei JSONL file; add vulnerability nodes linked to host/port."""
    path = Path(path)
    count = 0
    errors = 0
    if not path.exists():
        return {"vulnerabilities": 0, "errors": 0}
    nodes: list[KGNode] = []
    edges: list[KGEdge] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    info = obj.get("info", {}) or {}
                    tmpl = obj.get("template-id") or obj.get("templateID") or "unknown"
                    sev = info.get("severity", "unknown")
                    matched = obj.get("matched-at") or obj.get("matched") or ""
                    host = obj.get("host", "") or matched
                    vuln_id = f"vuln:{tmpl}@{matched or host}"
                    nodes.append(
                        KGNode(
                            id=vuln_id,
                            type="vulnerability",
                            properties={
                                "template_id": tmpl,
                                "severity": sev,
                                "matched_at": matched,
                                "info": info,
                            },
                        )
                    )
                    if host:
                        host_id = f"host:{host.split('://', 1)[-1].split('/', 1)[0].split(':', 1)[0]}"
                        nodes.append(KGNode(id=host_id, type="host", properties={}))
                        edges.append(
                            KGEdge(src=vuln_id, dst=host_id, relation="FOUND_ON")
                        )
                    count += 1
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    errors += 1
                    log.warning("ingest_nuclei_jsonl: bad line: %s", e)
        if nodes:
            kg.add_nodes(nodes)
        for e in edges:
            kg.add_edge(e)
    except OSError as e:
        log.warning("ingest_nuclei_jsonl failed: %s", e)
    return {"vulnerabilities": count, "errors": errors}


def ingest_subfinder(kg: KnowledgeGraph, path: Path) -> dict[str, int]:
    """Read newline-delimited hosts from subfinder output; add host nodes."""
    path = Path(path)
    if not path.exists():
        return {"hosts": 0}
    added = 0
    nodes: list[KGNode] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            h = line.strip()
            if not h:
                continue
            nodes.append(
                KGNode(
                    id=f"host:{h}",
                    type="host",
                    properties={"source": "subfinder", "hostname": h},
                )
            )
            added += 1
        if nodes:
            kg.add_nodes(nodes)
    except OSError as e:
        log.warning("ingest_subfinder failed: %s", e)
    return {"hosts": added}


def ingest_httpx_jsonl(kg: KnowledgeGraph, path: Path) -> dict[str, int]:
    """Parse httpx JSONL; create/update host node + http_service edge."""
    path = Path(path)
    if not path.exists():
        return {"hosts": 0, "errors": 0}
    count = 0
    errors = 0
    nodes: list[KGNode] = []
    edges: list[KGEdge] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    host = (
                        obj.get("host")
                        or obj.get("input")
                        or obj.get("url")
                        or ""
                    )
                    host_clean = (
                        host.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                    )
                    if not host_clean:
                        continue
                    host_id = f"host:{host_clean}"
                    svc_id = f"http:{obj.get('url', host)}"
                    nodes.append(
                        KGNode(
                            id=host_id,
                            type="host",
                            properties={"hostname": host_clean},
                        )
                    )
                    nodes.append(
                        KGNode(
                            id=svc_id,
                            type="http_service",
                            properties={
                                "url": obj.get("url", ""),
                                "status_code": obj.get("status_code"),
                                "title": obj.get("title", ""),
                                "tech": obj.get("tech") or obj.get("technologies") or [],
                            },
                        )
                    )
                    edges.append(KGEdge(src=host_id, dst=svc_id, relation="http_service"))
                    count += 1
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    errors += 1
                    log.warning("ingest_httpx_jsonl: bad line: %s", e)
        if nodes:
            kg.add_nodes(nodes)
        for e in edges:
            kg.add_edge(e)
    except OSError as e:
        log.warning("ingest_httpx_jsonl failed: %s", e)
    return {"hosts": count, "errors": errors}


def ingest_dnsx_jsonl(kg: KnowledgeGraph, path: Path) -> dict[str, int]:
    """Parse a dnsx JSONL file; add DNS record nodes linked to host."""
    path = Path(path)
    if not path.exists():
        return {"records": 0, "errors": 0}
    count = 0
    errors = 0
    nodes: list[KGNode] = []
    edges: list[KGEdge] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    host = obj.get("host") or obj.get("name") or ""
                    if not host:
                        continue
                    host_id = f"host:{host}"
                    nodes.append(KGNode(id=host_id, type="host", properties={"hostname": host}))
                    # dnsx emits per-record-type arrays like {"a": [...], "aaaa": [...]}
                    for rtype in ("a", "aaaa", "cname", "mx", "ns", "txt", "ptr", "soa"):
                        for val in obj.get(rtype, []) or []:
                            rec_id = f"dns:{rtype}:{host}:{val}"
                            nodes.append(
                                KGNode(
                                    id=rec_id,
                                    type="dns_record",
                                    properties={"record_type": rtype.upper(), "value": val, "host": host},
                                )
                            )
                            edges.append(KGEdge(src=host_id, dst=rec_id, relation="has_dns"))
                            count += 1
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    errors += 1
                    log.warning("ingest_dnsx_jsonl: bad line: %s", e)
        if nodes:
            kg.add_nodes(nodes)
        for e in edges:
            kg.add_edge(e)
    except OSError as e:
        log.warning("ingest_dnsx_jsonl failed: %s", e)
    return {"records": count, "errors": errors}


def ingest_masscan(kg: KnowledgeGraph, path: Path) -> dict[str, int]:
    """Parse masscan list-format output; add port nodes.

    Masscan list format line looks like:
        open tcp 443 1.2.3.4 1712345678
    """
    path = Path(path)
    if not path.exists():
        return {"ports": 0, "errors": 0}
    count = 0
    errors = 0
    nodes: list[KGNode] = []
    edges: list[KGEdge] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                parts = line.split()
                if len(parts) < 4:
                    continue
                # state proto port host [ts]
                state, proto, port, host = parts[0], parts[1], parts[2], parts[3]
                host_id = f"host:{host}"
                port_id = f"port:{host}:{port}/{proto}"
                nodes.append(KGNode(id=host_id, type="host", properties={"address": host}))
                nodes.append(
                    KGNode(
                        id=port_id,
                        type="port",
                        properties={
                            "host": host,
                            "port": int(port),
                            "protocol": proto,
                            "state": state,
                            "source": "masscan",
                        },
                    )
                )
                edges.append(KGEdge(src=host_id, dst=port_id, relation="exposes"))
                count += 1
            except (ValueError, IndexError) as e:
                errors += 1
                log.warning("ingest_masscan: bad line %r: %s", line, e)
        if nodes:
            kg.add_nodes(nodes)
        for e in edges:
            kg.add_edge(e)
    except OSError as e:
        log.warning("ingest_masscan failed: %s", e)
    return {"ports": count, "errors": errors}


# Expose the new ingest helpers as bound methods on KnowledgeGraph so
# agents can call ``kg.ingest_nuclei_jsonl(path)`` directly.
KnowledgeGraph.ingest_nmap_xml = lambda self, path: ingest_nmap_xml(self, Path(path))  # type: ignore[assignment]
KnowledgeGraph.ingest_nuclei_jsonl = lambda self, path: ingest_nuclei_jsonl(self, Path(path))  # type: ignore[assignment]
KnowledgeGraph.ingest_subfinder = lambda self, path: ingest_subfinder(self, Path(path))  # type: ignore[assignment]
KnowledgeGraph.ingest_httpx_jsonl = lambda self, path: ingest_httpx_jsonl(self, Path(path))  # type: ignore[assignment]
KnowledgeGraph.ingest_dnsx_jsonl = lambda self, path: ingest_dnsx_jsonl(self, Path(path))  # type: ignore[assignment]
KnowledgeGraph.ingest_masscan = lambda self, path: ingest_masscan(self, Path(path))  # type: ignore[assignment]
