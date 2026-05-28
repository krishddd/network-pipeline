"""Differential scanning (Plan B.1.4).

Late-stage engagements re-scan the same targets and burn iterations on
results the orchestrator already has. ``DiffScan`` tracks per-(target,
scan_type) content hashes as ``scan_artifact`` KG nodes — on a
re-scan, the helper returns ONLY the delta (new ports / removed
services / changed banners) plus a ``"since-baseline"`` preamble.

Hash is over the **parsed** structured output (post-output_schemas), so
trivial timestamp churn in raw stdout doesn't trigger a false delta.

Usage:

    diff = DiffScan(kg)
    payload, baseline = diff.compare_payload(
        target="example.com",
        scan_type="httpx",
        parsed_payload=httpx_lines_as_dicts,
    )
    if baseline is None:
        # First scan — store and return full payload
        return full_summary
    if payload is None:
        # No change since baseline — short-circuit
        return f"httpx unchanged since {baseline['ts']}"
    return f"httpx delta:\\n{render(payload)}"

The actual wrapper integration is opt-in (Phase-2 wrappers can call
this; we don't force it via shared base because the wrappers vary in
output shape).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from network_pipeline.core.logging import get_logger
from network_pipeline.tools.kg import KGNode, KnowledgeGraph

log = get_logger("core.diff_scan")


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(payload: Any) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class DiffScan:
    """Per-(target, scan_type) baseline tracker stored as KG nodes."""

    def __init__(self, kg: KnowledgeGraph) -> None:
        self._kg = kg

    @staticmethod
    def _node_id(target: str, scan_type: str) -> str:
        # KG node ids are free-form strings; namespace by prefix.
        return f"scan_artifact:{scan_type}:{target.lower()}"

    def get_baseline(
        self, target: str, scan_type: str,
    ) -> dict[str, Any] | None:
        """Return the most recent stored baseline payload, or None.

        Baselines live as ``scan_artifact`` nodes with these properties:

            target, scan_type, ts, hash, summary (1-line text),
            payload (canonical JSON of the parsed structure)
        """
        node_id = self._node_id(target, scan_type)
        nodes = self._kg.query("scan_artifact")
        for n in nodes:
            if n.get("id") == node_id:
                props = n.get("properties") or {}
                payload_raw = props.get("payload")
                if isinstance(payload_raw, str):
                    try:
                        payload = json.loads(payload_raw)
                    except json.JSONDecodeError:
                        payload = None
                else:
                    payload = payload_raw
                return {
                    "ts": props.get("ts", ""),
                    "hash": props.get("hash", ""),
                    "summary": props.get("summary", ""),
                    "payload": payload,
                }
        return None

    def store_baseline(
        self,
        *,
        target: str,
        scan_type: str,
        parsed_payload: Any,
        summary: str = "",
    ) -> str:
        """Persist or refresh the baseline. Returns the hash digest."""
        digest = _hash_payload(parsed_payload)
        ts = datetime.now(timezone.utc).isoformat()
        self._kg.add_node(KGNode(
            id=self._node_id(target, scan_type),
            type="scan_artifact",
            properties={
                "target": target,
                "scan_type": scan_type,
                "ts": ts,
                "hash": digest,
                "summary": summary,
                "payload": _canonical_json(parsed_payload),
            },
        ))
        return digest

    def compare_payload(
        self,
        *,
        target: str,
        scan_type: str,
        parsed_payload: Any,
    ) -> tuple[Any | None, dict[str, Any] | None]:
        """Compare ``parsed_payload`` against the stored baseline.

        Returns ``(delta_or_None, baseline_or_None)``:

        * ``baseline`` is None on the very first scan ⇒ caller should
          ``store_baseline`` and return the full summary.
        * ``delta`` is None when the payload hash is unchanged ⇒ caller
          can short-circuit with "unchanged since {baseline.ts}".
        * Otherwise ``delta`` is a structured diff (added / removed /
          changed lists for list payloads; full payload for dicts).
        """
        baseline = self.get_baseline(target, scan_type)
        new_hash = _hash_payload(parsed_payload)
        if baseline is None:
            return parsed_payload, None
        if baseline["hash"] == new_hash:
            return None, baseline
        # Hash differs — compute structural delta + refresh baseline.
        delta = _structural_delta(baseline.get("payload"), parsed_payload)
        # Refresh baseline so the NEXT scan diffs against this one.
        self.store_baseline(
            target=target, scan_type=scan_type,
            parsed_payload=parsed_payload,
            summary=baseline.get("summary", ""),
        )
        return delta, baseline


def _structural_delta(old: Any, new: Any) -> dict[str, Any]:
    """Best-effort structural diff for the common payload shapes.

    Lists of dicts (httpx / nuclei style) → keyed by ``url`` or
    ``template-id`` when present, falling back to the canonical hash
    of the dict. Lists of scalars → set diff. Dicts → key-level diff.
    Anything else → return ``new`` wholesale.
    """
    if isinstance(old, list) and isinstance(new, list):
        return _list_delta(old, new)
    if isinstance(old, dict) and isinstance(new, dict):
        added = {k: v for k, v in new.items() if k not in old}
        removed = {k: v for k, v in old.items() if k not in new}
        changed = {
            k: {"old": old[k], "new": new[k]}
            for k in old.keys() & new.keys() if old[k] != new[k]
        }
        return {"added": added, "removed": removed, "changed": changed}
    return {"new": new}


def _list_delta(old: list, new: list) -> dict[str, Any]:
    def _key(item: Any) -> str:
        if isinstance(item, dict):
            for cand in ("url", "host", "template-id", "id", "address"):
                if item.get(cand):
                    return f"{cand}={item[cand]}"
            return _hash_payload(item)[:16]
        return str(item)

    old_idx = {_key(i): i for i in old}
    new_idx = {_key(i): i for i in new}
    added = [v for k, v in new_idx.items() if k not in old_idx]
    removed = [v for k, v in old_idx.items() if k not in new_idx]
    changed = [
        {"key": k, "old": old_idx[k], "new": new_idx[k]}
        for k in old_idx.keys() & new_idx.keys() if old_idx[k] != new_idx[k]
    ]
    return {"added": added, "removed": removed, "changed": changed}


__all__ = ["DiffScan"]
