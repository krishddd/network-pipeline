"""Cross-engagement RAG memory (Plan B.1.5).

After every COMPLETE engagement, findings + KG summaries are embedded
via the local Ollama ``nomic-embed-text`` model and persisted to a JSON
index file. At the start of a new engagement, the orchestrator queries
``recall(target_signature)`` and gets back the top-k semantically
similar prior findings — used to seed OPPLAN with "this kind of target
historically had these classes of issues".

Strictly local, no egress: embeddings are produced by the same Ollama
server the engagement uses; the index file lives wherever the operator
points ``--rag-index``.

Storage format (JSON, one file): ``{"items": [{"text": "...", "vec":
[...], "meta": {...}}]}``. Atomic write via tmp + replace. We
deliberately avoid pulling in chromadb / lancedb to keep the [network]
extra small — for ≤10k items this is fast enough.

Cosine similarity is computed manually (numpy when available; pure-
python fallback) so the [network] extra remains optional on
``numpy``.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from network_pipeline.core.logging import get_logger

log = get_logger("core.rag_memory")


_OLLAMA_EMBED_MODEL = "nomic-embed-text"


# ── Embedding client (synchronous; uses httpx that's already a dep) ──


def _embed(text: str, *, base_url: str) -> list[float]:
    """Call ``POST /api/embeddings`` on the Ollama server.

    Returns the float vector. Raises on any HTTP / JSON error so the
    caller can decide between "RAG is best-effort, log + skip" and a
    fatal abort.
    """
    import httpx

    payload = {"model": _OLLAMA_EMBED_MODEL, "prompt": text}
    resp = httpx.post(
        f"{base_url.rstrip('/')}/api/embeddings",
        json=payload, timeout=30.0,
    )
    resp.raise_for_status()
    data = resp.json()
    vec = data.get("embedding") or []
    if not vec:
        raise ValueError("Ollama embeddings returned empty vector")
    return [float(x) for x in vec]


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity in [-1, 1]. Uses numpy when available."""
    try:
        import numpy as np  # type: ignore[import-not-found]
        va = np.asarray(a, dtype="float32")
        vb = np.asarray(b, dtype="float32")
        denom = float(np.linalg.norm(va) * np.linalg.norm(vb))
        if denom == 0:
            return 0.0
        return float(np.dot(va, vb) / denom)
    except ImportError:  # pragma: no cover - fallback
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(x * x for x in b))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)


# ── Index entry ──────────────────────────────────────────────────────


@dataclass
class RAGItem:
    text: str
    vec: list[float]
    meta: dict[str, Any] = field(default_factory=dict)


# ── Store ────────────────────────────────────────────────────────────


@dataclass
class CrossEngagementRAG:
    """Local-only RAG store keyed by free-form text + metadata.

    Created with ``--rag-index <path>``; if the file doesn't exist on
    first read it's treated as empty. ``add`` appends + persists; the
    file is fully rewritten via tmp + replace so a crash mid-write is
    safe.
    """

    index_path: Path
    base_url: str = "http://localhost:11434"
    items: list[RAGItem] = field(default_factory=list)
    _loaded: bool = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.index_path.exists():
            return
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            log.warning("could not load RAG index %s: %r", self.index_path, e)
            return
        for it in data.get("items", []):
            try:
                self.items.append(RAGItem(
                    text=str(it.get("text", "")),
                    vec=[float(x) for x in (it.get("vec") or [])],
                    meta=dict(it.get("meta") or {}),
                ))
            except Exception:
                continue

    def _persist(self) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"items": [
            {"text": it.text, "vec": it.vec, "meta": it.meta}
            for it in self.items
        ]}
        tmp = self.index_path.with_suffix(self.index_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, self.index_path)

    # ── public API ────────────────────────────────────────────────

    def add(self, text: str, *, meta: dict[str, Any] | None = None) -> bool:
        """Embed + store one item. Returns False on embedding failure."""
        self._load()
        try:
            vec = _embed(text, base_url=self.base_url)
        except Exception as e:
            log.warning("RAG embed failed (skipping item): %r", e)
            return False
        self.items.append(RAGItem(text=text, vec=vec, meta=dict(meta or {})))
        self._persist()
        return True

    def recall(self, query: str, *, k: int = 5) -> list[tuple[float, RAGItem]]:
        """Return top-k items ranked by cosine similarity to ``query``.

        Empty list when the index is empty or the query embedding fails
        — RAG is opportunistic, never fatal.
        """
        self._load()
        if not self.items:
            return []
        try:
            qv = _embed(query, base_url=self.base_url)
        except Exception as e:
            log.warning("RAG query embed failed: %r", e)
            return []
        scored = [(_cosine(qv, it.vec), it) for it in self.items]
        scored.sort(key=lambda t: t[0], reverse=True)
        return scored[:max(1, k)]

    def absorb_engagement(
        self, *, findings: list, kg_summary: str, target_signature: str,
        engagement_id: str,
    ) -> int:
        """Embed every finding (+ a KG summary record) at engagement end.

        Each finding becomes one item with ``meta.engagement_id`` so a
        future operator can audit where a recalled item came from.
        Returns count of items successfully added.
        """
        added = 0
        # KG summary entry
        if kg_summary:
            if self.add(
                f"[KG summary] {target_signature}\n{kg_summary}",
                meta={
                    "kind": "kg_summary",
                    "engagement_id": engagement_id,
                    "target_signature": target_signature,
                },
            ):
                added += 1
        for f in findings:
            text = (
                f"[{getattr(f, 'severity', '?')}] {getattr(f, 'title', '')}\n"
                f"target={getattr(f, 'affected_target', '')}\n"
                f"description={getattr(f, 'description', '')[:600]}\n"
                f"verified_methods={getattr(f, 'verified_methods', [])}"
            )
            ok = self.add(
                text,
                meta={
                    "kind": "finding",
                    "engagement_id": engagement_id,
                    "target_signature": target_signature,
                    "finding_id": getattr(f, "id", ""),
                    "severity": str(getattr(f, "severity", "")),
                    "cwe": list(getattr(f, "cwe", []) or []),
                    "mitre": list(getattr(f, "mitre", []) or []),
                },
            )
            if ok:
                added += 1
        log.info(
            "RAG absorb_engagement %s: %d items added (now %d total)",
            engagement_id, added, len(self.items),
        )
        return added


__all__ = ["CrossEngagementRAG", "RAGItem"]
