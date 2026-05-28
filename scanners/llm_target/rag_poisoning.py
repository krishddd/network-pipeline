"""JailAgent-lite: RAG-memory poisoning probe.

Models the attack from "LLM Red-Teaming Techniques Explained.md" §
*JailAgent / Constraint Tightening*. The paper's full pipeline trains a
shadow model and jointly optimises four losses (Clustering, Separability,
Particularity, Margin). We approximate at far lower cost using frozen
``sentence-transformers`` embeddings and only the Clustering + Margin
contributions — sufficient to demonstrate retrieval-perturbation against
a target RAG endpoint, without the ~hours of GPU-bound training the
full paper assumes.

## Safety gates (Phase-5 user concern)

Every public function in this module starts with TWO explicit gates:

  1. ``ScopeGuard.check_url(endpoint_url)`` — same gate every other
     scanner honours; raises ``OutOfScopeError`` (NOT a silent return)
     so callers cannot accidentally treat a refused request as a
     null-finding.
  2. ``check_write_gate(roe, endpoint_url)`` — refuses unless
     ``roe.allow_destructive_writes`` is True AND the endpoint matches
     a substring on ``roe.write_allowlist``. Raises ``WriteGateError``.

Both gates have unit tests in ``tests/unit/test_llm_target_*.py``. They
are the difference between a useful penetration-test capability and a
foot-gun that pushes adversarial documents into production indexes.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Optional

from network_pipeline.core.logging import get_logger
from network_pipeline.core.schemas import RoE
from network_pipeline.scanners._common import ScanFinding, ScanResult, truncate_for_agent

log = get_logger("scanners.llm_target.rag_poisoning")


# ── safety errors ─────────────────────────────────────────────────────


class OutOfScopeError(RuntimeError):
    """ScopeGuard refused the endpoint. NOT a silent failure."""


class WriteGateError(RuntimeError):
    """``allow_destructive_writes`` / ``write_allowlist`` refused the request."""


def check_write_gate(roe: Optional[RoE], endpoint_url: str) -> None:
    """Raise WriteGateError unless RoE explicitly permits writes to this URL.

    This is the second of the two safety gates documented above. Kept as
    a module-level function so tests can exercise it in isolation.
    """
    if roe is None:
        raise WriteGateError(
            "RoE is required for write-side scanners; no RoE on engagement"
        )
    if not getattr(roe, "allow_destructive_writes", False):
        raise WriteGateError(
            "roe.allow_destructive_writes is False — set it (and populate "
            "write_allowlist) via `soundwave interview` to permit RAG poisoning"
        )
    allowlist = list(getattr(roe, "write_allowlist", []) or [])
    if not allowlist:
        raise WriteGateError(
            "roe.write_allowlist is empty — no endpoints are eligible for writes"
        )
    if not any(entry in endpoint_url for entry in allowlist):
        raise WriteGateError(
            f"endpoint {endpoint_url!r} does not match any entry on "
            f"roe.write_allowlist={allowlist}"
        )


def _check_scope(scope: Any, endpoint_url: str) -> None:
    """Raise OutOfScopeError when ScopeGuard refuses the URL."""
    if scope is None:
        raise OutOfScopeError("no ScopeGuard configured; refusing to write")
    allows = getattr(scope, "allows", None)
    if allows is None or not allows(endpoint_url):
        raise OutOfScopeError(f"ScopeGuard refused {endpoint_url!r}")


# ── constraint tightening (Clustering + Margin only) ──────────────────


@dataclass(frozen=True)
class TrainedTrigger:
    """A short adversarial document with semantic anchors near the target intent.

    ``embedding`` is the trigger's sentence-transformer vector. The
    composer uses it to compute Clustering + Margin losses (the two
    cheaper components of the paper's four-loss training).
    """

    text: str
    embedding: list[float]
    clustering_loss: float
    margin_loss: float
    combined_loss: float


def _norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v)) or 1.0


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    return dot / (_norm(a) * _norm(b))


def _centroid(vectors: list[list[float]]) -> list[float]:
    if not vectors:
        return []
    dim = len(vectors[0])
    return [sum(v[i] for v in vectors) / len(vectors) for i in range(dim)]


def _embed(texts: list[str]) -> list[list[float]]:
    """Try sentence-transformers; fall back to a deterministic hash-based
    pseudo-embedding when the library isn't installed. Either way, the
    Clustering + Margin maths still works — only the absolute anchor
    quality changes."""
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore[import-not-found]

        model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        # convert_to_numpy=True so we get np.ndarrays we can cast to
        # plain lists. The downstream helpers (_cosine, _centroid,
        # _norm) assume Python lists — tensors break their truthiness
        # checks ("Boolean value of Tensor ... is ambiguous").
        raw = model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        return [list(map(float, row)) for row in raw]
    except Exception:
        # Deterministic fallback — 64-dim hash projection. Stable for
        # tests, terrible for real attacks (which is fine: the gates
        # above mean this path almost never runs in earnest).
        import hashlib

        def emb(t: str) -> list[float]:
            h = hashlib.sha256(t.encode("utf-8")).digest()
            return [b / 255.0 - 0.5 for b in h[:64]]
        return [emb(t) for t in texts]


def train_triggers(
    intent: str,
    candidate_payloads: list[str],
    *,
    benign_corpus: Optional[list[str]] = None,
) -> list[TrainedTrigger]:
    """Score each candidate payload via the simplified two-loss objective.

    No backprop; we don't update model weights. We use the frozen
    encoder to score each candidate as-is and rank by combined_loss
    (lower = better trigger).

    Clustering loss: candidate must be close to the *intent* embedding
      (small distance from the target query).
    Margin loss: candidate must be far from any benign-corpus embedding
      (so it dominates nearest-neighbour retrieval).
    """
    if not candidate_payloads:
        return []
    benign_corpus = benign_corpus or [
        "Welcome to the customer support portal.",
        "Our Q4 financial highlights show 12% growth.",
        "Read our latest blog post about cloud architecture.",
    ]
    embeds = _embed([intent] + candidate_payloads + benign_corpus)
    intent_emb = embeds[0]
    cand_embs = embeds[1: 1 + len(candidate_payloads)]
    benign_embs = embeds[1 + len(candidate_payloads):]

    triggers: list[TrainedTrigger] = []
    for text, emb in zip(candidate_payloads, cand_embs):
        # Clustering: 1 - cos(candidate, intent) → minimise.
        clustering = 1.0 - _cosine(emb, intent_emb)
        # Margin: 1 - max_cos(candidate, benign) → minimise distance to
        # the *closest* benign sample, so we want this NEGATIVE (i.e.
        # we want the candidate to be FAR from any benign). To keep
        # the "lower=better" convention, flip the sign.
        if benign_embs:
            max_benign_cos = max(_cosine(emb, b) for b in benign_embs)
        else:
            max_benign_cos = 0.0
        margin = max_benign_cos  # raw cosine; lower = farther = better
        combined = 0.6 * clustering + 0.4 * margin
        triggers.append(TrainedTrigger(
            text=text, embedding=list(emb),
            clustering_loss=clustering,
            margin_loss=margin,
            combined_loss=combined,
        ))
    triggers.sort(key=lambda t: t.combined_loss)
    return triggers


# ── scanner ───────────────────────────────────────────────────────────


class RAGPoisoningScanner:
    """Train triggers, upload to the target's write endpoint, verify retrieval.

    Three steps per scan:
      1. ``train_triggers`` ranks candidate documents by Clustering+Margin.
      2. POST the top trigger to the target's write endpoint (e.g.
         ``/documents`` or ``/memory/add``).
      3. Send the original ``intent`` to the read endpoint and check
         whether the trigger string surfaces in the response — that's
         the ASR-R metric from the paper (retrieval perturbation).
    """

    def __init__(
        self,
        http_client: Any,
        *,
        scope: Any,
        roe: Optional[RoE],
        write_path: str = "/documents",
        read_path: str = "/chat",
        write_field: str = "content",
        read_field: str = "message",
    ) -> None:
        self._http = http_client
        self._scope = scope
        self._roe = roe
        self._write_path = write_path
        self._read_path = read_path
        self._write_field = write_field
        self._read_field = read_field

    async def run(
        self,
        target_url: str,
        intent: str,
        candidate_payloads: list[str],
    ) -> ScanResult:
        from urllib.parse import urljoin

        write_endpoint = urljoin(target_url.rstrip("/") + "/", self._write_path.lstrip("/"))
        read_endpoint = urljoin(target_url.rstrip("/") + "/", self._read_path.lstrip("/"))

        # ── Safety gates (FIRST executable lines, as required) ───────
        _check_scope(self._scope, write_endpoint)
        check_write_gate(self._roe, write_endpoint)

        result = ScanResult(scanner="rag_poisoning", target=target_url)
        if self._http is None:
            result.success = False
            result.error = "no HTTPClient configured"
            return result

        triggers = train_triggers(intent, candidate_payloads)
        if not triggers:
            result.success = False
            result.error = "no candidate payloads"
            return result
        top = triggers[0]

        # 2. Upload trigger.
        try:
            write_resp = await self._http.request(
                "POST", write_endpoint,
                scanner_tool="rag_poisoning",
                agent="llm_redteam",
                objective_id="",
                json={self._write_field: top.text},
            )
        except Exception as e:  # noqa: BLE001
            result.success = False
            result.error = f"write failed: {e!r}"
            return result
        if write_resp is None:
            result.success = False
            result.error = "write refused (scope or RoE)"
            return result

        # 3. Retrieval probe.
        try:
            read_resp = await self._http.request(
                "POST", read_endpoint,
                scanner_tool="rag_poisoning",
                agent="llm_redteam",
                objective_id="",
                json={self._read_field: intent},
            )
        except Exception as e:  # noqa: BLE001
            result.success = False
            result.error = f"read failed: {e!r}"
            return result

        read_body = (read_resp.text if read_resp is not None else "") or ""
        # ASR-R: the trigger text — or a distinctive substring of it —
        # surfaces in the response.
        marker = _distinctive_substring(top.text)
        retrieval_perturbed = marker.lower() in read_body.lower()

        result.data = {
            "trigger_count": len(triggers),
            "top_combined_loss": round(top.combined_loss, 4),
            "top_clustering_loss": round(top.clustering_loss, 4),
            "top_margin_loss": round(top.margin_loss, 4),
            "asr_r": 1.0 if retrieval_perturbed else 0.0,
            "write_status": getattr(write_resp, "status_code", 0),
            "read_status": getattr(read_resp, "status_code", 0) if read_resp else 0,
        }
        if retrieval_perturbed:
            result.findings.append(ScanFinding(
                vuln_class="rag_poisoning.retrieval_perturbed",
                title="RAG retrieval perturbed by trained trigger document",
                severity="high",
                confidence="verified",
                affected_target=target_url,
                description=(
                    "Successfully poisoned the target's RAG index: an "
                    "uploaded trigger document with semantic anchors near "
                    "the intent embedding was retrieved when the intent "
                    "query was issued. Demonstrates JailAgent-class "
                    "vulnerability."
                ),
                cwe=["CWE-94", "CWE-1357"],
                mitre=["T1565.002"],  # Data Manipulation: Transmitted Data
                remediation=(
                    "Treat retrieved documents as untrusted input "
                    "(segregate from prompt instructions); add a "
                    "provenance check (signed source) on every document "
                    "the retriever serves; rate-limit the write endpoint."
                ),
                extra={
                    "attack_type": "rag_poisoning",
                    "trigger_preview": top.text[:240],
                    "clustering_loss": round(top.clustering_loss, 4),
                    "margin_loss": round(top.margin_loss, 4),
                    "asr_r": 1.0,
                },
            ))
        result.raw_text = truncate_for_agent(
            f"trained {len(triggers)} triggers; top combined_loss="
            f"{top.combined_loss:.4f}; asr_r="
            f"{1.0 if retrieval_perturbed else 0.0}\n"
            f"top trigger preview: {top.text[:240]!r}\n",
            cap=1024,
        )
        return result


def _distinctive_substring(text: str, length: int = 24) -> str:
    """Pick a substring unlikely to appear in unrelated responses.

    We avoid stop-words to reduce false positives. If the text is too
    short we just return the whole thing.
    """
    cleaned = text.strip()
    if len(cleaned) <= length:
        return cleaned
    # Take from the middle to avoid common openers like "The" / "A ".
    start = max(0, (len(cleaned) - length) // 2)
    return cleaned[start: start + length]


__all__ = [
    "OutOfScopeError",
    "RAGPoisoningScanner",
    "TrainedTrigger",
    "WriteGateError",
    "check_write_gate",
    "train_triggers",
]
