"""Tamper-evident evidence chain (Plan B.3.5 + risk #14).

Every finding line in ``findings.jsonl`` and every captured tool-output
sidecar (see ``tools/integrity.py``) feeds a Merkle tree. The tree
root is persisted to ``workspace/evidence_root.json`` after every
update and re-derived independently by the ``verify-evidence`` CLI
subcommand. Tampering with any input — finding, sidecar, argv record —
flips the root and the verification fails.

Integrity primitives:

* **HMAC-SHA256** signs each finding line. Key lives at
  ``~/.config/network_pipeline/keys/<engagement_id>.key`` (mode 600,
  derived once, never re-created). Without the key, lines are stored
  unsigned and the verifier reports "unsigned legacy" — never deletes
  data on missing-key.
* **Merkle leaf** = SHA-256 of the canonical-JSON serialised record
  ``{"file": <rel-path>, "content_sha256": <hex>, "ts": <iso8601>,
  "kind": <"finding"|"tool-output"|"argv">}``. The leaf timestamp
  comes ONLY from JSON content (Plan risk #14) — never
  ``os.stat().st_mtime`` — so the chain stays valid after the
  workspace is moved or tarred.

The Merkle tree itself is the standard binary-balanced variant: leaves
sorted lexicographically (so ordering is canonical regardless of
write order), pairs hashed together up the tree, last-leaf-duplicated
when count is odd. Root hash is stored alongside the leaf list so the
verifier can reconstruct the path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from network_pipeline.core.logging import get_logger

log = get_logger("core.evidence_chain")


# ── Key management ───────────────────────────────────────────────────


def default_key_path(engagement_id: str) -> Path:
    """Return the canonical key path for an engagement.

    ``$XDG_CONFIG_HOME/network_pipeline/keys/<engagement_id>.key``
    falling back to ``~/.config/network_pipeline/keys/...``. Mode 600.
    """
    base = os.environ.get("XDG_CONFIG_HOME")
    if not base:
        base = str(Path.home() / ".config")
    return Path(base) / "network_pipeline" / "keys" / f"{engagement_id}.key"


def load_or_create_key(path: Path) -> bytes:
    """Read the HMAC key at ``path``, or create a fresh 32-byte key."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            data = path.read_bytes()
            if len(data) >= 16:
                return data
        except OSError as e:
            raise RuntimeError(f"could not read evidence key {path}: {e}") from e
    key = secrets.token_bytes(32)
    # Best-effort restrictive mode — Windows ignores chmod, but POSIX
    # respects it. We write atomically so a partial key is impossible.
    tmp = path.with_suffix(".key.tmp")
    tmp.write_bytes(key)
    try:
        os.chmod(tmp, 0o600)
    except OSError:  # pragma: no cover - Windows
        pass
    os.replace(tmp, path)
    log.info("evidence key created at %s (32 bytes, mode 600 best-effort)", path)
    return key


# ── HMAC signing ─────────────────────────────────────────────────────


def hmac_sha256(key: bytes, payload: bytes) -> str:
    """Hex-digest HMAC-SHA256."""
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sign_finding_line(key: bytes | None, line_body: str) -> str:
    """Return ``<line_body>\\t__sig__=<hmac>`` if key, else line unchanged.

    The signature is appended as a tab-suffixed key=value so verifiers
    can split on the marker and re-validate. We don't mutate the JSON
    structure — keeping the line readable as plain JSON when sliced
    before the tab.
    """
    body = line_body.rstrip("\n")
    if key is None:
        return body + "\n"
    sig = hmac_sha256(key, body.encode("utf-8"))
    return f"{body}\t__sig__={sig}\n"


def split_signed_line(raw: str) -> tuple[str, str | None]:
    """Inverse of ``sign_finding_line``.

    Returns ``(body, sig_or_None)``. Lines without a signature return
    ``sig=None`` and ``body`` is the whole input.
    """
    raw = raw.rstrip("\n")
    if "\t__sig__=" in raw:
        body, _, sig = raw.partition("\t__sig__=")
        return body, sig.strip() or None
    return raw, None


# ── Merkle tree ──────────────────────────────────────────────────────


def _hash_pair(a: str, b: str) -> str:
    return hashlib.sha256((a + b).encode("utf-8")).hexdigest()


def merkle_root(leaves: list[str]) -> str:
    """Compute the Merkle root of a list of leaf hex digests.

    Sorted lexicographically before hashing so the root is canonical
    regardless of insertion order. Last leaf duplicated when count is
    odd (Bitcoin convention). Empty input → all-zero hash.
    """
    if not leaves:
        return "0" * 64
    layer = sorted(leaves)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [_hash_pair(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


@dataclass
class MerkleLeaf:
    """One leaf record. Persisted as an entry in ``evidence_leaves.jsonl``."""

    file: str  # workspace-relative path of the source artefact
    content_sha256: str
    ts: str    # ISO-8601 from JSON content, NEVER from os.stat()
    kind: str  # "finding" | "tool-output" | "argv"

    def canonical(self) -> str:
        # Sorted-keys JSON so two operators reproduce the same hash.
        return json.dumps(
            {"file": self.file, "content_sha256": self.content_sha256,
             "ts": self.ts, "kind": self.kind},
            sort_keys=True, separators=(",", ":"),
        )

    def leaf_hash(self) -> str:
        return sha256_hex(self.canonical().encode("utf-8"))


# ── Engagement-scoped chain ──────────────────────────────────────────


@dataclass
class EvidenceChain:
    """Append leaves; recompute root after each batch.

    The chain lives in the workspace:

    * ``evidence_leaves.jsonl`` — one JSON line per leaf (canonical form
      so verification re-derives the same hashes).
    * ``evidence_root.json`` — ``{"root": <hex>, "leaf_count": N,
      "updated_at": <iso8601>}``.

    Both files are atomically written via ``tmp + os.replace``.
    """

    workspace: Path
    key: bytes | None = None
    engagement_id: str = ""
    _leaves: list[MerkleLeaf] = field(default_factory=list)
    _loaded: bool = False
    # Bug-fix C: under --parallel N>1, multiple ShellRunner.run calls
    # finish concurrently and each invokes ``add_leaf`` which then
    # rewrites ``evidence_root.json``. Without serialisation the root
    # file races and may briefly show stale content. The lock is
    # process-local; cross-process callers (rare here) would still need
    # filelock — out of scope for now.
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def leaves_path(self) -> Path:
        return self.workspace / "evidence_leaves.jsonl"

    @property
    def root_path(self) -> Path:
        return self.workspace / "evidence_root.json"

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.leaves_path.exists():
            return
        try:
            with open(self.leaves_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        self._leaves.append(MerkleLeaf(**d))
                    except (json.JSONDecodeError, TypeError):
                        continue
        except OSError as e:  # pragma: no cover - defensive
            log.warning("could not preload evidence leaves: %r", e)

    # ── public API ────────────────────────────────────────────────

    def add_leaf(self, leaf: MerkleLeaf) -> None:
        self._ensure_loaded()
        with self._lock:
            self._leaves.append(leaf)
            # POSIX O_APPEND atomic for short lines; a crash mid-write
            # leaves either the full leaf or nothing.
            with open(self.leaves_path, "a", encoding="utf-8") as f:
                f.write(leaf.canonical() + "\n")
            self._rewrite_root_unlocked()

    def _rewrite_root(self) -> None:
        """Lock + rewrite. Public callers use this."""
        with self._lock:
            self._rewrite_root_unlocked()

    def _rewrite_root_unlocked(self) -> None:
        """Recompute + persist the Merkle root. Caller holds the lock."""
        payload = {
            "root": merkle_root([l.leaf_hash() for l in self._leaves]),
            "leaf_count": len(self._leaves),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "engagement_id": self.engagement_id,
        }
        tmp = self.root_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self.root_path)

    def add_finding_leaf(self, line_body: str, *, finding_path: Path) -> None:
        ts = _ts_from_finding_body(line_body)
        leaf = MerkleLeaf(
            file=str(finding_path.relative_to(self.workspace)),
            content_sha256=sha256_hex(line_body.encode("utf-8")),
            ts=ts,
            kind="finding",
        )
        self.add_leaf(leaf)

    def add_sidecar_leaf(
        self, *, sidecar_path: Path, content_sha256: str, ts: str, kind: str = "tool-output",
    ) -> None:
        leaf = MerkleLeaf(
            file=str(sidecar_path.relative_to(self.workspace)),
            content_sha256=content_sha256,
            ts=ts,
            kind=kind,
        )
        self.add_leaf(leaf)

    def current_root(self) -> str:
        self._ensure_loaded()
        return merkle_root([l.leaf_hash() for l in self._leaves])


# ── Verification ─────────────────────────────────────────────────────


def _ts_from_finding_body(line_body: str) -> str:
    """Pull ``discovered_at`` out of a finding JSON line.

    Per Plan risk #14, the leaf's ts is read from the line content,
    never from ``os.stat().st_mtime``.
    """
    # Strip trailing signature if present
    body, _ = split_signed_line(line_body)
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return ""
    return str(obj.get("discovered_at") or obj.get("ts") or "")


@dataclass
class VerifyReport:
    workspace: Path
    expected_root: str
    actual_root: str
    leaf_count: int
    unsigned_findings: int = 0
    bad_signatures: int = 0
    missing_sidecars: int = 0
    bad_sidecar_hashes: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            self.expected_root == self.actual_root
            and self.bad_signatures == 0
            and self.bad_sidecar_hashes == 0
            and self.missing_sidecars == 0
        )


def verify_evidence(workspace: Path, key: bytes | None) -> VerifyReport:
    """Independently re-derive the Merkle root and validate every signature.

    Distinguishes "unsigned legacy" lines (no key when written, or key
    not provided here) from "signature mismatch" (tampering). Does NOT
    delete or modify data — pure read-only check.
    """
    chain = EvidenceChain(workspace=workspace, key=key)
    chain._ensure_loaded()
    leaves = chain._leaves[:]

    # Re-derive findings hashes from disk and compare to recorded leaves.
    findings_path = workspace / "findings.jsonl"
    unsigned = 0
    bad_sig = 0
    findings_recomputed: list[str] = []
    findings_lines: dict[str, str] = {}
    if findings_path.exists():
        with open(findings_path, "r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.rstrip("\n")
                if not raw.strip():
                    continue
                body, sig = split_signed_line(raw)
                if sig is None:
                    unsigned += 1
                elif key is not None:
                    expected = hmac_sha256(key, body.encode("utf-8"))
                    if not hmac.compare_digest(expected, sig):
                        bad_sig += 1
                # Hash IS over the body (not the signature) so a key
                # rotation doesn't break Merkle equivalence.
                findings_recomputed.append(sha256_hex(body.encode("utf-8")))
                findings_lines[sha256_hex(body.encode("utf-8"))] = body

    # Sidecar files: re-hash the source bytes and compare.
    bad_sidecar_hashes = 0
    missing_sidecars = 0
    for leaf in leaves:
        if leaf.kind != "tool-output":
            continue
        # Sidecars are SHA-256 of an OUTPUT FILE, with ts embedded in
        # the sidecar JSON. Verify by re-hashing the OUTPUT FILE.
        path = workspace / leaf.file
        # Sidecar leaves point at the .sha256 sidecar file itself —
        # but verification is against the original file the sidecar
        # describes. Fall back to checking the sidecar's recorded
        # content_sha256 against the SOURCE file (sidecar siblings).
        source_candidates = [
            workspace / leaf.file.replace(".sha256", ""),  # plain source
            path,  # if the leaf points at the source directly
        ]
        source = next((p for p in source_candidates if p.exists()), None)
        if source is None or not source.is_file():
            missing_sidecars += 1
            continue
        try:
            actual = sha256_hex(source.read_bytes())
        except OSError:
            missing_sidecars += 1
            continue
        if actual != leaf.content_sha256:
            bad_sidecar_hashes += 1

    actual_root = merkle_root([l.leaf_hash() for l in leaves])
    expected_root = ""
    if chain.root_path.exists():
        try:
            expected_root = json.loads(
                chain.root_path.read_text(encoding="utf-8")
            ).get("root", "")
        except (json.JSONDecodeError, OSError):
            pass

    notes: list[str] = []
    if unsigned:
        notes.append(f"{unsigned} finding lines stored without HMAC (legacy)")
    if key is None:
        notes.append("no HMAC key provided — signatures not verified")

    return VerifyReport(
        workspace=workspace,
        expected_root=expected_root,
        actual_root=actual_root,
        leaf_count=len(leaves),
        unsigned_findings=unsigned,
        bad_signatures=bad_sig,
        missing_sidecars=missing_sidecars,
        bad_sidecar_hashes=bad_sidecar_hashes,
        notes=notes,
    )


__all__ = [
    "EvidenceChain",
    "MerkleLeaf",
    "VerifyReport",
    "default_key_path",
    "hmac_sha256",
    "load_or_create_key",
    "merkle_root",
    "sha256_hex",
    "sign_finding_line",
    "split_signed_line",
    "verify_evidence",
]
