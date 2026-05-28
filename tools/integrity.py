"""SHA-256 sidecars for captured subprocess output (Plan B.3.5).

Every ``ShellRunner.run`` writes ``stdout``, ``stderr``, ``argv`` files
under ``tool_io/<agent>/<ts>_<obj>_<binary>.{stdout,stderr,argv}``.
For audit, we additionally drop a sidecar JSON next to each captured
artefact:

    tool_io/<agent>/<stem>.sha256

containing::

    {
      "file": "<workspace-relative path of the source>",
      "sha256": "<hex digest of the source bytes>",
      "ts": "<iso8601 — clock time at capture, NOT filesystem mtime>",
      "argv_sha256": "<hex digest of the argv file bytes>"
    }

The ``ts`` in the sidecar is the canonical timestamp the EvidenceChain
later reads — Plan risk #14 forbids using ``os.stat().st_mtime``
because tar / move / copy operations alter the filesystem mtime and
would break Merkle reproduction across machines.

The sidecar is also fed back as a Merkle leaf (``kind="tool-output"``)
when an EvidenceChain is attached to the runner.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from network_pipeline.core.logging import get_logger

log = get_logger("tools.integrity")


def sha256_file(path: Path) -> str:
    """Stream-hash a file in 1 MB chunks. Returns hex digest."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as e:
        log.warning("sha256_file failed for %s: %r", path, e)
        return ""
    return h.hexdigest()


def write_sidecar(
    *,
    source_path: Path,
    workspace: Path,
    argv_path: Path | None = None,
    kind: str = "tool-output",
) -> Path | None:
    """Hash ``source_path`` and write a sibling ``.sha256`` JSON sidecar.

    Returns the sidecar path, or None when source can't be read.
    The sidecar's ``ts`` is taken at write time (not from filesystem
    mtime) so the chain stays valid after workspace moves.
    """
    if not source_path.exists():
        return None
    digest = sha256_file(source_path)
    if not digest:
        return None
    sidecar_path = source_path.with_suffix(source_path.suffix + ".sha256")
    payload = {
        "file": str(source_path.relative_to(workspace))
        if source_path.is_absolute() else str(source_path),
        "sha256": digest,
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
    }
    if argv_path is not None and argv_path.exists():
        payload["argv_sha256"] = sha256_file(argv_path)
    tmp = sidecar_path.with_suffix(sidecar_path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, sidecar_path)
    return sidecar_path


def read_sidecar(sidecar_path: Path) -> dict | None:
    """Load a sidecar JSON. Returns None when missing / malformed."""
    if not sidecar_path.exists():
        return None
    try:
        return json.loads(sidecar_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


__all__ = ["read_sidecar", "sha256_file", "write_sidecar"]
