"""HTTP service for click-to-run engagements against an allowlist.

The API is a thin layer over ``core.auto`` that exposes:

* ``GET /api/targets`` — the curated list of public, authorised test
  targets (Vulnweb, IBM AltoroJ, Google Gruyere, etc.).
* ``POST /api/engagements`` — start a new engagement against ONE entry
  from the allowlist. Arbitrary targets are rejected.
* ``GET /api/engagements`` — list all past + running engagements.
* ``GET /api/engagements/{id}`` — engagement metadata + status.
* ``GET /api/engagements/{id}/findings`` — flattened findings JSON.
* ``GET /api/engagements/{id}/report?fmt=sarif|json`` — download.

Security boundary: the curated allowlist (``api/targets.json``) is the
ONLY place targets are accepted from. The endpoint never lets a
caller scan an arbitrary URL — that would turn the FastAPI service
into a pentest-as-a-service for the public internet.
"""

from __future__ import annotations
