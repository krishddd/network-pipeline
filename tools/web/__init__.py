"""Web-specific tool wrappers (Phase 2).

Each module in this package exposes ``run_<tool>(runner, ...)`` that:

* Builds a ``ShellRunner`` argv list (no shell=True ever).
* Invokes the binary via the runner so the existing scope guard, argv
  guard, rate limit, OPSEC gate, capability gate, and per-target
  paranoid override all apply transparently.
* Parses the tool's output through ``tools.output_schemas`` (Pydantic-
  validated) when JSON, or returns a condensed text summary capped at
  4 KB when free-form.
* Returns a string (LangGraph @tool contract). Raw output paths are
  surfaced inside that string so the agent can pass them to KG ingest.
"""

from __future__ import annotations
