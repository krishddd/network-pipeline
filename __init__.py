"""network_pipeline — autonomous network security testing module.

A LangGraph-based red-team pipeline ported from Decepticon and trimmed
for local use:
  * Local Ollama instead of LiteLLM proxy
  * Subprocess execution instead of Docker sandbox
  * JSON knowledge graph instead of Neo4j
  * 7 network-focused agents (orchestrator, recon, scanner, exploit,
    postexploit, analyst, defender)

Lives alongside the existing OWASP ASI suite in Security_module/ but is
fully decoupled — the two run via separate CLIs and only share the
reporting/ emitters.
"""

__version__ = "0.1.0"
