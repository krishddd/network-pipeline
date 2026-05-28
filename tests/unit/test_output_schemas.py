"""Tests for tools.output_schemas — Pydantic-validated tool output."""

from __future__ import annotations


def test_nuclei_hit_parses_well_formed():
    from network_pipeline.tools.output_schemas import NucleiHit

    raw = {
        "template-id": "tech-detect",
        "info": {"name": "nginx", "severity": "info", "tags": ["tech"]},
        "host": "https://example.com",
        "matched-at": "https://example.com/",
        "type": "http",
    }
    h = NucleiHit.model_validate(raw)
    assert h.template_id == "tech-detect"
    assert h.info.severity == "info"
    assert h.host == "https://example.com"


def test_nuclei_hit_missing_info_defaults():
    from network_pipeline.tools.output_schemas import NucleiHit

    h = NucleiHit.model_validate({"host": "x"})
    assert h.info.severity == "unknown"
    assert h.info.name == "?"


def test_parse_jsonl_collects_errors():
    from network_pipeline.tools.output_schemas import NucleiHit, parse_jsonl

    text = (
        '{"template-id": "x", "info": {"severity": "high"}, "host": "h1"}\n'
        "this is not json\n"
        '{"info": "wrong-type"}\n'  # info should be dict
        '{"template-id": "y", "info": {"severity": "low"}, "host": "h2"}\n'
    )
    hits, errs = parse_jsonl(text, NucleiHit, tool="nuclei")
    assert len(hits) == 2
    assert {h.host for h in hits} == {"h1", "h2"}
    assert len(errs) == 2
    assert any("json" in e.error for e in errs)
    assert any("schema" in e.error for e in errs)


def test_parse_jsonl_skips_blank_lines():
    from network_pipeline.tools.output_schemas import NucleiHit, parse_jsonl

    hits, errs = parse_jsonl("\n   \n\n", NucleiHit, tool="nuclei")
    assert hits == [] and errs == []


def test_extra_fields_ignored_for_forward_compat():
    from network_pipeline.tools.output_schemas import HttpxLine

    raw = {"url": "https://x", "status-code": 200, "tomorrow": "new field"}
    h = HttpxLine.model_validate(raw)
    assert h.status_code == 200
