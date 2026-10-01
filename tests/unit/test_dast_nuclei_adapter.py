"""core.dast.adapters.nuclei's JSONL parsing (Week 49 task 3, plan §22.4)."""

from __future__ import annotations

import json

from core.dast.adapters.nuclei import EXCLUDED_TAGS, _parse_jsonl
from core.models import Category, Severity


def _line(**kw: object) -> str:
    return json.dumps(kw)


def test_parses_a_simple_finding() -> None:
    line = _line(
        **{
            "template-id": "exposed-panel",
            "info": {
                "name": "Exposed Admin Panel",
                "severity": "medium",
                "description": "an admin panel is exposed",
                "classification": {"cwe-id": "CWE-200"},
                "reference": "https://example.org/ref",
            },
            "matched-at": "https://example.com/admin",
        }
    )
    findings = _parse_jsonl(line)
    assert len(findings) == 1
    f = findings[0]
    assert f.taxonomy.category is Category.DAST
    assert f.taxonomy.cwe == ("CWE-200",)
    assert f.scoring.normalized_severity is Severity.MEDIUM
    assert f.location.route == "/admin"
    assert f.remediation.references == ["https://example.org/ref"]


def test_cwe_list_is_uppercased_and_preserved_as_a_tuple() -> None:
    line = _line(
        **{
            "template-id": "t1",
            "info": {
                "name": "n",
                "severity": "low",
                "classification": {"cwe-id": ["cwe-89", "cwe-20"]},
            },
            "matched-at": "https://example.com/",
        }
    )
    assert _parse_jsonl(line)[0].taxonomy.cwe == ("CWE-89", "CWE-20")


def test_missing_severity_defaults_to_info() -> None:
    line = _line(
        **{"template-id": "t1", "info": {"name": "n"}, "matched-at": "https://example.com/"}
    )
    assert _parse_jsonl(line)[0].scoring.normalized_severity is Severity.INFO


def test_blank_and_malformed_lines_are_skipped() -> None:
    assert _parse_jsonl("\n\n") == []
    assert _parse_jsonl("not json at all") == []


def test_multiple_lines_produce_multiple_findings() -> None:
    lines = "\n".join(
        [
            _line(
                **{"template-id": "a", "info": {"name": "A"}, "matched-at": "https://example.com/a"}
            ),
            _line(
                **{"template-id": "b", "info": {"name": "B"}, "matched-at": "https://example.com/b"}
            ),
        ]
    )
    findings = _parse_jsonl(lines)
    assert {f.location.route for f in findings} == {"/a", "/b"}


def test_same_template_and_matched_at_reported_twice_get_distinct_ids() -> None:
    """A real live scan found this: nuclei can report the same template-id against the same
    matched-at more than once (one record per matcher/extracted value within a template) -- an id
    keyed on (template-id, matched-at) alone collides. Regression test for that real bug."""
    lines = "\n".join(
        [
            _line(
                **{
                    "template-id": "http-missing-security-headers",
                    "info": {"name": "n"},
                    "matched-at": "https://example.com/",
                    "extracted-results": ["X-Frame-Options"],
                }
            ),
            _line(
                **{
                    "template-id": "http-missing-security-headers",
                    "info": {"name": "n"},
                    "matched-at": "https://example.com/",
                    "extracted-results": ["X-Content-Type-Options"],
                }
            ),
        ]
    )
    findings = _parse_jsonl(lines)
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2


def test_excluded_tags_never_include_an_allowed_tag_by_accident() -> None:
    """Regression guard for the module's own safety invariant: these four tags must always be
    excluded, unconditionally -- see the module docstring for why."""
    assert set(EXCLUDED_TAGS) == {"dos", "fuzz", "intrusive", "bruteforce"}
