"""core.dast.adapters.nuclei's JSONL parsing (Week 49 task 3, plan §22.4) and its egress-proxy
wiring (Week 49b, plan §22.4 follow-up)."""

from __future__ import annotations

import json
import subprocess
from typing import Any

from core.dast.adapters import nuclei
from core.dast.adapters.nuclei import ALLOWED_PROTOCOL_TYPES, EXCLUDED_TAGS, _parse_jsonl
from core.dast.proxy import ProxyConfig
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


def test_allowed_protocol_types_is_http_only() -> None:
    """Regression guard: a real live run found Nuclei's `dns`/`whois`-type templates legitimately
    contact hosts other than the verified target (a DNS resolver, a domain registry's RDAP API) --
    see the module docstring. `http` must stay the only allowed protocol type, unconditionally."""
    assert set(ALLOWED_PROTOCOL_TYPES) == {"http"}


def test_without_a_proxy_the_argv_has_no_proxy_or_add_host_flags(monkeypatch: Any) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(nuclei.subprocess, "run", fake_run)
    nuclei.run_nuclei("https://example.com/")
    assert "-proxy" not in captured["argv"]
    assert "--add-host" not in captured["argv"]
    assert "-pt" in captured["argv"]
    assert captured["argv"][captured["argv"].index("-pt") + 1] == "http"


def test_with_a_proxy_the_argv_points_nuclei_at_it_through_host_docker_internal(
    monkeypatch: Any,
) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(nuclei.subprocess, "run", fake_run)
    nuclei.run_nuclei(
        "https://example.com/", proxy=ProxyConfig(host="host.docker.internal", port=1234)
    )
    argv = captured["argv"]
    assert "--add-host" in argv
    assert argv[argv.index("--add-host") + 1] == "host.docker.internal:host-gateway"
    assert "-proxy" in argv
    assert argv[argv.index("-proxy") + 1] == "http://host.docker.internal:1234"
