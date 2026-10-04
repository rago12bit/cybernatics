"""The GitLab security report and Checkov import parsers (Week 58 §42.2). Complements the
DefectDojo comparison in tests/unit/test_ingest_defectdojo.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.adapters.checkov import CheckovAdapter
from core.correlation import correlate
from core.imports.parsers import ParseResult, get_parser, run_parser_on_bytes
from core.models import Category, Severity

DD = Path("tests/golden/ingest/defectdojo")
CHECKOV_RAW = Path("tests/golden/checkov/raw.json").read_bytes()


def run(name: str, data: bytes | dict | list) -> ParseResult:
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    return run_parser_on_bytes(get_parser(name), raw)


# --- Checkov --------------------------------------------------------------------------------------


def test_an_uploaded_checkov_report_is_the_scans_findings_exactly() -> None:
    uploaded = run("checkov", CHECKOV_RAW)
    native = CheckovAdapter().parse(CHECKOV_RAW)
    assert uploaded.complete and uploaded.can_close_missing and native
    assert [f.to_dict() for f in uploaded.findings] == [f.to_dict() for f in native]


def test_checkov_reads_one_framework_or_a_list_of_them_and_ignores_passed_checks() -> None:
    one = run("checkov", (DD / "checkov/checkov-report-1-vuln.json").read_bytes())
    many = run("checkov", (DD / "checkov/checkov-report-multiple-check_type.json").read_bytes())
    assert one.complete and len(one.findings) >= 1 and many.complete and len(many.findings) > 1
    assert all(f.taxonomy.category is Category.IAC for f in many.findings)


def test_a_checkov_report_with_no_failed_checks_is_a_clean_scan() -> None:
    r = run(
        "checkov",
        {"check_type": "terraform", "results": {"passed_checks": [], "failed_checks": []}},
    )
    assert r.complete and r.findings == [] and r.can_close_missing


def test_checkov_counters_only_means_nothing_was_scanned_and_closes_nothing() -> None:
    r = run("checkov", (DD / "checkov/checkov2-report-0-vuln.json").read_bytes())
    assert r.complete and r.findings == [] and not r.can_close_missing
    assert any("no resources were scanned" in w for w in r.warnings)


def test_checkov_json_that_is_not_checkov_is_refused() -> None:
    assert not run("checkov", {"hello": "world"}).complete


# --- GitLab ---------------------------------------------------------------------------------------


def _vuln(location: dict[str, Any], **over: Any) -> dict[str, Any]:
    return {"id": "abc", "name": "Thing", "description": "d", "severity": "High",
            "location": location, "identifiers": [], **over}  # fmt: skip


def _report(*vulns: dict[str, Any], **top: Any) -> dict[str, Any]:
    return {"version": "15.0.0", "vulnerabilities": list(vulns), "remediations": [], **top}


def test_gitlab_classifies_each_record_by_its_location() -> None:
    r = run("gitlab", _report(
        _vuln({"file": "a.py", "start_line": 3, "end_line": 4},
              identifiers=[{"type": "bandit_test_id", "value": "B101"}, {"type": "cwe", "value": "89"}]),
        _vuln({"file": "package-lock.json", "dependency": {"package": {"name": "lodash"}, "version": "4.17.4"}},
              identifiers=[{"type": "cve", "value": "CVE-2019-10744"}]),
        _vuln({"image": "reg/app:1", "operating_system": "debian:10", "dependency": {"package": {"name": "apt"}, "version": "1.4"}},
              identifiers=[{"type": "cve", "value": "CVE-2019-3462"}], message="apt flaw"),
        _vuln({"file": ".env", "start_line": 1, "commit": {"sha": "0"}}, raw_source_code_extract="KEY=abc",
              identifiers=[{"type": "gitleaks_rule_id", "value": "AWS"}]),
        _vuln({"hostname": "https://app.example:443", "path": "/login?x=1", "method": "GET", "param": ""},
              identifiers=[{"type": "ZAProxy_PluginId", "value": "10020"}]),
        _vuln({"crash_type": "Index-out-of-range"}),  # a coverage-fuzzing crash: no place
    ))  # fmt: skip
    cats = [f.taxonomy.category for f in r.findings]
    assert r.complete and cats == [
        Category.SAST,
        Category.SCA,
        Category.SCA,
        Category.SECRETS,
        Category.DAST,
    ]
    sast, dep, image, secret, dast = r.findings
    assert sast.evidence.rule_ids == {"gitlab": ["B101"]} and sast.taxonomy.cwe == ("CWE-89",)
    assert (sast.location.start_line, sast.location.end_line) == (3, 4)
    assert dep.package and dep.package.ecosystem == "npm" and dep.title == "CVE-2019-10744: Thing"
    assert (
        image.package and image.package.ecosystem == "debian" and image.location.path == "reg/app:1"
    )
    assert (
        image.title == "apt flaw"
    )  # a container finding is named by GitLab's message, not prefixed
    assert (dast.location.host, dast.location.route) == ("https://app.example", "/login")
    assert any("coverage-fuzzing" in w for w in r.warnings)


def test_gitlab_dependency_files_say_which_package_manager_when_the_file_name_does_not() -> None:
    r = run("gitlab", _report(
        _vuln({"file": "deps/odd.lock", "dependency": {"package": {"name": "x"}, "version": "1"}},
              identifiers=[{"type": "cve", "value": "CVE-2020-1"}]),
        scan={"type": "dependency_scanning", "scanner": {"name": "Gemnasium"}},
        dependency_files=[{"path": "deps/odd.lock", "package_manager": "yarn"}],
    ))  # fmt: skip
    assert r.findings[0].package and r.findings[0].package.ecosystem == "npm"
    assert r.findings[0].evidence.reported_by == ["Gemnasium"]


def test_gitlab_unknown_and_undefined_severity_are_info_and_the_title_keeps_the_word() -> None:
    r = run("gitlab", _report(_vuln({"file": "a", "start_line": 1}, severity="Unknown"),
                              _vuln({"file": "b", "start_line": 1}, severity="Undefined", name="Other")))  # fmt: skip
    assert all(f.scoring.normalized_severity is Severity.INFO for f in r.findings)
    assert (
        r.findings[0].title == "[Unknown severity] Thing"
        and r.findings[1].title == "[Undefined severity] Other"
    )


def test_gitlabs_own_id_is_not_the_identity_of_a_finding() -> None:
    """GitLab recomputes `id` between runs; two reports of one defect that differ only in `id`
    must be one Issue."""

    def one(i: str) -> list:
        loc = {"file": "a.py", "start_line": 3, "end_line": 3}
        ids = [{"type": "bandit_test_id", "value": "B101"}]
        merged, _ = correlate(run("gitlab", _report(_vuln(loc, id=i, identifiers=ids))).findings)
        return merged

    assert one("11111")[0].fingerprint == one("22222")[0].fingerprint


def test_gitlab_a_report_with_no_vulnerabilities_key_is_refused_and_an_empty_list_is_clean() -> (
    None
):
    assert not run("gitlab", {"version": "15.0.0", "scan": {}}).complete
    clean = run("gitlab", _report())
    assert clean.complete and clean.findings == [] and clean.can_close_missing


def test_gitlab_and_snyk_are_told_apart() -> None:
    snyk = (DD / "snyk/single_project_one_vuln.json").read_bytes()
    gitlab = (DD / "gitlab/gitlab_sast--gl-sast-report-1-vuln_v15.json").read_bytes()
    assert get_parser("gitlab").sniff(snyk[:65536]) == 0
    assert get_parser("snyk").sniff(gitlab[:65536]) == 0


FILES = {
    "gitlab": ("gitlab", (DD / "gitlab/gitlab_dep_scan--gl-dependency-scanning-report-1-vuln_v15.json").read_bytes()),
    "checkov": ("checkov", CHECKOV_RAW),
}  # fmt: skip


@settings(max_examples=120, deadline=None)
@given(st.sampled_from(sorted(FILES)), st.floats(min_value=0.0, max_value=0.999))
def test_no_strict_prefix_of_a_report_reads_as_a_complete_one(which: str, fraction: float) -> None:
    parser, raw = FILES[which]
    raw = raw.rstrip()
    cut = int(len(raw) * fraction)
    r = run_parser_on_bytes(get_parser(parser), raw[:cut])
    assert not r.complete or (cut == 0 and r.findings == []), (which, cut)


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=2048))
def test_arbitrary_bytes_never_raise_in_the_new_parsers(blob: bytes) -> None:
    for name in ("gitlab", "checkov"):
        r = run_parser_on_bytes(get_parser(name), blob)
        assert r.complete or r.error


@pytest.mark.parametrize("name", ["gitlab", "checkov"])
def test_a_deeply_nested_report_is_refused(name: str) -> None:
    bomb = b'{"vulnerabilities":' + b"[" * 3000 + b"]" * 3000 + b"}"
    assert not run_parser_on_bytes(get_parser(name), bomb).complete


def test_a_dependency_finding_without_a_cve_keeps_its_identity_when_gitlabs_id_changes() -> None:
    def one(i: str) -> str:
        v = _vuln(
            {
                "file": "go.sum",
                "dependency": {"package": {"name": "gopkg.in/yaml.v2"}, "version": "v2.2.2"},
            },
            id=i,
            identifiers=[{"type": "gemnasium", "value": "7368f513-0aa9"}],
        )
        merged, _ = correlate(run("gitlab", _report(v)).findings)
        return merged[0].fingerprint

    assert one("aaa") == one("bbb")
