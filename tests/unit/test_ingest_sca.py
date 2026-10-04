"""The Grype, Trivy and Snyk import parsers (Week 58 §42.2): an uploaded report reads the same as a
scan Bulwark ran itself, edge-case layouts, and what a vulnerability scanner's report may close.
Complements tests/unit/test_ingest_defectdojo.py, which compares them with DefectDojo's results."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from core.adapters.grype import GrypeAdapter
from core.adapters.trivy import TrivyAdapter
from core.correlation import correlate
from core.imports.parsers import ParseResult, get_parser, run_parser_on_bytes
from core.models import Category, Severity

DD = Path("tests/golden/ingest/defectdojo")
GRYPE_RAW = Path("tests/golden/grype/raw.json").read_bytes()
TRIVY_RAW = Path("tests/golden/trivy/raw.json").read_bytes()


def run(name: str, data: bytes | dict | list) -> ParseResult:
    raw = data if isinstance(data, bytes) else json.dumps(data).encode()
    return run_parser_on_bytes(get_parser(name), raw)


# --- one reading of a report, uploaded or scanned -------------------------------------------------


def test_an_uploaded_grype_report_is_the_scans_findings_exactly() -> None:
    uploaded = run("grype", GRYPE_RAW)
    native = GrypeAdapter().parse(GRYPE_RAW)
    assert uploaded.complete and uploaded.can_close_missing
    assert [f.to_dict() for f in uploaded.findings] == [f.to_dict() for f in native] and native


def test_an_uploaded_trivy_report_is_the_scans_findings_exactly() -> None:
    uploaded = run("trivy", TRIVY_RAW)
    native = TrivyAdapter().parse(TRIVY_RAW)
    assert uploaded.complete and uploaded.can_close_missing
    assert [f.to_dict() for f in uploaded.findings] == [f.to_dict() for f in native] and native


# --- Trivy ----------------------------------------------------------------------------------------


def test_trivy_kubernetes_reports_are_read_in_both_layouts() -> None:
    old = run("trivy", (DD / "trivy/kubernetes.json").read_bytes())
    assert (
        old.complete and old.findings
    )  # Vulnerabilities[].Results and Misconfigurations[].Results
    new = run("trivy", {"ArtifactName": "c", "Resources": [{"Results": [
        {"Target": "Deployment/x", "Type": "kubernetes", "Class": "config", "Misconfigurations": [
            {"ID": "KSV001", "Title": "t", "Severity": "HIGH", "Message": "m",
             "CauseMetadata": {"StartLine": 3, "EndLine": 4}}]}]}]})  # fmt: skip
    assert new.complete and [f.evidence.rule_ids for f in new.findings] == [{"trivy": ["KSV001"]}]


def test_trivy_secrets_become_secret_findings_and_licences_are_counted_not_imported() -> None:
    r = run("trivy", (DD / "trivy/misconfigurations_and_secrets.json").read_bytes())
    assert Category.SECRETS in {f.taxonomy.category for f in r.findings}
    lic = run("trivy", (DD / "trivy/license_scheme.json").read_bytes())
    assert lic.complete and lic.findings == []
    assert any("19 licence finding(s) were not imported" in w for w in lic.warnings)


def test_trivy_a_scan_with_nothing_to_report_is_clean_and_may_close() -> None:
    assert run("trivy", b"null").findings == [] and run("trivy", b"null").can_close_missing
    clean = run("trivy", {"SchemaVersion": 2, "ArtifactName": "alpine:3.19"})
    assert clean.complete and clean.findings == [] and clean.can_close_missing


def test_trivy_json_that_is_not_trivy_is_refused() -> None:
    assert not run("trivy", {"hello": "world"}).complete
    assert not run("trivy", {"results": []}).complete


def test_trivy_the_cvss_shown_is_the_one_of_the_source_that_set_the_severity() -> None:
    r = run("trivy", (DD / "trivy/cvss_severity_source.json").read_bytes())
    # NVD says 9.8 for the second one, but GitHub's advisory (7.5) is what made it HIGH.
    assert r.findings[1].scoring.normalized_severity is Severity.HIGH
    assert r.findings[1].scoring.cvss_v3_1 == 7.5


# --- Snyk -----------------------------------------------------------------------------------------


def _vuln(**over: object) -> dict:
    base = {"id": "SNYK-JS-LODASH-1", "title": "Prototype Pollution", "severity": "high",
            "packageName": "lodash", "version": "4.17.4", "from": ["app@1.0.0", "lodash@4.17.4"],
            "identifiers": {"CVE": ["CVE-2019-10744"], "CWE": ["CWE-1321"]}, "cvssScore": 9.1,
            "description": "d", "semver": {"vulnerable": "<4.17.12"}}  # fmt: skip
    return {**base, **over}


def _project(*vulns: dict, **over: object) -> dict:
    return {"vulnerabilities": list(vulns), "ok": False, "packageManager": "npm",
            "displayTargetFile": "package-lock.json", "projectName": "app", **over}  # fmt: skip


def test_snyk_reads_project_details_that_follow_the_vulnerabilities() -> None:
    """Snyk writes `displayTargetFile` after `vulnerabilities`; the file is read twice for it."""
    r = run("snyk", _project(_vuln()))
    (f,) = r.findings
    assert f.location.path == "package-lock.json" and f.package and f.package.ecosystem == "npm"
    assert f.taxonomy.cve == ("CVE-2019-10744",) and f.taxonomy.cwe == ("CWE-1321",)
    assert (
        "SNYK-JS-LODASH-1" in f.taxonomy.aliases
        and "Vulnerable path: app@1.0.0 > lodash@4.17.4" in f.description
    )


def test_snyk_a_list_of_projects_keeps_each_projects_own_file_and_manager() -> None:
    r = run("snyk", [_project(_vuln()), _project(_vuln(id="SNYK-PYTHON-X", packageName="x"),
                      packageManager="pip", displayTargetFile="requirements.txt")])  # fmt: skip
    assert [(f.location.path, f.package.ecosystem) for f in r.findings if f.package] == [
        ("package-lock.json", "npm"), ("requirements.txt", "pypi")]  # fmt: skip


@pytest.mark.parametrize(
    "word,score,expected",
    [("low", 9.8, Severity.CRITICAL), ("critical", 3.1, Severity.LOW), ("high", 4.0, Severity.MEDIUM),
     ("medium", None, Severity.MEDIUM), ("high", None, Severity.HIGH)],
)  # fmt: skip
def test_snyk_severity_follows_the_score_and_falls_back_to_the_word(
    word: str, score: float | None, expected: Severity
) -> None:
    (f,) = run("snyk", _project(_vuln(severity=word, cvssScore=score))).findings
    assert f.scoring.normalized_severity is expected


def test_snyk_an_unknown_severity_word_is_info_and_reported() -> None:
    r = run("snyk", _project(_vuln(severity="spicy", cvssScore=None)))
    assert r.findings[0].scoring.normalized_severity is Severity.INFO
    assert any("spicy" in w for w in r.warnings)


def test_snyk_a_clean_project_is_a_complete_empty_report() -> None:
    r = run(
        "snyk", {"vulnerabilities": [], "ok": True, "dependencyCount": 3, "packageManager": "npm"}
    )
    assert r.complete and r.findings == [] and r.can_close_missing


def test_snyk_a_fixed_in_or_upgrade_path_becomes_the_remediation() -> None:
    (f,) = run("snyk", _project(_vuln(upgradePath=[False, "lodash@4.17.21"]))).findings
    assert f.remediation.summary == "Upgrade to lodash@4.17.21."


def test_snyk_and_trivy_describing_one_vulnerability_are_one_issue() -> None:
    """Same package, version and CVE from two tools: one fingerprint, whichever uploaded it."""
    trivy = next(
        f
        for f in run("trivy", TRIVY_RAW).findings
        if f.package and f.package.name == "lodash" and f.taxonomy.cve
    )
    cve = trivy.taxonomy.cve[0]
    snyk = run(
        "snyk",
        _project(
            _vuln(
                packageName="lodash",
                version=trivy.package.version,  # type: ignore[union-attr]
                identifiers={"CVE": [cve]},
            )
        ),
    ).findings
    merged, _ = correlate([trivy, *snyk])
    assert len({f.fingerprint for f in merged}) == 1


def test_snyk_json_that_is_not_snyk_is_refused() -> None:
    assert not run("snyk", {"hello": "world"}).complete
    assert not run("snyk", [1, 2]).complete or run("snyk", [1, 2]).findings == []


# --- detection, truncation, hostile bytes ---------------------------------------------------------

FILES = {
    "grype": ("grype", GRYPE_RAW),
    "trivy": ("trivy", TRIVY_RAW),
    "snyk": ("snyk", json.dumps([_project(_vuln()), _project(_vuln(id="B"))]).encode()),
}


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
def test_arbitrary_bytes_never_raise_in_the_sca_parsers(blob: bytes) -> None:
    for name in ("grype", "trivy", "snyk"):
        r = run_parser_on_bytes(get_parser(name), blob)
        assert r.complete or r.error


def test_a_deeply_nested_report_is_refused() -> None:
    bomb = b'{"matches":' + b"[" * 3000 + b"]" * 3000 + b"}"
    for name in ("grype", "trivy", "snyk"):
        r = run_parser_on_bytes(get_parser(name), bomb)
        assert not r.complete
