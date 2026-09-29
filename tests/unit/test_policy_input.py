"""core/policy/input.py: building the OPA input document from a scan's own findings (plan §20.4)."""

from __future__ import annotations

from core.policy.input import build_input, issue_document


def _finding(**scoring_overrides: object) -> dict[str, object]:
    return {
        "id": "f1",
        "fingerprint": "fp1",
        "title": "t",
        "taxonomy": {"category": "sast", "cwe": ["CWE-89"], "owasp_top_10_2021": []},
        "scoring": {"normalized_severity": "high", "in_cisa_kev": False, **scoring_overrides},
        "package": None,
    }


def test_issue_document_maps_core_fields() -> None:
    doc = issue_document(_finding())
    assert doc["id"] == "f1"
    assert doc["severity"] == "HIGH"  # uppercased for the Rego policy's own convention
    assert doc["category"] == "sast"
    assert doc["cwe"] == ["CWE-89"]
    assert doc["in_cisa_kev"] is False


def test_reachable_is_omitted_when_unknown_not_sent_as_null() -> None:
    doc = issue_document(_finding())  # no "reachable" key in scoring at all
    assert "reachable" not in doc


def test_reachable_true_and_false_are_both_included() -> None:
    assert issue_document(_finding(reachable=True))["reachable"] is True
    assert issue_document(_finding(reachable=False))["reachable"] is False


def test_malicious_is_false_by_default_not_omitted() -> None:
    doc = issue_document(_finding())
    assert doc["malicious"] is False  # always present, like in_cisa_kev -- never simply absent


def test_malicious_is_true_when_a_mal_alias_is_present() -> None:
    f = _finding()
    f["taxonomy"] = {**f["taxonomy"], "aliases": ["MAL-2022-7441"]}
    assert issue_document(f)["malicious"] is True


def test_malicious_is_false_for_ordinary_vulnerability_aliases() -> None:
    f = _finding()
    f["taxonomy"] = {**f["taxonomy"], "aliases": ["CVE-2020-1234", "GHSA-xxxx-xxxx-xxxx"]}
    assert issue_document(f)["malicious"] is False


def test_license_is_omitted_when_the_package_has_none() -> None:
    doc = issue_document(_finding())
    assert "license" not in doc


def test_license_is_included_when_present() -> None:
    f = _finding()
    f["package"] = {"name": "x", "version": "1", "ecosystem": "npm", "license": "GPL-3.0"}
    assert issue_document(f)["license"] == "GPL-3.0"


def test_triage_fields_are_omitted_without_an_issue_argument() -> None:
    doc = issue_document(_finding())
    assert "triage_status" not in doc and "triage_expires_at" not in doc


def test_triage_fields_are_included_when_an_issue_is_given() -> None:
    doc = issue_document(
        _finding(), issue={"triage_status": "accepted", "triage_expires_at": "2027-01-01T00:00:00Z"}
    )
    assert doc["triage_status"] == "accepted"
    assert doc["triage_expires_at"] == "2027-01-01T00:00:00Z"


def test_entrypoint_reads_the_http_entrypoint_hop_from_a_taint_path() -> None:
    f = _finding()
    f["taint_path"] = [
        {"path": "a.py", "line": 4, "description": "HTTP entrypoint: GET /search (flask)", "is_sink": False, "snippet": ""},
        {"path": "a.py", "line": 10, "description": "execute(...) -- sql injection", "is_sink": True, "snippet": ""},
    ]  # fmt: skip
    assert issue_document(f)["entrypoint"] == "GET /search (flask)"


def test_entrypoint_is_empty_without_a_taint_path() -> None:
    assert issue_document(_finding())["entrypoint"] == ""


def test_build_input_wraps_documents_under_new_issues() -> None:
    doc = build_input([_finding()])
    assert list(doc.keys()) == ["new_issues"]
    assert len(doc["new_issues"]) == 1


def test_build_input_looks_up_issue_context_by_fingerprint() -> None:
    doc = build_input(
        [_finding()],
        issues_by_fingerprint={"fp1": {"triage_status": "accepted", "triage_expires_at": "x"}},
    )
    assert doc["new_issues"][0]["triage_status"] == "accepted"
