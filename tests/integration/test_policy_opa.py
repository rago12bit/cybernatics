"""core/policy/opa.py and the starter policy library (plan §20.4): needs the real `opa` binary,
not a mock -- policy evaluation correctness depends entirely on OPA's own Rego semantics."""

from __future__ import annotations

import shutil

import pytest

from core.policy.gate import evaluate_gate, load_starter_policy
from core.policy.opa import check_syntax, eval_deny, run_tests
from core.policy.starter import STARTER_DIR

pytestmark = pytest.mark.skipif(not shutil.which("opa"), reason="opa not available")


def test_check_syntax_accepts_valid_rego() -> None:
    assert check_syntax("package x\n\nallow if { true }\n") is None


def test_check_syntax_rejects_invalid_rego() -> None:
    error = check_syntax("package x\ndeny contains msg if {\n  msg :=\n")
    assert error is not None and "rego_parse_error" in error


def test_eval_deny_runs_the_plans_own_worked_example() -> None:
    rego = """
package gate.pull_request

deny contains msg if {
    some issue in input.new_issues
    issue.in_cisa_kev
    issue.reachable
    msg := sprintf("%s is actively exploited and reachable from %s", [issue.id, issue.entrypoint])
}
"""
    result = eval_deny(
        rego,
        "gate.pull_request",
        {"new_issues": [{"id": "ISS-1", "in_cisa_kev": True, "reachable": True, "entrypoint": "POST /login"}]},
    )  # fmt: skip
    assert result.deny == ("ISS-1 is actively exploited and reachable from POST /login",)
    assert result.error is None


def test_eval_deny_on_a_syntactically_invalid_policy_returns_an_error_not_a_crash() -> None:
    result = eval_deny("package x\ndeny contains msg if {\n  msg :=\n", "x", {})
    assert result.error is not None
    assert result.deny == ()


def test_eval_deny_with_no_matching_data_denies_nothing() -> None:
    rego = 'package gate.pull_request\n\ndeny contains msg if {\n\tinput.impossible == true\n\tmsg := "unreachable"\n}\n'
    result = eval_deny(rego, "gate.pull_request", {})
    assert result.deny == () and result.error is None


def test_the_starter_policys_own_opa_tests_all_pass() -> None:
    """The same check CI runs (`opa test core/policy/starter`), inside the normal test suite too,
    so a regression in the starter library is caught by `pytest` alone, not only a separate CI
    step someone could forget to keep passing."""
    result = run_tests(STARTER_DIR)
    assert result.ok, f"starter policy tests failed: {result.failures}"
    assert result.passed >= 10  # one positive + one negative case per rule, plus edge cases


def test_evaluate_gate_runs_the_starter_policy_end_to_end() -> None:
    findings = [
        {
            "id": "f1", "fingerprint": "fp1", "title": "SQLi",
            "taxonomy": {"category": "sast", "cwe": ["CWE-89"]},
            "scoring": {"normalized_severity": "HIGH", "in_cisa_kev": True, "reachable": True},
            "taint_path": [
                {"path": "a.py", "line": 4, "description": "HTTP entrypoint: GET /search (flask)", "is_sink": False, "snippet": ""},
            ],
        },
    ]  # fmt: skip
    result = evaluate_gate(findings, load_starter_policy())
    assert len(result.deny) == 1
    assert "f1" in result.deny[0] and "GET /search (flask)" in result.deny[0]


def test_evaluate_gate_on_a_clean_finding_denies_nothing() -> None:
    findings = [
        {
            "id": "f1", "fingerprint": "fp1", "title": "minor",
            "taxonomy": {"category": "sast", "cwe": []},
            "scoring": {"normalized_severity": "LOW", "in_cisa_kev": False},
        },
    ]  # fmt: skip
    result = evaluate_gate(findings, load_starter_policy())
    assert result.deny == ()
