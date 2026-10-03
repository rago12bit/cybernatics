"""What imported findings go through before reimport (Week 54 task 7, ADR-0040): identity, merging,
scoring, and -- because an upload carries no guarantee a scan's tools give -- secret redaction."""

from __future__ import annotations

import json
from typing import Any

from core.imports.parsers import get_parser, run_parser_on_bytes
from core.imports.prepare import prepare
from core.models import Category
from core.redact import SECRET_PLACEHOLDER

SECRET = "AKIAIOSFODNN7EXAMPLE1234"
VALUE = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETVALUE9"


def sarif(tool: str, results: list[dict[str, Any]]) -> bytes:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": tool, "rules": [{"id": "r1"}]}},
                    "results": results,
                }
            ],
        }
    ).encode()


def result(path: str, line: int, message: str, snippet: str) -> dict[str, Any]:
    return {
        "ruleId": "r1",
        "level": "error",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": line, "snippet": {"text": snippet}},
                }
            }
        ],
    }


def parse(data: bytes):  # type: ignore[no-untyped-def]
    r = run_parser_on_bytes(get_parser("sarif"), data)
    assert r.complete
    return r.findings


def test_parsed_findings_have_no_identity_until_they_are_prepared() -> None:
    """Why `prepare` exists: reimport matches by fingerprint, and a parser does not make one."""
    raw = parse(sarif("tool", [result("a.py", 1, "x", "one"), result("b.py", 9, "y", "two")]))
    assert [f.fingerprint for f in raw] == ["", ""]
    prepared = prepare(raw)
    assert len({f.fingerprint for f in prepared}) == 2 and all(f.fingerprint for f in prepared)


def test_prepared_findings_are_scored() -> None:
    (f,) = prepare(parse(sarif("tool", [result("a.py", 1, "x", "one")])))
    assert f.scoring.risk_score is not None


def test_a_secret_in_an_uploaded_report_is_never_kept() -> None:
    findings = parse(
        sarif(
            "gitleaks",
            [
                result("app/.env", 3, f"Detected a key: '{SECRET}'", f"KEY='{SECRET}'"),
                result("app/.env", 4, f"Detected a secret: '{VALUE}'", f"SECRET='{VALUE}'"),
            ],
        )
    )
    assert {f.taxonomy.category for f in findings} == {Category.SECRETS}
    prepared = prepare(findings)
    dumped = json.dumps([f.to_dict() for f in prepared])
    assert SECRET not in dumped and VALUE not in dumped and "SECRETVALUE" not in dumped
    assert all(f.location.snippet == SECRET_PLACEHOLDER for f in prepared)


def test_two_different_secrets_stay_two_findings_after_redaction() -> None:
    """Redaction must not make every secret in a file look like the same one."""
    findings = prepare(
        parse(
            sarif(
                "gitleaks",
                [
                    result("app/.env", 3, "key", f"KEY='{SECRET}'"),
                    result("app/.env", 40, "secret", f"SECRET='{VALUE}'"),
                ],
            )
        )
    )
    assert len(findings) == 2 and len({f.fingerprint for f in findings}) == 2


def test_other_findings_near_a_secret_have_their_snippet_withheld() -> None:
    findings = prepare(
        parse(sarif("gitleaks", [result("app/cfg.py", 10, "a secret", f"x='{VALUE}'")]))
        + parse(sarif("semgrep", [result("app/cfg.py", 11, "hardcoded", f"pw = '{VALUE}'")]))
    )
    sast = next(f for f in findings if f.taxonomy.category is not Category.SECRETS)
    assert VALUE not in json.dumps(sast.to_dict())
