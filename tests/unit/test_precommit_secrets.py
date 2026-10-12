"""core.precommit.secrets_scan: the native, no-Docker secret patterns the pre-commit hook checks
staged files against (Week 51 task 4, plan §23). Each rule is a distinctively-prefixed credential
format, deliberately narrower than Gitleaks (core/adapters/gitleaks.py) in exchange for running
without a container."""

from __future__ import annotations

import pytest

from core.models import Category
from core.precommit.secrets_scan import scan_secrets


@pytest.mark.parametrize(
    "rule_id,line",
    [
        ("PCS001", 'aws_key = "AKIAABCDEFGHIJKLMNOP"'),
        ("PCS002", 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'),
        ("PCS003", "token = 'ghp_" + "a" * 36 + "'"),
        ("PCS004", "token = 'github_pat_" + "b" * 82 + "'"),
        ("PCS005", "token = 'ghs_" + "c" * 36 + "'"),
        ("PCS006", "SLACK_TOKEN = 'xoxb-" + "1234567890-1234567890123-abcdefghijklmnop'"),
        (
            "PCS007",
            "WEBHOOK = 'https://hooks.slack.com/services/T00000000/B00000000/"
            "XXXXXXXXXXXXXXXXXXXXXXXX'",
        ),
        ("PCS008", "stripe_key = 'sk_live_" + "d" * 24 + "'"),
        ("PCS009", "stripe_key = 'rk_live_" + "e" * 24 + "'"),
        ("PCS010", "GOOGLE_API_KEY = 'AIza" + "f" * 35 + "'"),
        ("PCS011", "-----BEGIN RSA PRIVATE KEY-----"),
        ("PCS012", "npm_token = 'npm_" + "g" * 36 + "'"),
        ("PCS014", "key = 'sk-ant-" + "h" * 25 + "'"),
        ("PCS015", "SENDGRID_API_KEY = 'SG." + "i" * 22 + "." + "j" * 43 + "'"),
    ],
)
def test_each_rule_fires_on_its_own_shape(rule_id: str, line: str) -> None:
    findings = scan_secrets("config.py", line)
    fired = {rid for f in findings for rids in f.evidence.rule_ids.values() for rid in rids}
    assert rule_id in fired, f"expected {rule_id} to fire on: {line!r} (got {fired})"


def test_openai_key_rule_fires_and_does_not_misclassify_as_stripe() -> None:
    findings = scan_secrets("x.py", "key = 'sk-" + "k" * 40 + "'")
    rule_ids = {rid for f in findings for rids in f.evidence.rule_ids.values() for rid in rids}
    assert "PCS013" in rule_ids
    assert "PCS008" not in rule_ids and "PCS009" not in rule_ids


def test_clean_file_produces_no_findings() -> None:
    text = "\n".join(
        [
            "def add(a, b):",
            "    return a + b",
            "",
            "API_URL = 'https://example.com/api'",
            "# a comment mentioning a key, but not shaped like one",
        ]
    )
    assert scan_secrets("clean.py", text) == []


def test_finding_never_carries_the_matched_secret_text() -> None:
    secret = "AKIAABCDEFGHIJKLMNOP"
    [finding] = scan_secrets("x.py", f'aws_key = "{secret}"')
    assert secret not in finding.title
    assert secret not in finding.description
    assert secret not in finding.location.snippet


def test_line_number_is_reported_correctly_in_a_multiline_file() -> None:
    text = "a = 1\nb = 2\naws_key = 'AKIAABCDEFGHIJKLMNOP'\nc = 3\n"
    [finding] = scan_secrets("x.py", text)
    assert finding.location.start_line == 3
    assert finding.location.end_line == 3


def test_two_different_secrets_on_different_lines_are_two_findings() -> None:
    text = "k1 = 'AKIAABCDEFGHIJKLMNOP'\nk2 = 'AIza" + "z" * 35 + "'\n"
    findings = scan_secrets("x.py", text)
    assert len(findings) == 2
    assert {f.location.start_line for f in findings} == {1, 2}


def test_every_finding_is_category_secrets_and_severity_high() -> None:
    findings = scan_secrets("x.py", "aws_key = 'AKIAABCDEFGHIJKLMNOP'")
    assert findings
    for f in findings:
        assert f.taxonomy.category is Category.SECRETS
        assert f.scoring.normalized_severity.value == "HIGH"
