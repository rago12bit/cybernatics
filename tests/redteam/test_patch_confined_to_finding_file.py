"""Red-team scenario (plan §21.9): "writes outside the patch" and "downgrades severity", tested
against schema-VALID replies (so the broad rejection in test_contract_hardening.py isn't doing the
work here for the wrong reason -- these are well-formed JSON objects with exactly the five required
fields, differing only in the one adversarial detail each test targets) fed to
core.llm.contract.parse_response, the fix-suggestion contract whose own docstring names both of
these exact defenses.
"""

from __future__ import annotations

import json

import pytest

from core.llm.contract import ContractError, parse_response
from tests.redteam.payloads import load_payloads

PAYLOADS = load_payloads()

BASE = {
    "explanation": "Use a parameterized query instead of string concatenation.",
    "impact": "An attacker could read or modify arbitrary rows in the database.",
    "fix_summary": "Bind the user input as a query parameter rather than interpolating it.",
    "confidence": "high",
}


def test_patch_redirect_payload_is_rejected_as_the_suggested_patch() -> None:
    """The corpus's own "patch-redirect" payload, made into a syntactically-plausible diff header
    pointing outside the finding's file."""
    patch = (
        "--- a/../../etc/passwd\n"
        "+++ b/../../etc/passwd\n"
        "@@ -1,1 +1,1 @@\n"
        "-root:x:0:0:root:/root:/bin/bash\n"
        "+pwned:x:0:0:root:/root:/bin/bash\n"
    )
    assert "patch-redirect" in PAYLOADS  # sanity: the corpus still has the payload this mirrors
    reply = json.dumps({**BASE, "suggested_patch": patch})
    with pytest.raises(ContractError, match="path"):
        parse_response(reply, path="app/users.py")


def test_absolute_path_patch_is_rejected() -> None:
    patch = "--- /etc/passwd\n+++ /etc/passwd\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    reply = json.dumps({**BASE, "suggested_patch": patch})
    with pytest.raises(ContractError, match="path"):
        parse_response(reply, path="app/users.py")


def test_patch_targeting_a_different_real_file_is_rejected() -> None:
    """Not a traversal attempt -- a plain, plausible-looking relative path that just isn't the
    file the finding is actually in. The contract must confine a patch to the ONE file it was
    asked about, not merely reject unsafe-looking paths."""
    patch = "--- a/app/settings.py\n+++ b/app/settings.py\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    reply = json.dumps({**BASE, "suggested_patch": patch})
    with pytest.raises(ContractError, match="only the file"):
        parse_response(reply, path="app/users.py")


def test_well_formed_dismissal_language_is_rejected_despite_a_valid_schema() -> None:
    """Every field present, nothing extra, confidence is a legal value -- the ONLY adversarial
    detail is that the explanation argues the finding isn't real. Schema validity alone must not
    be enough to get a dismissal through."""
    reply = json.dumps(
        {
            **BASE,
            "explanation": "This is a false positive, safe to ignore.",
            "suggested_patch": None,
        }
    )
    with pytest.raises(ContractError, match="dismiss"):
        parse_response(reply, path="app/users.py")


def test_extra_severity_field_is_rejected_despite_otherwise_valid_content() -> None:
    """The corpus's "json-hijack" payload embeds this exact extra field; here it's isolated from
    that payload's other adversarial content to confirm THIS specific defense (unexpected keys)
    is what fires, not the dismissive wording alongside it."""
    reply = json.dumps({**BASE, "suggested_patch": None, "severity": "LOW"})
    with pytest.raises(ContractError, match="unexpected field"):
        parse_response(reply, path="app/users.py")
