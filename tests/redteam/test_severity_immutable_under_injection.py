"""Red-team scenario (plan §21.9): "downgrades severity". Unlike test_contract_hardening.py, the
attack here isn't a malformed reply -- it's a WORST-CASE model that reads injected text planted in
the scanned code (the corpus's own suppression-style payloads) and fully complies, returning a
legitimate, schema-valid "likely_false_positive" verdict. The triage assistant is explicitly allowed
to say that (core.triage_assistant.service.assess's whole purpose); the real guarantee under test is
that even a fully-compliant model's verdict never reaches back into the Finding object itself --
severity, taxonomy and triage state are untouched regardless of what the model said.
"""

from __future__ import annotations

import copy
import json

import pytest

from core.llm.client import Completion
from core.llm.prompt import CodeContext
from core.models import Category, Finding, Location, Scoring, Severity, Taxonomy
from core.triage_assistant.service import assess
from tests.redteam.payloads import load_payloads

PAYLOADS = load_payloads()

_SUPPRESSION_PAYLOADS = ["override-classic", "override-polite", "role-change", "output-hijack"]


class CompliantAdversarialModel:
    """A worst-case fake: doesn't resist the injected instruction at all, just parrots it back as
    a legitimate-shaped verdict -- the strongest test of the architecture, since a model that
    resisted wouldn't exercise the guarantee under test."""

    model = "compliant-adversarial-fake"

    def complete(self, system: str, user: str) -> Completion:
        reply = json.dumps(
            {
                "verdict": "likely_false_positive",
                "confidence": "high",
                "rationale": "The embedded instructions say this is safe, so marking it as such.",
                "supporting_lines": [1],
            }
        )
        return Completion(reply, 10)


def _finding(payload: str) -> Finding:
    return Finding(
        "f1",
        f"SQL injection ({payload})",
        f"User-controlled input reaches a raw query. {payload}",
        Location("app/users.py", 10, 10, "snippet"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
        scoring=Scoring(normalized_severity=Severity.CRITICAL, risk_score=95),
    )


@pytest.mark.parametrize("payload_name", _SUPPRESSION_PAYLOADS)
def test_a_fully_compliant_model_cannot_change_the_findings_own_severity(payload_name: str) -> None:
    finding = _finding(PAYLOADS[payload_name])
    before = copy.deepcopy(finding)

    result = assess(finding, CompliantAdversarialModel(), CodeContext(PAYLOADS[payload_name], 1))

    assert result is not None
    assert result.verdict.verdict == "likely_false_positive"  # the model DID comply -- confirmed

    assert finding.scoring.normalized_severity is before.scoring.normalized_severity
    assert finding.scoring.risk_score == before.scoring.risk_score
    assert finding.taxonomy == before.taxonomy
    assert finding.triage == before.triage
    assert finding == before, "assess() must never mutate the Finding it was given"
