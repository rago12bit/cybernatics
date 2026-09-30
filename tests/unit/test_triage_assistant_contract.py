"""core.triage_assistant.contract: the triage assistant's output contract (plan §21.3)."""

from __future__ import annotations

import json

import pytest

from core.triage_assistant.contract import ContractError, parse_response

VALID = {
    "verdict": "likely_real",
    "confidence": "high",
    "rationale": "User input reaches the sink unsanitized.",
    "supporting_lines": [10, 11],
}


def _reply(**overrides: object) -> str:
    return json.dumps({**VALID, **overrides})


def test_a_valid_reply_parses() -> None:
    r = parse_response(_reply(), first_line=10, last_line=11)
    assert r.verdict == "likely_real"
    assert r.confidence == "high"
    assert r.supporting_lines == (10, 11)


def test_tolerates_one_json_fence() -> None:
    r = parse_response(f"```json\n{_reply()}\n```", first_line=10, last_line=11)
    assert r.verdict == "likely_real"


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "[]",
        '{"verdict": "likely_real"}',  # missing fields
        json.dumps({**VALID, "extra": "x"}),
        json.dumps({**VALID, "verdict": "definitely_a_bug"}),
        json.dumps({**VALID, "confidence": "certain"}),
        json.dumps({**VALID, "rationale": ""}),
        json.dumps({**VALID, "rationale": "x" * 1001}),
        json.dumps({**VALID, "rationale": "has\x00control"}),
        json.dumps({**VALID, "supporting_lines": []}),
        json.dumps({**VALID, "supporting_lines": ["10"]}),
        json.dumps({**VALID, "supporting_lines": [True]}),
        json.dumps({**VALID, "supporting_lines": list(range(1, 17))}),
    ],
)
def test_rejects_malformed_replies(bad: str) -> None:
    with pytest.raises(ContractError):
        parse_response(bad, first_line=10, last_line=11)


def test_rejects_a_line_citation_outside_the_shown_range() -> None:
    """A model citing a line it was never shown is a hallucinated citation, not a valid answer."""
    with pytest.raises(ContractError, match="outside the"):
        parse_response(_reply(supporting_lines=[999]), first_line=10, last_line=11)


def test_rejects_duplicate_keys() -> None:
    with pytest.raises(ContractError):
        parse_response('{"verdict": "unsure", "verdict": "likely_real"}', first_line=1, last_line=1)


def test_rejects_a_reply_that_is_far_too_long() -> None:
    with pytest.raises(ContractError):
        parse_response("x" * 9000, first_line=1, last_line=1)
