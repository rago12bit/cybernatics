"""core.hypotheses.contract: the Hypotheses lane's output contract (plan §21.4)."""

from __future__ import annotations

import json

import pytest

from core.hypotheses.contract import ContractError, parse_response

SURFACED = {
    "surface": True,
    "evidence": "The sibling route requires login_required; this one has no such decorator.",
    "suggested_check": "Call the endpoint without a session cookie and see if it still succeeds.",
    "confidence": "medium",
}
DECLINED = {
    "surface": False,
    "evidence": "This looks like a public health check endpoint.",
    "suggested_check": "",
    "confidence": "high",
}


def test_a_surfaced_reply_parses() -> None:
    r = parse_response(json.dumps(SURFACED))
    assert r.surface is True and r.confidence == "medium"


def test_a_declined_reply_with_an_empty_suggested_check_parses() -> None:
    r = parse_response(json.dumps(DECLINED))
    assert r.surface is False and r.suggested_check == ""


def test_surface_true_requires_a_non_empty_suggested_check() -> None:
    with pytest.raises(ContractError, match="non-empty"):
        parse_response(json.dumps({**SURFACED, "suggested_check": ""}))


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        json.dumps({"surface": True}),  # missing fields
        json.dumps({**SURFACED, "extra": "x"}),
        json.dumps({**SURFACED, "surface": "yes"}),
        json.dumps({**SURFACED, "confidence": "certain"}),
        json.dumps({**SURFACED, "evidence": ""}),
        json.dumps({**SURFACED, "evidence": "x" * 1201}),
        json.dumps({**SURFACED, "suggested_check": "x" * 801}),
        json.dumps({**SURFACED, "evidence": "has\x00control"}),
    ],
)
def test_rejects_malformed_replies(bad: str) -> None:
    with pytest.raises(ContractError):
        parse_response(bad)


def test_tolerates_one_json_fence() -> None:
    r = parse_response(f"```json\n{json.dumps(SURFACED)}\n```")
    assert r.surface is True
