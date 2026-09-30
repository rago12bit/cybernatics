"""core.triage_assistant.service.assess: the propose-a-verdict call, against a fake model."""

from __future__ import annotations

import json

from core.llm.client import Completion
from core.llm.prompt import CodeContext
from core.models import Category, Finding, Location, Taxonomy
from core.triage_assistant.service import assess

VALID = json.dumps(
    {
        "verdict": "likely_real",
        "confidence": "high",
        "rationale": "The input reaches the sink unsanitized.",
        "supporting_lines": [10],
    }
)


class FakeModel:
    model = "fake-model-1"

    def __init__(self, out: str | Exception | list[str | Exception], tokens: int = 10) -> None:
        self.out = out if isinstance(out, list) else [out]
        self.calls: list[tuple[str, str]] = []
        self.tokens = tokens

    def complete(self, system: str, user: str) -> Completion:
        self.calls.append((system, user))
        item = self.out[min(len(self.calls) - 1, len(self.out) - 1)]
        if isinstance(item, Exception):
            raise item
        return Completion(item, self.tokens)


def _finding() -> Finding:
    return Finding(
        "f1", "SQL injection", "d", Location("app/users.py", 10, 10, "snippet"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip


def test_no_client_means_no_verdict_not_a_guess() -> None:
    assert assess(_finding(), None, None) is None


def test_a_valid_reply_produces_an_assessment() -> None:
    client = FakeModel(VALID)
    result = assess(_finding(), client, CodeContext("code", 10))
    assert result is not None
    assert result.verdict.verdict == "likely_real"
    assert result.model == "fake-model-1"
    assert result.tokens_used == 10
    assert len(client.calls) == 1


def test_a_malformed_reply_is_repaired_once() -> None:
    client = FakeModel(["not json", VALID])
    result = assess(_finding(), client, CodeContext("code", 10))
    assert result is not None
    assert result.verdict.verdict == "likely_real"
    assert result.tokens_used == 20  # both calls counted
    assert len(client.calls) == 2


def test_two_failed_attempts_return_no_verdict() -> None:
    client = FakeModel(["not json", "still not json"])
    assert assess(_finding(), client, CodeContext("code", 10)) is None


def test_a_transport_failure_returns_no_verdict_not_a_crash() -> None:
    client = FakeModel(RuntimeError("boom"))
    assert assess(_finding(), client, CodeContext("code", 10)) is None


def test_a_hallucinated_line_citation_is_rejected_and_repaired() -> None:
    bad = json.dumps(
        {
            "verdict": "likely_real",
            "confidence": "high",
            "rationale": "x",
            "supporting_lines": [9999],
        }
    )
    client = FakeModel([bad, VALID])
    result = assess(_finding(), client, CodeContext("code", 10))
    assert result is not None and result.verdict.verdict == "likely_real"


def test_the_repair_note_never_echoes_the_rejected_reply() -> None:
    client = FakeModel(["some secret-looking rejected text", VALID])
    assess(_finding(), client, CodeContext("code", 10))
    _, second_user = client.calls[1]
    assert "some secret-looking rejected text" not in second_user
