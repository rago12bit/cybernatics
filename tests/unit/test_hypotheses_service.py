"""core.hypotheses.service: assess_candidate and the generate_for_checkout orchestration pass."""

from __future__ import annotations

import json
from pathlib import Path

from core.codeintel.models import Entrypoint
from core.hypotheses.facts import Candidate
from core.hypotheses.service import assess_candidate, generate_for_checkout
from core.llm.client import Completion

SURFACED = json.dumps(
    {
        "surface": True,
        "evidence": "No auth decorator, unlike the sibling route.",
        "suggested_check": "Call it without a session and see if it still works.",
        "confidence": "medium",
    }
)
DECLINED = json.dumps(
    {
        "surface": False,
        "evidence": "Looks like a public health check.",
        "suggested_check": "",
        "confidence": "high",
    }
)


class FakeModel:
    model = "fake-model-1"

    def __init__(self, out: str | Exception | list[str | Exception]) -> None:
        self.out = out if isinstance(out, list) else [out]
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> Completion:
        self.calls.append((system, user))
        item = self.out[min(len(self.calls) - 1, len(self.out) - 1)]
        if isinstance(item, Exception):
            raise item
        return Completion(item, 10)


def _candidate() -> Candidate:
    route = Entrypoint("app.py:delete_user:2", "flask", "DELETE", "/users/1")
    sibling = Entrypoint("app.py:list_users:1", "flask", "GET", "/users", ("login_required",))
    return Candidate(route, "app.py", 2, (sibling,))


def test_no_client_means_no_hypothesis() -> None:
    assert assess_candidate(_candidate(), "code", None) is None


def test_a_surfaced_reply_produces_an_assessment() -> None:
    result = assess_candidate(_candidate(), "def delete_user(): pass", FakeModel(SURFACED))
    assert result is not None
    assert result.result.surface is True
    assert result.model == "fake-model-1"


def test_a_declined_reply_still_produces_an_assessment_the_caller_can_filter() -> None:
    result = assess_candidate(_candidate(), "code", FakeModel(DECLINED))
    assert result is not None and result.result.surface is False


def test_a_malformed_reply_is_repaired_once() -> None:
    result = assess_candidate(_candidate(), "code", FakeModel(["not json", SURFACED]))
    assert result is not None and result.result.surface is True


def test_two_failed_attempts_return_none() -> None:
    assert assess_candidate(_candidate(), "code", FakeModel(["nope", "still nope"])) is None


def test_generate_for_checkout_with_no_client_does_no_work(tmp_path: Path) -> None:
    assert generate_for_checkout(tmp_path, None) == []


def test_generate_for_checkout_end_to_end_against_a_real_directory(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.get('/users')\n"
        "@login_required\n"
        "def list_users():\n"
        "    pass\n"
        "\n"
        "@app.delete('/users/<id>')\n"
        "def delete_user(id):\n"
        "    db.delete(User, id)\n"
    )
    surfaced = generate_for_checkout(tmp_path, FakeModel(SURFACED))
    assert len(surfaced) == 1
    candidate, assessment = surfaced[0]
    assert candidate.route.path == "/users/<id>"
    assert assessment.result.surface is True
    assert "delete_user" in assessment.snippet


def test_generate_for_checkout_drops_declined_candidates(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "@app.get('/users')\n@login_required\ndef list_users():\n    pass\n\n"
        "@app.get('/health')\ndef health():\n    pass\n"
    )
    assert generate_for_checkout(tmp_path, FakeModel(DECLINED)) == []
