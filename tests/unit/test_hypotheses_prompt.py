"""core.hypotheses.prompt: nonce-fenced prompt construction for the Hypotheses lane."""

from __future__ import annotations

import re

from core.codeintel.models import Entrypoint
from core.hypotheses.facts import Candidate
from core.hypotheses.prompt import build_prompt


def _candidate(markers: tuple[str, ...] = ()) -> Candidate:
    route = Entrypoint("app.py:delete_user:2", "flask", "DELETE", "/users/<id>", markers)
    sibling = Entrypoint("app.py:list_users:1", "flask", "GET", "/users", ("login_required",))
    return Candidate(route, "app.py", 2, (sibling,))


def test_facts_and_code_are_nonce_fenced() -> None:
    p = build_prompt(_candidate(), "def delete_user(id):\n    db.delete(User, id)")
    begins = re.findall(r"=====BEGIN UNTRUSTED DATA \[([0-9a-f]{32})\]", p.user)
    ends = re.findall(r"=====END UNTRUSTED DATA \[([0-9a-f]{32})\]", p.user)
    assert begins and begins == ends and all(n == p.nonce for n in begins)


def test_sibling_markers_are_named_in_the_facts_block() -> None:
    p = build_prompt(_candidate(), "code")
    assert "login_required" in p.user
    assert "DELETE /users/<id>" in p.user


def test_the_candidates_own_markers_are_shown_as_none_when_empty() -> None:
    p = build_prompt(_candidate(), "code")
    assert "Candidate's own auth-looking markers: none" in p.user


def test_secrets_are_scrubbed_from_code() -> None:
    p = build_prompt(_candidate(), 'key = "AKIAIOSFODNN7EXAMPLE"')
    assert "AKIAIOSFODNN7EXAMPLE" not in p.user
    assert p.secrets_scrubbed >= 1


def test_system_prompt_tells_the_model_to_propose_not_confirm() -> None:
    p = build_prompt(_candidate(), "code")
    assert "HYPOTHESIS" in p.system
