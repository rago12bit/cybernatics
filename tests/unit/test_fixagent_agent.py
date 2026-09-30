"""The tool-calling propose-patch loop (plan §21.2) against a fake Anthropic-shaped client -- the
same fake-block style `tests/unit/test_llm.py` already uses for `AnthropicClient` itself, extended
to `stop_reason`/`tool_use` blocks since this is the first tool-calling code in the repository.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from core.fixagent.agent import AgentGiveUp, propose_patch
from core.fixagent.context import gather_context
from core.models import Category, Finding, Location, Taxonomy

SRC = 'def get_user(uid):\n    return db.execute("SELECT * FROM users WHERE id=" + uid)\n'
GOOD_PATCH = (
    "--- a/app/users.py\n+++ b/app/users.py\n@@ -1,2 +1,2 @@\n"
    " def get_user(uid):\n"
    '-    return db.execute("SELECT * FROM users WHERE id=" + uid)\n'
    '+    return db.execute("SELECT * FROM users WHERE id=?", (uid,))\n'
)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    d = tmp_path / "repo"
    (d / "app").mkdir(parents=True)
    (d / "app" / "users.py").write_text(SRC)
    return d


@pytest.fixture
def ctx(repo: Path):  # type: ignore[no-untyped-def]
    f = Finding(
        "f1", "SQL injection", "d", Location("app/users.py", 2, 2, SRC),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip
    return gather_context(repo, f)


def _finding() -> Finding:
    return Finding(
        "f1", "SQL injection", "d", Location("app/users.py", 2, 2, SRC),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )  # fmt: skip


class Block:
    def __init__(self, type_: str, **kw: Any) -> None:
        self.type = type_
        for k, v in kw.items():
            setattr(self, k, v)


class Usage:
    def __init__(self, inp: int = 10, out: int = 5) -> None:
        self.input_tokens, self.output_tokens = inp, out


class Message:
    def __init__(self, content: list[Block], stop_reason: str = "tool_use") -> None:
        self.content = content
        self.stop_reason = stop_reason
        self.usage = Usage()


class FakeClient:
    model = "fake-model"

    def __init__(self, responses: list[Message]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, list[Any], list[Any]]] = []

    def complete_with_tools(self, system: str, messages: Any, tools: Any) -> Message:
        self.calls.append((system, list(messages), list(tools)))
        return self.responses.pop(0)


def propose_patch_block(
    patch: str = GOOD_PATCH, confidence: str = "high", id_: str = "t1"
) -> Block:
    return Block(
        "tool_use", id=id_, name="propose_patch",
        input={"explanation": "fix it", "patch": patch, "confidence": confidence},
    )  # fmt: skip


def test_a_model_that_proposes_a_valid_patch_immediately_succeeds(ctx: Any, repo: Path) -> None:
    client = FakeClient([Message([propose_patch_block()])])
    result = propose_patch(client, repo, _finding(), ctx)
    assert result.patch == GOOD_PATCH and result.confidence == "high" and result.tokens_used == 15
    assert len(client.calls) == 1


def test_a_model_that_reads_a_file_first_then_proposes_gets_a_real_tool_result(
    ctx: Any, repo: Path
) -> None:
    read_call = Block("tool_use", id="t0", name="read_file", input={"path": "app/users.py"})
    client = FakeClient([Message([read_call]), Message([propose_patch_block()])])
    result = propose_patch(client, repo, _finding(), ctx)
    assert result.patch == GOOD_PATCH
    assert len(client.calls) == 2
    # the second call's message history must contain the REAL file content as a tool result
    second_call_messages = client.calls[1][1]
    tool_result_blob = str(second_call_messages)
    assert "def get_user" in tool_result_blob


def test_an_invalid_patch_is_rejected_and_the_model_gets_one_more_chance(
    ctx: Any, repo: Path
) -> None:
    bad = propose_patch_block(patch="not a diff", id_="t1")
    client = FakeClient([Message([bad]), Message([propose_patch_block(id_="t2")])])
    result = propose_patch(client, repo, _finding(), ctx)
    assert result.patch == GOOD_PATCH and len(client.calls) == 2


def test_the_model_stopping_without_a_tool_call_gives_up(ctx: Any, repo: Path) -> None:
    client = FakeClient([Message([Block("text", text="I need more info")], stop_reason="end_turn")])
    with pytest.raises(AgentGiveUp):
        propose_patch(client, repo, _finding(), ctx)


def test_exceeding_max_turns_without_a_patch_gives_up(ctx: Any, repo: Path) -> None:
    from core.fixagent import agent as agent_mod

    searches = [
        Message([Block("tool_use", id=f"s{i}", name="search_code", input={"query": "x"})])
        for i in range(agent_mod.MAX_TURNS)
    ]
    client = FakeClient(searches)
    with pytest.raises(AgentGiveUp):
        propose_patch(client, repo, _finding(), ctx)
    assert len(client.calls) == agent_mod.MAX_TURNS


def test_feedback_from_a_previous_attempt_appears_in_the_first_message_not_as_repository_data(
    ctx: Any, repo: Path
) -> None:
    client = FakeClient([Message([propose_patch_block()])])
    propose_patch(client, repo, _finding(), ctx, feedback="the rule still flags this location")
    first_call_messages = client.calls[0][1]
    assert "the rule still flags this location" in str(first_call_messages)


def test_tool_results_are_scrubbed_for_secrets_before_reaching_the_model(
    ctx: Any, repo: Path
) -> None:
    (repo / "app" / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    read_call = Block("tool_use", id="t0", name="read_file", input={"path": "app/config.py"})
    client = FakeClient([Message([read_call]), Message([propose_patch_block()])])
    propose_patch(client, repo, _finding(), ctx)
    second_call_messages = client.calls[1][1]
    assert "AKIAIOSFODNN7EXAMPLE" not in str(second_call_messages)
