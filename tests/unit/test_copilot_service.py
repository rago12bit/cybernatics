"""core.copilot.service.ask: the tool-calling turn loop against a fake Anthropic-shaped client --
the same fake-block style tests/unit/test_fixagent_agent.py uses for propose_patch, the first
tool-calling loop in this codebase."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.codeintel import analyze
from core.copilot.service import CopilotGiveUp, ask
from core.copilot.tools import CopilotContext
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo


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

    def complete_with_tools(self, system: str, messages: Any, tools: Any) -> Message:
        return self.responses.pop(0)


def _seed(sessions: sessionmaker[Session]) -> tuple[str, str, str]:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id="org-a",
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id, scan_id = scan.asset_id, scan.id
    assert asset_id is not None
    with sessions() as s:
        f = Finding(
            "f1", "SQL injection", "d", Location("a.py", 1, 1), Taxonomy(Category.SAST, cwe=("CWE-89",))
        )  # fmt: skip
        result = repo.sync_issues_for_scan(s, scan_id, [f])
        repo.add_findings(s, scan_id, [f], issue_updates=result.updates)
        issue_id = next(u.issue_id for u in result.updates if u.finding_id == "f1")
    return asset_id, scan_id, issue_id


def _ctx(
    sessions: sessionmaker[Session], asset_id: str, scan_id: str, checkout: Path
) -> CopilotContext:
    return CopilotContext(
        session=sessions(), org_id="org-a", asset_id=asset_id, latest_scan_id=scan_id,
        checkout=checkout, graph=analyze(checkout),
    )  # fmt: skip


def _answer_block(citations: list[dict[str, Any]], id_: str = "t1") -> Block:
    return Block(
        "tool_use",
        id=id_,
        name="give_answer",
        input={"answer": "here you go", "citations": citations},
    )


def test_a_model_that_answers_with_a_valid_citation_immediately_succeeds(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_id, scan_id, issue_id = _seed(sessions)
    ctx = _ctx(sessions, asset_id, scan_id, tmp_path)
    client = FakeClient([Message([_answer_block([{"kind": "issue", "issue_id": issue_id}])])])
    result = ask(client, ctx, "what issues are open?")
    assert result.answer == "here you go"
    assert result.citations == [{"kind": "issue", "issue_id": issue_id}]
    ctx.session.close()


def test_an_invalid_citation_is_rejected_then_a_retry_with_a_valid_one_succeeds(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_id, scan_id, issue_id = _seed(sessions)
    ctx = _ctx(sessions, asset_id, scan_id, tmp_path)
    client = FakeClient(
        [
            Message([_answer_block([{"kind": "issue", "issue_id": "ISS-BOGUS"}], id_="t1")]),
            Message([_answer_block([{"kind": "issue", "issue_id": issue_id}], id_="t2")]),
        ]
    )
    result = ask(client, ctx, "what issues are open?")
    assert result.citations == [{"kind": "issue", "issue_id": issue_id}]
    ctx.session.close()


def test_a_model_that_uses_a_real_tool_then_answers(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_id, scan_id, issue_id = _seed(sessions)
    ctx = _ctx(sessions, asset_id, scan_id, tmp_path)
    query_call = Block("tool_use", id="q1", name="query_issues", input={})
    client = FakeClient(
        [
            Message([query_call]),
            Message([_answer_block([{"kind": "issue", "issue_id": issue_id}], id_="t1")]),
        ]
    )
    result = ask(client, ctx, "what issues are open?")
    assert result.citations == [{"kind": "issue", "issue_id": issue_id}]
    ctx.session.close()


def test_a_model_that_never_calls_give_answer_gives_up(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    asset_id, scan_id, _ = _seed(sessions)
    ctx = _ctx(sessions, asset_id, scan_id, tmp_path)
    client = FakeClient([Message([], stop_reason="end_turn")])
    with pytest.raises(CopilotGiveUp):
        ask(client, ctx, "what issues are open?")
    ctx.session.close()
