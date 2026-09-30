"""core.persistence.repo's copilot-conversation functions (Week 44 task 3, plan §21.5):
create_conversation/get_conversation/add_message/list_messages."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo


def _asset(sessions: sessionmaker[Session], org_id: str = "org-a") -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=org_id,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def test_create_conversation_round_trips_context(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        row = repo.create_conversation(s, asset_id, context_kind="issue", context_id="ISS-1")
        conv_id = row.id
        assert row.asset_id == asset_id
        assert row.context_kind == "issue" and row.context_id == "ISS-1"
    with sessions() as s:
        fetched = repo.get_conversation(s, conv_id)
        assert fetched is not None and fetched.id == conv_id


def test_create_conversation_with_no_context_is_allowed(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        row = repo.create_conversation(s, asset_id)
        assert row.context_kind is None and row.context_id is None


def test_get_conversation_is_scoped_to_the_requesting_org(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions, org_id="org-a")
    with sessions() as s:
        conv_id = repo.create_conversation(s, asset_id).id
    with sessions() as s:
        assert repo.get_conversation(s, conv_id, org_id="org-b") is None
        assert repo.get_conversation(s, conv_id, org_id="org-a") is not None


def test_get_conversation_unknown_id_returns_none(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        assert repo.get_conversation(s, "no-such-conversation") is None


def test_add_message_stores_it_and_bumps_last_message_at(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        conv = repo.create_conversation(s, asset_id)
        conv_id, original_last_message_at = conv.id, conv.last_message_at
    with sessions() as s:
        row = repo.add_message(s, conv_id, role="user", content="what issues are open?")
        assert row.role == "user" and row.content == "what issues are open?"
        assert row.citations is None and row.tokens_used is None
    with sessions() as s:
        conv = repo.get_conversation(s, conv_id)
        assert conv is not None and conv.last_message_at >= original_last_message_at


def test_add_message_stores_citations_and_tokens_for_an_assistant_message(
    sessions: sessionmaker[Session],
) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        conv_id = repo.create_conversation(s, asset_id).id
    citations = [{"kind": "issue", "issue_id": "ISS-1"}]
    with sessions() as s:
        row = repo.add_message(
            s, conv_id, role="assistant", content="here's what I found", citations=citations,
            tokens_used=42,
        )  # fmt: skip
        assert row.citations == citations and row.tokens_used == 42


def test_list_messages_returns_them_in_creation_order(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions)
    with sessions() as s:
        conv_id = repo.create_conversation(s, asset_id).id
        repo.add_message(s, conv_id, role="user", content="q1")
        repo.add_message(s, conv_id, role="assistant", content="a1")
        repo.add_message(s, conv_id, role="user", content="q2")
    with sessions() as s:
        msgs = repo.list_messages(s, conv_id)
        assert [m.content for m in msgs] == ["q1", "a1", "q2"]


def test_list_messages_is_scoped_to_the_requesting_org(sessions: sessionmaker[Session]) -> None:
    asset_id = _asset(sessions, org_id="org-a")
    with sessions() as s:
        conv_id = repo.create_conversation(s, asset_id).id
        repo.add_message(s, conv_id, role="user", content="q1")
    with sessions() as s:
        assert repo.list_messages(s, conv_id, org_id="org-b") == []
        assert len(repo.list_messages(s, conv_id, org_id="org-a")) == 1
