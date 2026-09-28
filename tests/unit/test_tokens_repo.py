"""API token and audit-log persistence (Week 29/30 backfill), on SQLite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tokens import hash_token


def test_create_and_look_up_a_token_by_hash(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        row, raw = repo.create_api_token(s, org_id="org-a", name="ci", scopes=["scans:read"])
        assert raw.startswith("bulwark_")
        found = repo.get_api_token_by_hash(s, hash_token(raw))
        assert found is not None and found.id == row.id and found.org_id == "org-a"
        assert repo.get_api_token_by_hash(s, "0" * 64) is None


def test_revoked_token_is_still_findable_but_marked_revoked(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        row, raw = repo.create_api_token(s, org_id="org-a", name="ci", scopes=["scans:read"])
        assert repo.revoke_api_token(s, row.id) is True
        assert repo.revoke_api_token(s, row.id) is False  # already revoked
        found = repo.get_api_token_by_hash(s, hash_token(raw))
        assert found is not None and found.revoked_at is not None


def test_list_api_tokens_is_scoped_to_one_org(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        repo.create_api_token(s, org_id="org-a", name="a1", scopes=["scans:read"])
        repo.create_api_token(s, org_id="org-b", name="b1", scopes=["scans:read"])
        a = repo.list_api_tokens(s, "org-a")
        b = repo.list_api_tokens(s, "org-b")
    assert {t.name for t in a} == {"a1"}
    assert {t.name for t in b} == {"b1"}


def test_touch_updates_last_used_at(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        row, _ = repo.create_api_token(s, org_id="org-a", name="ci", scopes=["scans:read"])
        assert row.last_used_at is None
        repo.touch_api_token(s, row.id)
        refreshed = s.get(type(row), row.id)
        assert refreshed is not None and refreshed.last_used_at is not None


def test_expired_token_is_still_returned_by_lookup(sessions: sessionmaker[Session]) -> None:
    """The lookup itself doesn't enforce expiry -- `api/deps.py`'s auth layer does, so this is
    checked there, not silently swallowed here where a caller might forget to check it."""
    with sessions() as s:
        past = datetime.now(timezone.utc) - timedelta(days=1)
        row, raw = repo.create_api_token(
            s, org_id="org-a", name="old", scopes=["scans:read"], expires_at=past
        )
        found = repo.get_api_token_by_hash(s, hash_token(raw))
        assert found is not None and found.id == row.id and found.expires_at == past


def test_audit_chain_appends_correctly_and_links(sessions: sessionmaker[Session]) -> None:
    import core.audit as audit

    with sessions() as s:
        e1 = repo.append_audit_entry(s, actor="test", action="a.one", target="x", payload={"n": 1})
        e2 = repo.append_audit_entry(s, actor="test", action="a.two", target="y", payload={"n": 2})
        entries = repo.list_audit_entries(s)
    assert [e.seq for e in entries] == [1, 2]
    assert e1.prev_hash == audit.GENESIS_HASH
    assert e2.prev_hash == e1.entry_hash
    assert audit.verify_chain(entries).ok


def test_list_audit_entries_since_seq_excludes_earlier_ones(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        for i in range(5):
            repo.append_audit_entry(s, actor="t", action="a", target=str(i), payload={})
        later = repo.list_audit_entries(s, since_seq=3)
    assert [e.seq for e in later] == [4, 5]


def test_checkpoints_are_recorded_and_listed_in_order(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        e1 = repo.append_audit_entry(s, actor="t", action="a", target="1", payload={})
        cp1 = repo.record_checkpoint(
            s, seq_end=e1.seq, chain_hash=e1.entry_hash, signature_bundle="{}", rekor_log_index=42
        )
        assert repo.latest_checkpoint(s).id == cp1.id
        e2 = repo.append_audit_entry(s, actor="t", action="a", target="2", payload={})
        cp2 = repo.record_checkpoint(
            s, seq_end=e2.seq, chain_hash=e2.entry_hash, signature_bundle="{}", rekor_log_index=43
        )
        checkpoints = repo.list_checkpoints(s)
        latest = repo.latest_checkpoint(s)
    assert [c.id for c in checkpoints] == [cp1.id, cp2.id]
    assert latest is not None and latest.id == cp2.id
