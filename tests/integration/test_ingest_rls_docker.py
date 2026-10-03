"""Persistent Tests, import records and the event outbox (migration 0027, Week 54 task 2, ADR-0040),
against REAL Postgres with real Row-Level Security -- not the SQLite tests in
tests/unit/test_persistence_ingest.py, which cannot exercise whether FORCE ROW LEVEL SECURITY
actually stops one org's session from reading or writing another's rows.

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head, connected
as the non-superuser `bulwark_worker` role (ADR-0033) -- exactly the connection the real worker uses.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tenancy import set_session_org


def _rls_test_db_url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _postgres_ready() -> bool:
    url = _rls_test_db_url()
    if not url:
        return False
    try:
        create_engine(url).connect().close()
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


pytestmark = pytest.mark.skipif(
    not _postgres_ready(),
    reason="BULWARK_RLS_TEST_DATABASE_URL not set or not reachable -- see "
    ".github/workflows/ci.yml's tenancy-rls job",
)


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:
    a, b = f"ing-rls-a-{uuid.uuid4().hex[:8]}", f"ing-rls-b-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
            [{"id": a, "n": "A"}, {"id": b, "n": "B"}],
        )
        s.commit()
    yield a, b
    with sessions() as s:
        for org in (a, b):
            set_session_org(s, org)
            for table in ("outbox_events", "import_records", "engagement_tests"):
                s.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
            # engagements cascade from assets (migration 0026's own FK)
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _seed_test_and_import(sessions: sessionmaker[Session], org: str) -> tuple[str, str, str]:
    """One engagement, a persistent Test, and one applied import in it, all under `org`."""
    with sessions() as s:
        set_session_org(s, org)
        asset = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org)
        eng = repo.create_engagement(
            s, org_id=org, asset_id=asset.id, name="Q3 pentest", engagement_type="import"
        )
        test = repo.get_or_create_engagement_test(
            s, org_id=org, engagement_id=eng.id, name="Nessus", parser="nessus"
        )
        rec = repo.add_import_record(
            s, org_id=org, test_id=test.id, scan_id=None, parser="nessus", file_digest="a" * 64
        )
        s.commit()
        return eng.id, test.id, rec.id


def test_an_orgs_test_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    eng_id, test_id, _ = _seed_test_and_import(sessions, org_a)
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_engagement_test(s, test_id, org_b) is None
        # Org B cannot enumerate org A's engagement's tests by guessing its real id either.
        assert repo.list_engagement_tests(s, eng_id, org_b) == []
        # ...and cannot mint a Test under it.
        with pytest.raises(ValueError, match="not found"):
            repo.get_or_create_engagement_test(s, org_id=org_b, engagement_id=eng_id, name="x")
    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.get_engagement_test(s, test_id, org_a) is not None


def test_an_orgs_import_record_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    _, test_id, rec_id = _seed_test_and_import(sessions, org_a)
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_import_record(s, rec_id, org_b) is None
        assert repo.list_import_records(s, test_id, org_b) == []
        assert repo.latest_applied_import(s, test_id, org_b) is None
    with sessions() as s:
        set_session_org(s, org_a)
        latest = repo.latest_applied_import(s, test_id, org_a)
        assert latest is not None and latest.id == rec_id


def test_an_orgs_outbox_events_are_invisible_and_undispatchable_by_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.add_outbox_event(s, org_id=org_a, event_type="issue.created", payload={"x": 1})
        s.commit()
        event_id = repo.pending_outbox_events(s, org_a)[0].id
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.pending_outbox_events(s, org_b) == []
        # Even handed org A's real event id, org B's session cannot touch it.
        repo.mark_outbox_dispatched(s, org_b, [event_id])
    with sessions() as s:
        set_session_org(s, org_a)
        assert [e.id for e in repo.pending_outbox_events(s, org_a)] == [event_id]


def test_a_session_cannot_write_another_orgs_rows(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """Reads are not the only direction: with org B's context set, an INSERT stamped with org A's
    id must be refused by the policy itself, not just filtered out afterwards."""
    org_a, org_b = two_orgs
    eng_id, test_id, _ = _seed_test_and_import(sessions, org_a)
    with sessions() as s:
        set_session_org(s, org_b)
        with pytest.raises(DBAPIError, match="row-level security"):
            s.execute(
                text(
                    "INSERT INTO outbox_events (org_id, event_type, payload, created_at) "
                    "VALUES (:o, 'e', '{}', now())"
                ),
                {"o": org_a},
            )
        s.rollback()
    with sessions() as s:
        set_session_org(s, org_b)
        with pytest.raises(DBAPIError, match="row-level security"):
            s.execute(
                text(
                    "INSERT INTO engagement_tests (id, org_id, engagement_id, name, created_at) "
                    "VALUES (:id, :o, :e, 'forged', now())"
                ),
                {"id": str(uuid.uuid4()), "o": org_a, "e": eng_id},
            )
        s.rollback()
    with sessions() as s:
        set_session_org(s, org_a)
        assert [t.name for t in repo.list_engagement_tests(s, eng_id, org_a)] == ["Nessus"]
        assert repo.pending_outbox_events(s, org_a) == []


def test_a_fresh_connection_with_no_org_context_sees_none_of_the_new_tables(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """An unset app.current_org must read as "see nothing," not "see everything" -- see
    core.tenancy.set_session_org's own docstring on why this needs a genuinely fresh connection,
    never one reused from the pooled `sessions` fixture."""
    org_a, _ = two_orgs
    _seed_test_and_import(sessions, org_a)
    with sessions() as s:
        set_session_org(s, org_a)
        repo.add_outbox_event(s, org_id=org_a, event_type="issue.created", payload={})
        s.commit()

    fresh_engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    try:
        with fresh_engine.connect() as conn:
            for table in ("engagement_tests", "import_records", "outbox_events"):
                assert list(conn.execute(text(f"SELECT * FROM {table}"))) == [], table
    finally:
        fresh_engine.dispose()
