"""A session must always run as its own org, even when overlapping sessions share pooled connections
(found during Week 54 task 4; see core.tenancy._reapply_org_on_every_transaction).

Row-Level Security reads `app.current_org` from the *connection*, but a Session returns its
connection to the pool on every commit and takes whichever is free next. The original
`set_config(..., false)` put the org on a connection the session might never see again and left it
there for the next session to inherit -- so with two overlapping sessions for different orgs, the
first one's next statement after a commit ran as the second org. None of the single-session tests
above could see it; this one interleaves on purpose.

Needs `BULWARK_RLS_TEST_DATABASE_URL` (a Postgres migrated to head, connected as `bulwark_worker`).
"""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tenancy import set_session_org


def _url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _ready() -> bool:
    if not _url():
        return False
    try:
        create_engine(_url()).connect().close()  # type: ignore[arg-type]
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="BULWARK_RLS_TEST_DATABASE_URL not reachable")


@pytest.fixture
def tiny_pool() -> Iterator[sessionmaker[Session]]:
    """Two connections for everything, so overlapping sessions are forced to share them."""
    engine = create_engine(_url(), pool_size=2, max_overflow=0, pool_pre_ping=True)  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


def _current_org(s: Session) -> str | None:
    return s.execute(text("SELECT nullif(current_setting('app.current_org', true), '')")).scalar()


def test_a_session_still_runs_as_its_own_org_after_another_session_used_its_connection(
    tiny_pool: sessionmaker[Session],
) -> None:
    a, b = tiny_pool(), tiny_pool()
    try:
        set_session_org(a, "org-A")
        assert _current_org(a) == "org-A"
        a.commit()  # A's connection goes back to the pool...
        set_session_org(b, "org-B")  # ...and B can pick it up and set its own org.
        assert _current_org(b) == "org-B"
        b.commit()
        assert _current_org(a) == "org-A"  # A's next transaction must still be A's
        a.rollback()
        assert _current_org(a) == "org-A"  # and after a rollback too
        assert _current_org(b) == "org-B"
    finally:
        a.close()
        b.close()


def test_an_idle_pooled_connection_carries_no_org(tiny_pool: sessionmaker[Session]) -> None:
    with tiny_pool() as s:
        set_session_org(s, "org-A")
        assert _current_org(s) == "org-A"
        s.commit()
    # A connection nobody has claimed must read as "no org" (RLS: see nothing), never as org-A.
    with tiny_pool() as raw:
        assert _current_org(raw) is None


def test_a_session_with_no_org_sees_no_org_even_on_a_connection_used_by_another(
    tiny_pool: sessionmaker[Session],
) -> None:
    with tiny_pool() as a:
        set_session_org(a, "org-A")
        a.commit()
    with tiny_pool() as nobody:
        assert _current_org(nobody) is None


def test_many_overlapping_sessions_never_run_as_each_other(
    tiny_pool: sessionmaker[Session],
) -> None:
    """Stress: eight threads, eight orgs, two connections, each thread committing repeatedly and
    checking its org after every commit and rollback. Any inheritance shows up as a mismatch."""
    mismatches: list[str] = []
    errors: list[BaseException] = []

    def work(org: str) -> None:
        try:
            with tiny_pool() as s:
                set_session_org(s, org)
                for step in range(40):
                    seen = _current_org(s)
                    if seen != org:
                        mismatches.append(f"{org} ran as {seen} at step {step}")
                    if step % 3 == 0:
                        s.rollback()
                    else:
                        s.commit()
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(f"org-{n}",)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors, errors
    assert mismatches == []


def test_rows_stay_with_their_own_org_when_sessions_interleave(
    tiny_pool: sessionmaker[Session],
) -> None:
    """The consequence that matters: with the old behaviour A, mid-request, could read (and write
    into) B's tenant. Seed one portfolio per org, interleave, and read back."""
    a_org, b_org = f"pool-a-{uuid.uuid4().hex[:8]}", f"pool-b-{uuid.uuid4().hex[:8]}"
    with tiny_pool() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
            [{"id": a_org, "n": "A"}, {"id": b_org, "n": "B"}],
        )
        s.commit()
    try:
        a, b = tiny_pool(), tiny_pool()
        try:
            set_session_org(a, a_org)
            repo.create_portfolio(a, org_id=a_org, name="A's payments")  # commits inside
            set_session_org(b, b_org)
            repo.create_portfolio(b, org_id=b_org, name="B's payments")
            # A is mid-request, having committed once; B has run in between on the same pool.
            assert [p.name for p in repo.list_portfolios(a, a_org)] == ["A's payments"]
            assert [p.name for p in repo.list_portfolios(b, b_org)] == ["B's payments"]
            assert repo.list_portfolios(a, b_org) == []  # A cannot read B's rows
        finally:
            a.close()
            b.close()
    finally:
        with tiny_pool() as s:
            for org in (a_org, b_org):
                set_session_org(s, org)
                s.execute(text("DELETE FROM portfolios WHERE org_id = :o"), {"o": org})
            s.execute(
                text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a_org, "b": b_org}
            )
            s.commit()
