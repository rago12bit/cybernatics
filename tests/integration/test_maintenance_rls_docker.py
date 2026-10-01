"""core.maintenance.reap_stale_scans, against REAL Postgres with real RLS -- not the SQLite
application-level tests in tests/unit/test_maintenance.py, which cannot exercise the bug this file
exists to catch: SQLite has no RLS, so a query with no `app.current_org` set still sees every row
there, masking the exact failure mode this function had in production (see its own docstring and
ADR-0036 -- this is a Week 50 fix, not a Week 50 feature, found live while doing Week 50's own
connection-pool work).

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head, connected
as the non-superuser `bulwark_worker` role (ADR-0033) -- exactly the connection the real worker uses
to run this exact function.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from core import maintenance
from core.events import MemoryPublisher
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
    a, b = f"reap-rls-a-{uuid.uuid4().hex[:8]}", f"reap-rls-b-{uuid.uuid4().hex[:8]}"
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
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _stuck_scan(sessions: sessionmaker[Session], org_id: str, started: datetime) -> str:
    with sessions() as s:
        set_session_org(s, org_id)
        scan = repo.create_scan(
            s, source_type="git", source_ref=f"https://x/{org_id}.git", source_label="x/y",
            tools=["bandit"], org_id=org_id,
        )  # fmt: skip
        scan.status, scan.started_at = "running", started
        s.commit()
        return scan.id


def test_a_stale_scan_is_reaped_even_though_no_org_context_is_set_before_the_call(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """The real regression: calling this with no `app.current_org` ever set on the caller's own
    session -- the exact way core.tasks.maintenance_task calls it -- must still reap real scans in
    other orgs' rows, which only genuinely proves something under real RLS. The old implementation
    queried `scans` directly on a session with no org context and would have seen (and reaped)
    nothing at all here; this assert is what would have failed before the fix."""
    org_a, org_b = two_orgs
    now = datetime.now(timezone.utc)
    stuck_a = _stuck_scan(sessions, org_a, now - timedelta(hours=2))
    stuck_b = _stuck_scan(sessions, org_b, now - timedelta(hours=2))

    reaped = maintenance.reap_stale_scans(sessions, timedelta(minutes=30), MemoryPublisher(), now)

    assert sorted(reaped) == sorted([stuck_a, stuck_b])
    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.get_scan(s, stuck_a, org_id=org_a).status == "failed"  # type: ignore[union-attr]
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_scan(s, stuck_b, org_id=org_b).status == "failed"  # type: ignore[union-attr]


def test_a_fresh_scan_in_one_org_is_not_reaped_by_another_orgs_sweep(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    now = datetime.now(timezone.utc)
    stuck_a = _stuck_scan(sessions, org_a, now - timedelta(hours=2))
    fresh_b = _stuck_scan(sessions, org_b, now - timedelta(minutes=1))

    reaped = maintenance.reap_stale_scans(sessions, timedelta(minutes=30), None, now)

    assert reaped == [stuck_a]
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_scan(s, fresh_b, org_id=org_b).status == "running"  # type: ignore[union-attr]
