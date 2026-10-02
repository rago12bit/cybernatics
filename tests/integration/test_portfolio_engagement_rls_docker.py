"""Portfolio and Engagement (migration 0026, Week 53 task 4, plan §40 change C11, ADR-0039),
against REAL Postgres with real Row-Level Security -- not the SQLite application-level tests in
tests/unit/test_persistence_portfolio_engagement.py, which cannot exercise whether FORCE ROW LEVEL
SECURITY actually stops one org's session from seeing another's portfolios, engagements, or the
Tests (ToolRun rows) inside them.

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head, connected
as the non-superuser `bulwark_worker` role (ADR-0033) -- exactly the connection the real worker uses.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
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
    a, b = f"pe-rls-a-{uuid.uuid4().hex[:8]}", f"pe-rls-b-{uuid.uuid4().hex[:8]}"
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
            # tool_runs/scans cascade-delete nothing of ours on asset delete except themselves;
            # engagements CASCADE from assets (migration 0026's own FK), portfolios are independent.
            s.execute(text("DELETE FROM portfolios WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def test_an_orgs_portfolio_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        portfolio = repo.create_portfolio(s, org_id=org_a, name="Payments")
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_portfolio(s, portfolio.id, org_b) is None
        assert repo.list_portfolios(s, org_b) == []
    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.get_portfolio(s, portfolio.id, org_a) is not None
        assert [p.name for p in repo.list_portfolios(s, org_a)] == ["Payments"]


def test_an_orgs_engagement_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        asset = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org_a)
        engagement = repo.get_or_create_ci_engagement(s, asset_id=asset.id, org_id=org_a)
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_engagement(s, engagement.id, org_b) is None
        # Org B also cannot enumerate org A's asset's engagements by guessing its real asset id.
        assert repo.list_engagements_for_asset(s, asset.id, org_b) == []
    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.get_engagement(s, engagement.id, org_a) is not None


def test_an_orgs_tests_toolruns_in_an_engagement_are_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """The Tests inside an Engagement are ToolRun rows (ADR-0039) -- their own RLS policy
    (migration 0005, unchanged by this week's work) is an EXISTS join through `scans`, not a direct
    org_id column; this is the live proof that still holds once an engagement_id is attached."""
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://x", source_label="a/b",
            tools=["bandit"], org_id=org_a,
        )  # fmt: skip
        repo.add_tool_run(s, scan.id, "bandit", {"status": "ok", "findings": 3})
        engagement = repo.get_or_create_ci_engagement(s, asset_id=scan.asset_id, org_id=org_a)
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.list_tool_runs_for_engagement(s, engagement.id, org_b) == []
    with sessions() as s:
        set_session_org(s, org_a)
        tests = repo.list_tool_runs_for_engagement(s, engagement.id, org_a)
        assert [t.tool for t in tests] == ["bandit"]


def test_a_fresh_connection_with_no_org_context_sees_no_portfolios_or_engagements_at_all(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """An unset app.current_org must read as "see nothing," not "see everything" -- the same
    fail-closed guarantee every other RLS-protected table in this project has (see
    core.tenancy.set_session_org's own docstring on why this needs a genuinely fresh connection,
    never one reused from the pooled `sessions` fixture)."""
    org_a, _ = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.create_portfolio(s, org_id=org_a, name="Payments")
        asset = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org_a)
        repo.get_or_create_ci_engagement(s, asset_id=asset.id, org_id=org_a)

    fresh_engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    try:
        with fresh_engine.connect() as conn:
            assert list(conn.execute(text("SELECT * FROM portfolios"))) == []
            assert list(conn.execute(text("SELECT * FROM engagements"))) == []
    finally:
        fresh_engine.dispose()
