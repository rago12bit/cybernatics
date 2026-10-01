"""Per-org plugin allowlist (core.persistence.models.PluginAllowlistRow), against REAL Postgres with
real RLS -- not the SQLite application-level tests in tests/unit/test_persistence_plugin_allowlist.py,
which cannot exercise the one thing that actually matters here: that FORCE ROW LEVEL SECURITY really
stops one organization's session from seeing another's allowlist rows, not merely that the Python
code remembers to filter by org_id (Week 51 task 1, plan §23).

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head, connected
as the non-superuser `bulwark_worker` role (ADR-0033) -- exactly the connection the real worker uses
when `core.plugins.registry.resolve_adapters` calls `core.persistence.repo.is_plugin_allowed`.
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
    a, b = f"plugin-rls-a-{uuid.uuid4().hex[:8]}", f"plugin-rls-b-{uuid.uuid4().hex[:8]}"
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
            s.execute(text("DELETE FROM plugin_allowlist WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def test_an_orgs_allowlist_row_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """The real regression this file exists to catch: is_plugin_allowed must read FALSE for org B
    even though a row exists for the same plugin name under org A -- SQLite's unit-test equivalent
    cannot tell "correctly isolated by RLS" apart from "happened to filter correctly in Python,"
    since SQLite enforces nothing here at all."""
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.set_plugin_allowed(s, org_a, "acme-plugin", enabled=True, allowed_by="token:a")

    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.is_plugin_allowed(s, org_b, "acme-plugin") is False
        assert repo.list_plugin_allowlist(s, org_b) == []

    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.is_plugin_allowed(s, org_a, "acme-plugin") is True


def test_a_brand_new_connection_with_no_org_context_set_sees_no_allowlist_rows_at_all(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """An unset app.current_org must read as "see nothing," not "see everything" -- the exact
    failure mode core.maintenance.reap_stale_scans had before its own Week 50 fix, and precisely why
    core.plugins.registry.resolve_adapters refuses to resolve a plugin at all when no org_id/session
    is supplied, rather than falling back to some "trust every org" default.

    Deliberately a brand-new engine/connection, never the pooled `sessions` fixture used elsewhere
    in this file: `set_session_org` sets `app.current_org` session-scoped, not transaction-local
    (its own docstring explains why), so a *reused* pooled connection legitimately keeps whatever
    the previous logical session last set -- that's not a leak, it's why `api.deps.db` and
    `scoped_sessions` both call it unconditionally on every session they open, never relying on a
    pooled connection's previous state. This test's claim is about a connection that has never had
    any org context set at all, which only a fresh connection can actually demonstrate."""
    org_a, _ = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.set_plugin_allowed(s, org_a, "acme-plugin", enabled=True, allowed_by="token:a")

    fresh_engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    try:
        with fresh_engine.connect() as conn:
            rows = list(conn.execute(text("SELECT * FROM plugin_allowlist")))
    finally:
        fresh_engine.dispose()
    assert rows == []


def test_an_org_cannot_revoke_another_orgs_plugin_by_guessing_its_name(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.set_plugin_allowed(s, org_a, "acme-plugin", enabled=True, allowed_by="token:a")

    with sessions() as s:
        set_session_org(s, org_b)
        repo.set_plugin_allowed(s, org_b, "acme-plugin", enabled=False, allowed_by="token:b")

    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.is_plugin_allowed(s, org_a, "acme-plugin") is True  # untouched by org B's write
