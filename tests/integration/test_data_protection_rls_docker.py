"""scan_data_keys' and data_retention_policies' Row-Level Security and cascade delete (Week 47 task
1/2, plan §22.2), against REAL Postgres with real RLS -- not the SQLite application-level tests in
tests/unit/test_persistence_scan_data_keys.py / test_persistence_retention_settings.py, which cannot
exercise either: SQLite has no RLS equivalent, and does not enforce foreign-key constraints by
default, so the migrations' `ON DELETE CASCADE` needs a real engine to prove.

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head, connected
as the non-superuser `bulwark_app` role (ADR-0013) -- exactly the connection the real worker uses.
Skips everywhere else, the same way tests/integration/test_tenancy_rls_docker.py does.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import DEFAULT_RETENTION_DAYS
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
    reason="BULWARK_RLS_TEST_DATABASE_URL not set or not reachable (needs a migrated Postgres, "
    "connected as bulwark_app) -- set up by .github/workflows/ci.yml's tenancy-rls job",
)


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_rls_test_db_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:
    a, b = f"dp-rls-test-a-{uuid.uuid4().hex[:8]}", f"dp-rls-test-b-{uuid.uuid4().hex[:8]}"
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
            s.execute(text("DELETE FROM scan_data_keys WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM data_retention_policies WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _seed_scan_with_key(sessions: sessionmaker[Session], org_id: str, wrapped: bytes) -> str:
    with sessions() as s:
        set_session_org(s, org_id)
        scan = repo.create_scan(
            s, source_type="git", source_ref=f"https://x/{org_id}.git", source_label="x/y",
            tools=["bandit"], org_id=org_id,
        )  # fmt: skip
        repo.save_scan_data_key(s, scan.id, org_id, wrapped)
        return scan.id


def test_an_orgs_data_key_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    scan_id = _seed_scan_with_key(sessions, org_a, b"org-a-wrapped-key")

    with sessions() as s:
        set_session_org(s, org_a)
        row = repo.get_scan_data_key(s, scan_id)
        assert row is not None and row.wrapped_dek == b"org-a-wrapped-key"

    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_scan_data_key(s, scan_id) is None


def test_an_org_cannot_delete_another_orgs_data_key(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    scan_id = _seed_scan_with_key(sessions, org_a, b"org-a-wrapped-key")

    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.delete_scan_data_key(s, scan_id) is False  # RLS: nothing visible to delete

    with sessions() as s:
        set_session_org(s, org_a)
        row = repo.get_scan_data_key(s, scan_id)
        assert row is not None and row.wrapped_dek == b"org-a-wrapped-key"


def test_deleting_the_scan_cascades_to_its_data_key_on_real_postgres(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, _ = two_orgs
    scan_id = _seed_scan_with_key(sessions, org_a, b"org-a-wrapped-key")

    with sessions() as s:
        set_session_org(s, org_a)
        scan = repo.get_scan(s, scan_id)
        assert scan is not None
        s.delete(scan)
        s.commit()

    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.get_scan_data_key(s, scan_id) is None


def test_an_orgs_retention_setting_is_invisible_to_another_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        repo.set_retention_days(s, org_a, 45)

    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.get_retention_days(s, org_a) == 45

    with sessions() as s:
        set_session_org(s, org_b)
        # RLS hides org A's row entirely -- org B sees the plan's own default, not org A's value,
        # even though this call still explicitly passes org_a's id: RLS is the real enforcement,
        # not just the application code filtering correctly.
        assert repo.get_retention_days(s, org_a) == DEFAULT_RETENTION_DAYS
