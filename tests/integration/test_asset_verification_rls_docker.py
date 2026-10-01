"""Real-Postgres RLS test for `asset_verifications` (Week 49 task 1, ADR-0035) -- same pattern and
same reason as `test_tenancy_rls_docker.py`: this table has no `org_id` column of its own, so its
join-based policy (through `assets.org_id`) needs a real Postgres planner to prove, not SQLite.

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a real Postgres already migrated to head, connected
as `bulwark_worker` -- exactly `.github/workflows/ci.yml`'s `tenancy-rls` job's own setup. Skips
everywhere else.
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
    a, b = f"rls-test-a-{uuid.uuid4().hex[:8]}", f"rls-test-b-{uuid.uuid4().hex[:8]}"
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
            s.execute(
                text(
                    "DELETE FROM asset_verifications WHERE asset_id IN "
                    "(SELECT id FROM assets WHERE org_id = :o)"
                ),
                {"o": org},
            )
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def test_a_verification_row_is_invisible_from_another_org_even_by_direct_id_lookup(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        asset, verification = repo.register_web_asset(
            s, domain="rls-test.example.com", method="dns_txt", org_id=org_a
        )
        asset_id, real_token = asset.id, verification.token

    # Org A, in its own session context, sees it.
    with sessions() as s:
        set_session_org(s, org_a)
        seen = repo.get_asset_verification(s, asset_id, org_id=org_a)
        assert seen is not None and seen.token == real_token

    # Org B's session context: RLS hides the row even when org_id filtering is bypassed entirely by
    # querying the table directly with the raw asset_id -- this is the real guarantee application-
    # level `org_id=` filtering alone can never provide.
    with sessions() as s:
        set_session_org(s, org_b)
        row = s.execute(
            text("SELECT * FROM asset_verifications WHERE asset_id = :id"), {"id": asset_id}
        ).first()
        assert row is None


def test_two_orgs_registering_the_same_domain_are_fully_isolated(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    with sessions() as s:
        set_session_org(s, org_a)
        asset_a, _ = repo.register_web_asset(
            s, domain="rls-shared.example.com", method="dns_txt", org_id=org_a
        )
    with sessions() as s:
        set_session_org(s, org_b)
        asset_b, _ = repo.register_web_asset(
            s, domain="rls-shared.example.com", method="dns_txt", org_id=org_b
        )
    assert asset_a.id != asset_b.id

    with sessions() as s:
        set_session_org(s, org_a)
        assert repo.get_asset_verification(s, asset_b.id, org_id=org_a) is None
    with sessions() as s:
        set_session_org(s, org_b)
        assert repo.get_asset_verification(s, asset_a.id, org_id=org_b) is None
