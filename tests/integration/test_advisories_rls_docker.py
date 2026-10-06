"""Week 68 under REAL Row-Level Security (migration 0040): the advisories themselves are public
and shared, but what they mean for an organization -- its impacts and what it has done about each
-- belongs to that organization alone. Matching runs on Postgres as `bulwark_worker`; another org's
session sees no impact, no state, nothing in the list and no impact view. Needs
`BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as `bulwark_worker`)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from core import inventory
from core.advisories import store, view
from core.advisories.osv import parse
from core.persistence import repo
from core.persistence.models import Advisory, AdvisoryImpact, AdvisoryState
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401

FIXTURES = Path(__file__).parent.parent / "fixtures" / "osv"
FIXTURE_IDS = sorted(p.stem for p in FIXTURES.glob("*.json"))


@pytest.fixture
def advisories(sessions: sessionmaker[Session]) -> Iterator[None]:  # noqa: F811
    """The fixture records, added if the database does not have them yet (it may already hold
    OSV's real data, which they are copies of), and removed afterwards only if they were added."""
    records = [r for r in (parse(p.read_bytes()) for p in sorted(FIXTURES.glob("*.json"))) if r]
    ids = [r.id for r in records]
    with sessions() as s:
        had = set(s.scalars(select(Advisory.id).where(Advisory.id.in_(ids))))
        store.upsert(s, [r for r in records if r.id not in had], source="test")
    yield
    with sessions() as s:
        s.execute(delete(Advisory).where(Advisory.id.in_([i for i in ids if i not in had])))
        s.commit()


def _sbom(s: Session, org: str, purl: str) -> None:
    sc = repo.create_scan(
        s, source_type="git", source_ref="https://example.com/a/b", source_label=f"{org}/svc",
        tools=["syft"], org_id=org,
    )  # fmt: skip
    assert sc.asset_id is not None
    inventory.record(s, org_id=org, asset_id=sc.asset_id, scan_id=sc.id, source="scan",
                     packages=[{"purl": purl}])  # fmt: skip


def test_impacts_and_states_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str], advisories: None  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        _sbom(s, a, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        mine = {r["vuln_key"] for r in view.listing(s, a, limit=500)}
        assert "CVE-2021-44228" in mine
    with sessions() as s:
        set_session_org(s, b)
        for model in (AdvisoryImpact, AdvisoryState):
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert view.listing(s, b) == [] and view.impact(s, b, "CVE-2021-44228") is None
        public = select(func.count()).select_from(Advisory).where(Advisory.id.in_(FIXTURE_IDS))
        assert s.scalar(public) == len(FIXTURE_IDS)  # the advisories are public: everyone reads
        _sbom(s, b, "pkg:npm/lodash@4.17.20")
        theirs = {r["vuln_key"] for r in view.listing(s, b, limit=500)}
        assert "CVE-2021-23337" in theirs and "CVE-2021-44228" not in theirs
    with sessions() as s:
        set_session_org(s, a)
        assert "CVE-2021-23337" not in {st.vuln_key for st in s.scalars(select(AdvisoryState))}
        assert view.impact(s, a, "CVE-2021-23337") is None
