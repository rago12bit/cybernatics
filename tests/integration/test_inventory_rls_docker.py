"""Week 67 under REAL Row-Level Security (migration 0039): libraries and components belong to one
organization. Recorded on Postgres (the `ON CONFLICT` path for libraries included); another org's
session finds no library, no component and no search result for the same purl. Needs
`BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as `bulwark_worker`)."""

from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from core import inventory
from core.persistence import repo
from core.persistence.models import Asset, ComponentRow, Library
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401

LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core"


def _record(s: Session, org: str, version: str, project: str = "svc") -> None:
    sc = repo.create_scan(
        s, source_type="git", source_ref=f"https://example.com/a/{project}",
        source_label=f"{org}/{project}",
        tools=["syft"], org_id=org,
    )  # fmt: skip
    assert sc.asset_id is not None
    inventory.record(
        s, org_id=org, asset_id=sc.asset_id, scan_id=sc.id, source=inventory.SCAN_SOURCE,
        packages=[{"purl": f"{LOG4J}@{version}"}, {"purl": "pkg:npm/lodash@4.17.21"}],
    )  # fmt: skip


def test_the_inventory_stays_in_its_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        _record(s, a, "2.14.1")
        _record(s, a, "2.17.1", "web")  # the same libraries again: found, not inserted twice
        assert s.scalar(select(func.count()).select_from(Library)) == 2
        r = inventory.search(s, a, purl=LOG4J, constraint="<2.17.1")
        assert r.summary()["projects"] == 1 and r.uses[0].version == "2.14.1"
    with sessions() as s:
        set_session_org(s, b)
        for model in (Library, ComponentRow):
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert inventory.search(s, b, purl=LOG4J).library is None
        assert inventory.libraries(s, b) == []
        _record(s, b, "2.0")  # its own log4j-core: a separate library row, under its own org
        assert inventory.search(s, b, purl=LOG4J).summary()["projects"] == 1
    with sessions() as s:
        set_session_org(s, a)
        assert [lib["projects"] for lib in inventory.libraries(s, a)] == [2, 2]
        assert {u.version for u in inventory.search(s, a, purl=LOG4J).uses} == {"2.14.1", "2.17.1"}


def test_a_deleted_project_leaves_the_counts_after_the_recount(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, _b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        _record(s, a, "2.14.1")
        _record(s, a, "2.17.1", "web")
        web = repo.get_or_create_asset(s, source_type="git", source_label=f"{a}/web", org_id=a)
        s.execute(delete(Asset).where(Asset.id == web.id))  # its components go with it
        s.commit()
        assert inventory.search(s, a, purl=LOG4J).summary()["projects"] == 1  # exact at once
        assert inventory.recount_org(s, a) == 2
        assert [lib["projects"] for lib in inventory.libraries(s, a)] == [1, 1]
