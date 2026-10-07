"""Week 71 under REAL Row-Level Security (migration 0043): a dashboard, even one shared with every
role, and the role a person picked belong to one organization. Run as `bulwark_worker`; another
org's session sees no row, cannot fetch, save or delete it, and its listing holds only the built-in
dashboard. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head)."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core import dashboards as svc
from core.persistence.models import Dashboard, PersonRole
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401

WIDGET = {"id": "a", "metric": "open_issues", "x": 0, "y": 0, "w": 6, "h": 4}


def test_dashboards_and_roles_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        svc.set_role(s, a, "token:alice", "lead")
        v = svc.Viewer("token:alice", "lead")
        d = svc.create(s, a, v, {"name": "Program", "shared_with": list(svc.ROLES),
                                 "widgets": [WIDGET]})  # fmt: skip
        did = d.id
        for model in (Dashboard, PersonRole):
            assert s.scalar(select(func.count()).select_from(model)) == 1, model.__tablename__
    with sessions() as s:
        set_session_org(s, b)
        for model in (Dashboard, PersonRole):
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert svc.role_of(s, b, "token:alice") is None
        # Even the operator of org B, and a lead of B, see only the built-in dashboard.
        for viewer in (svc.Viewer(svc.SHARED_TOKEN, None), svc.Viewer("token:alice", "lead")):
            assert [x["id"] for x in svc.listing(s, b, viewer)] == [svc.PROGRAM["id"]]
            for act in (
                lambda v: svc.get(s, b, did, v),
                lambda v: svc.update(s, b, v, did, {"version": 1, "name": "x"}),
                lambda v: svc.delete(s, b, v, did),
                lambda v: svc.copy_of(s, b, v, did),
            ):
                with pytest.raises(svc.DashboardError) as err:
                    act(viewer)
                assert err.value.status == 404
                s.rollback()
                set_session_org(s, b)
        # Asking for org A's id while acting for B is still filtered by the database.
        assert s.get(Dashboard, did) is None
    with sessions() as s:
        set_session_org(s, a)
        assert svc.get(s, a, did, svc.Viewer("token:bob", "tester")).name == "Program"


def test_overviews_and_homes_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    from core.metrics import portfolio, rollup
    from core.persistence.models import IssueRow, Portfolio
    from tests.integration.test_metrics_rls_docker import _project

    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        unit = Portfolio(org_id=a, name="Payments")
        s.add(unit)
        s.commit()
        asset = _project(s, a, 3)
        from core.persistence.models import Asset

        s.get(Asset, asset).portfolio_id = unit.id  # type: ignore[union-attr]
        for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset)):
            i.assignee = "token:alice"
        s.commit()
        rollup.refresh_all(s, a)
        assert [o["name"] for o in portfolio.overviews(s, a)] == ["Payments"]
        assert svc.assigned(s, a, "token:alice")["total"] == 3
        uid = unit.id
    with sessions() as s:
        set_session_org(s, b)
        assert portfolio.overviews(s, b) == []
        with pytest.raises(LookupError):
            portfolio.overview(s, b, uid)
        assert svc.assigned(s, b, "token:alice") == {"total": 0, "rows": []}
        assert svc.my_engagements(s, b, "token:alice") == []
