"""Week 70 under REAL Row-Level Security (migration 0042): the metric summary tables belong to one
organization. Marking on flush, refreshing and every metric run as `bulwark_worker`; another org's
session sees no row and no number. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.metrics import query, rollup
from core.metrics.definitions import METRICS
from core.models import Severity
from core.persistence import repo
from core.persistence.models import (
    Library,
    MetricAssetStatus,
    MetricComponent,
    MetricDirty,
    MetricIssueDay,
    MetricOpenIssue,
    MetricSlaDay,
)
from core.sla import service
from core.sla.policy import STARTER
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401
from tests.unit.test_sla import finding

MODELS = (MetricOpenIssue, MetricIssueDay, MetricSlaDay, MetricAssetStatus, MetricComponent,
          MetricDirty)  # fmt: skip


def _project(s: Session, org: str, n: int) -> str:
    sc = repo.create_scan(s, source_type="git", source_ref="https://example.com/m/n",
                          source_label=f"{org}/svc", tools=["semgrep"], org_id=org)  # fmt: skip
    found = [finding(i, Severity.HIGH) for i in range(n)]
    sync = repo.sync_issues_for_scan(s, sc.id, found)
    repo.add_findings(s, sc.id, found, sync.updates)
    repo.finish_scan(s, sc.id, "completed")
    assert sc.asset_id is not None
    return sc.asset_id


def test_metric_rows_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        asset = _project(s, a, 7)
        assert s.scalar(select(func.count()).select_from(MetricDirty)) == 1  # marked on flush
        service.save(s, org_id=a, asset_id=asset, enabled=True, bands=STARTER, actor="t")
        lib = Library(org_id=a, ecosystem="npm", name="zq-lib", key="npm:zq-lib",
                      purl="pkg:npm/zq-lib")  # fmt: skip
        s.add(lib)
        s.commit()
        rollup.refresh_all(s, a)
        # A component row and a dirty mark, so every table has something to hide.
        s.add(MetricComponent(org_id=a, library_id=lib.id, asset_id=asset, vulns=1, kev=0))
        rollup.mark(s, a, ["zq-pending"])
        s.commit()
        for model in MODELS:
            assert s.scalar(select(func.count()).select_from(model)), model.__tablename__
        assert query.compute(s, a, "open_issues", query.Filters())["value"] == 7
    with sessions() as s:
        set_session_org(s, b)
        for model in MODELS:
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        for m in METRICS:
            out = query.compute(s, b, m.id, query.Filters())
            assert out["value"] in (0, None), m.id
        _project(s, b, 2)
        rollup.refresh_dirty(s, b)
        assert query.compute(s, b, "open_issues", query.Filters())["value"] == 2
    with sessions() as s:
        set_session_org(s, a)
        assert query.compute(s, a, "open_issues", query.Filters())["value"] == 7
