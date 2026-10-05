"""Priority policies under REAL Row-Level Security (migration 0035, Week 63): another org cannot
read a project's policy, its recomputation re-ranks only its own project's Issues (run as the
worker role, the way the background job runs), the preview never sees another org's Issues, and the
issues-table band filter runs in Postgres. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head,
as `bulwark_worker`)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.models import Severity
from core.persistence import repo
from core.persistence.models import IssueRow, PriorityPolicy
from core.priority import service
from core.priority.engine import STARTER
from core.tenancy import scoped_sessions, set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401
from tests.unit.test_sla import finding


def _project(s: Session, org: str) -> str:
    sc = repo.create_scan(
        s, source_type="git", source_ref="https://example.com/a/b", source_label=f"{org}/web",
        tools=["semgrep"], org_id=org,
    )  # fmt: skip
    findings = [finding(1, Severity.CRITICAL), finding(2, Severity.HIGH), finding(3, Severity.LOW)]
    sync = repo.sync_issues_for_scan(s, sc.id, findings)
    repo.add_findings(s, sc.id, findings, sync.updates)
    repo.finish_scan(s, sc.id, "completed")
    return sc.asset_id  # type: ignore[return-value]


def test_a_policy_and_its_recomputation_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        asset_a = _project(s, a)
        # ingest ranked every Issue (no policy yet: the v2 score, version 0)
        assert {i.priority_version for i in s.scalars(select(IssueRow))} == {0}
    with sessions() as s:
        set_session_org(s, b)
        asset_b = _project(s, b)
        before_b = {i.id: i.priority_score for i in s.scalars(select(IssueRow))}
    with sessions() as s:
        set_session_org(s, a)
        row = service.save(s, org_id=a, asset_id=asset_a, weights=STARTER,
                           context={"criticality": "critical"}, actor="t")  # fmt: skip
        policy_id = row.id
    # the background job, as the worker runs it: a fresh session scoped from the task's org
    with scoped_sessions(sessions, a)() as s:
        done = service.recompute(s, policy_id)
        assert done is not None and (done.status, done.processed) == ("done", 3)
        assert {i.priority_version for i in s.scalars(select(IssueRow))} == {1}
        # the band filter, in Postgres
        p1 = s.scalars(select(IssueRow.title).where(IssueRow.priority_band.in_(["P1"]))).all()
        assert "Problem 1" in p1
    with sessions() as s:
        set_session_org(s, b)
        assert s.scalar(select(func.count()).select_from(PriorityPolicy)) == 0
        assert service.current(s, asset_a) is None
        assert {i.id: i.priority_score for i in s.scalars(select(IssueRow))} == before_b
        assert service.preview(s, asset_a, STARTER, None)["open_issues"] == 0
        assert service.preview(s, asset_b, STARTER, None)["open_issues"] == 3
        # org B's job cannot run org A's policy: under B's scope it does not exist
        assert service.recompute(s, policy_id) is None
