"""Risk acceptance under REAL Row-Level Security (migration 0034, Week 62): another org cannot see
a request, approve it, or have the expiry job touch it; the whole lifecycle -- request, approve,
expire with an SLA restart -- runs as the worker role. Needs `BULWARK_RLS_TEST_DATABASE_URL`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.acceptance import service
from core.persistence.models import IssueRow, RiskAcceptance, RiskAcceptanceIssue
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import _project_with_issues, two_orgs  # noqa: F401


def test_a_risk_acceptance_belongs_to_one_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    now = datetime.now(timezone.utc)
    with sessions() as s:
        set_session_org(s, a)
        asset = _project_with_issues(s, a)
        issue_ids = list(s.scalars(select(IssueRow.id).where(IssueRow.asset_id == asset)))
        ra = service.request(
            s, org_id=a, asset_id=asset, issue_ids=issue_ids[:2], decision="accept",
            justification="Retired in November.", controls="WAF rule 9412.", proof_links=[],
            expires_at=now + timedelta(days=30), restart_sla=True, approver=None,
            actor="token:alice", max_days=90,
        )  # fmt: skip
        ra_id = ra.id
    with sessions() as s:
        set_session_org(s, b)
        assert s.scalar(select(func.count()).select_from(RiskAcceptance)) == 0
        assert s.scalar(select(func.count()).select_from(RiskAcceptanceIssue)) == 0
        assert service.get(s, ra_id, b) is None and service.list_for(s, b) == []
        assert (
            service.expire_due(s, b, now=now + timedelta(days=60), notify=lambda *x: None).expired
            == []
        )
    with sessions() as s:
        set_session_org(s, a)
        row = service.get(s, ra_id, a)
        assert row is not None
        service.approve(s, row, actor="token:bob", note=None)
        assert sorted(i.triage_status for i in s.scalars(select(IssueRow))) == [
            "accepted", "accepted", "open",
        ]  # fmt: skip
        later = now + timedelta(days=31)
        assert len(service.expire_due(s, a, now=later, notify=lambda *x: None).expired) == 1
        reopened = [i for i in s.scalars(select(IssueRow)) if i.sla_started_at is not None]
        assert len(reopened) == 2 and {i.triage_status for i in reopened} == {"open"}
