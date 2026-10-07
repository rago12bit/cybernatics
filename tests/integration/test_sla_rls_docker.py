"""SLA policies under REAL Row-Level Security (migration 0033, Week 61): another org cannot read a
project's policy, and its SLA sweep never announces -- or even sees -- another org's Issues. The
deadline arithmetic runs in Postgres here too (the issues-table filter), not only in SQLite. Needs
`BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as `bulwark_worker`)."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.models import Severity
from core.persistence import repo
from core.persistence.models import IssueRow, SlaPolicy
from core.sla import service
from core.sla.policy import STARTER
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.unit.test_sla import finding


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:  # noqa: F811
    a, b = f"sla-a-{uuid.uuid4().hex[:8]}", f"sla-b-{uuid.uuid4().hex[:8]}"
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
            for table in (
                "issue_batches",
                "saved_views",
                "person_prefs",
                "report_links",
                "report_runs",
                "reports",
                "dashboards",
                "person_roles",
                "metric_open_issues",
                "metric_issue_days",
                "metric_sla_days",
                "metric_asset_status",
                "metric_components",
                "metric_dirty",
                "evidence_packs",
                "compliance_statuses",
                "vex_statements",
                "code_usage",
                "advisory_impacts",
                "advisory_states",
                "components",
                "libraries",
                "notifications",
                "issue_watchers",
                "notification_prefs",
                "ticket_configs",
                "rule_runs",
                "automation_rules",
                "risk_acceptance_issues",
                "risk_acceptances",
                "sla_policies",
                "priority_policies",
                "engagement_checklist_items",
                "retest_runs",
                "issue_notes",
                "tags",
                "outbox_events",
            ):  # audit entries are append-only
                s.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM findings WHERE scan_id IN "
                           "(SELECT id FROM scans WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM external_issue_links WHERE org_id = :o"), {"o": org})
            s.execute(text("UPDATE issues SET group_id = NULL WHERE asset_id IN "
                           "(SELECT id FROM assets WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM issue_groups WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM issues WHERE asset_id IN "
                           "(SELECT id FROM assets WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM engagements WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM api_tokens WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _project_with_issues(s: Session, org: str) -> str:
    sc = repo.create_scan(
        s, source_type="git", source_ref="https://example.com/a/b", source_label=f"{org}/web",
        tools=["semgrep"], org_id=org,
    )  # fmt: skip
    findings = [finding(1, Severity.HIGH), finding(2, Severity.HIGH), finding(3, Severity.HIGH)]
    sync = repo.sync_issues_for_scan(s, sc.id, findings)
    repo.add_findings(s, sc.id, findings, sync.updates)
    repo.finish_scan(s, sc.id, "completed")
    now = datetime.now(timezone.utc)
    for issue, days in zip(
        s.scalars(
            select(IssueRow).where(IssueRow.asset_id == sc.asset_id).order_by(IssueRow.title)
        ),
        (31, 25, 1),
        strict=True,
    ):
        issue.first_seen_at = now - timedelta(days=days)
    s.commit()
    return sc.asset_id  # type: ignore[return-value]


def test_a_policy_and_its_announcements_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    sent: list[Any] = []
    with sessions() as s:
        set_session_org(s, a)
        asset = _project_with_issues(s, a)
        service.save(s, org_id=a, asset_id=asset, enabled=True, bands=STARTER, actor="t")
        # The issues-table filter, with Postgres doing the deadline arithmetic.
        policy = service.policy_for(s, asset)
        now = datetime.now(timezone.utc)
        titles = {
            state: sorted(
                s.scalars(select(IssueRow.title).where(service.clause(policy, [state], now)))
            )
            for state in ("breached", "due_soon", "on_track")
        }
        assert titles == {"breached": ["Problem 1"], "due_soon": ["Problem 2"],
                          "on_track": ["Problem 3"]}  # fmt: skip
    with sessions() as s:
        set_session_org(s, b)
        assert s.scalar(select(func.count()).select_from(SlaPolicy)) == 0
        assert service.current(s, asset) is None
        assert service.sweep(s, b, notify=lambda *x: sent.append(x)).announced == 0
        assert s.scalar(select(func.count()).select_from(IssueRow)) == 0
    with sessions() as s:
        set_session_org(s, a)
        assert service.sweep(s, a, notify=lambda *x: sent.append(x)).announced == 2
        assert {i.sla_notified for i in s.scalars(select(IssueRow))} == {
            "breached",
            "due_soon",
            None,
        }
    assert len(sent) == 1
