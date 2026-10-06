"""Week 66 under REAL Row-Level Security (migration 0038): notifications, watchers, notification
preferences, issue groups and ticket settings belong to one organization. Notifications are made
from the outbox on Postgres; another org's session sees none of these rows, its inbox for the same
person is empty, and its dispatcher finds nothing. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres
at head, as `bulwark_worker`)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.collab import notes
from core.dispatch import dispatch, drain
from core.models import Severity
from core.notify import prefs
from core.notify import service as notify
from core.persistence import repo
from core.persistence.models import (
    IssueGroup,
    IssueRow,
    IssueWatcher,
    Notification,
    NotificationPrefs,
    TicketConfig,
)
from core.tenancy import set_session_org
from core.tickets import groups
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401
from tests.unit.test_sla import finding


def test_notifications_groups_and_ticket_settings_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        sc = repo.create_scan(
            s,
            source_type="git",
            source_ref="https://example.com/a/b",
            source_label=f"{a}/web",
            tools=["semgrep"],
            org_id=a,
        )
        found = [finding(1, Severity.HIGH)]
        sync = repo.sync_issues_for_scan(s, sc.id, found)
        repo.add_findings(s, sc.id, found, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        priya, _ = repo.create_api_token(s, org_id=a, name="Priya N.", scopes=["scans:read"])
        arjun, _ = repo.create_api_token(s, org_id=a, name="Arjun K.", scopes=["scans:read"])
        arjun_actor = f"token:{arjun.display_prefix}"
        issue = s.scalars(select(IssueRow)).one()
        notes.add(s, issue, body="@arjunk look", author=f"token:{priya.display_prefix}")
        prefs.save(s, a, arjun_actor, {"email": "arjun@acme.example"}, actor=arjun_actor)
        g = groups.get_or_create(s, a, issue.asset_id, "jinja2 upgrade", actor="t")
        groups.set_group(s, a, issue, g, actor="t")
        s.add(TicketConfig(org_id=a, asset_id=issue.asset_id, provider="jira", target="PAY",
                           status_source="ticket", status_map={}, enabled=True))  # fmt: skip
        s.commit()
        assert drain(s, a) > 0
        assert [n.title for n in notify.inbox(s, a, arjun_actor)] == [
            "Priya N. mentioned you on “Problem 1”"
        ]
    with sessions() as s:
        set_session_org(s, b)
        for model in (Notification, IssueWatcher, NotificationPrefs, IssueGroup, TicketConfig):
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert notify.inbox(s, b, arjun_actor) == []
        assert notify.unread(s, b, arjun_actor) == 0
        assert dispatch(s, b) == 0
    with sessions() as s:  # the first org still sees all of it
        set_session_org(s, a)
        assert notify.unread(s, a, arjun_actor) == 1
        assert s.scalar(select(func.count()).select_from(IssueWatcher)) == 2  # author, mentioned
