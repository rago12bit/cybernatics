"""Week 64 under REAL Row-Level Security (migration 0036): an assessment's checklist results, an
Issue's notes and targeted retests, and tags belong to one organization -- another org's session
sees none of them, cannot read an engagement by id, and its tag filter matches nothing of the
first org's. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head, as `bulwark_worker`)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.collab import notes, tags
from core.engagements import service as engagements
from core.models import Severity
from core.persistence import repo
from core.persistence.models import (
    Engagement,
    EngagementChecklistItem,
    IssueNote,
    IssueRow,
    RetestRun,
    Tag,
)
from core.retest import service as retest
from core.retest import targeted
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401
from tests.unit.test_sla import finding


def test_engagements_notes_retests_and_tags_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        sc = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/a/b", source_label=f"{a}/web",
            tools=["semgrep"], org_id=a,
        )  # fmt: skip
        found = [finding(1, Severity.HIGH)]
        sync = repo.sync_issues_for_scan(s, sc.id, found)
        repo.add_findings(s, sc.id, found, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        asset = sc.asset_id
        assert asset is not None
        e = engagements.create(
            s, org_id=a, asset_id=asset, data={"name": "Q3 pentest", "checklist": "wstg-4.2"},
            actor="t",
        )  # fmt: skip
        engagements.set_item(s, e, "WSTG-INFO-01", "pass", "seen", actor="t")
        issue = s.scalars(select(IssueRow)).one()
        notes.add(s, issue, body="Reproduced on staging", author="t")
        tags.replace(
            s, org_id=a, target_type="issue", target_id=issue.id, names=["idor"], actor="t"
        )
        targeted.start(s, issue, actor="t")
        retest_status = s.get(IssueRow, issue.id).retest_status  # type: ignore[union-attr]
        assert retest_status == "requested"
        # the tag filter runs in Postgres
        hit = s.scalars(select(IssueRow.id).where(tags.issue_clause(["idor"]))).all()
        assert hit == [issue.id]
        ids = (e.id, issue.id)
    with sessions() as s:
        set_session_org(s, b)
        for model in (EngagementChecklistItem, IssueNote, RetestRun, Tag, IssueRow, Engagement):
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert engagements.get(s, ids[0], b) is None
        assert s.scalars(select(IssueRow.id).where(tags.issue_clause(["idor"]))).all() == []
        assert notes.mentions_of(s, b, "t") == []
    with sessions() as s:  # and the first org still sees all of it
        set_session_org(s, a)
        e2 = engagements.get(s, ids[0], a)
        assert e2 is not None
        state = engagements.checklist_state(s, e2)
        assert state is not None and state.summary()["pass"] == 1
        assert len(notes.thread(s, ids[1])) == 1
        assert len(targeted.runs(s, ids[1])) == 1
        assert retest.view(s.get(IssueRow, ids[1]))["status"] == "requested"  # type: ignore[arg-type]
