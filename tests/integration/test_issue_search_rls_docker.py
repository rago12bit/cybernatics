"""Week 73 under REAL Row-Level Security: the org-wide Issues search sees only its organization's
Issues whatever the query or the cursor says; past the cap the count is still exact when it is
quick, and a count that runs out of time is cut off without disturbing the rest of the request.
Needs `BULWARK_RLS_TEST_DATABASE_URL`."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from core.models import Severity
from core.persistence import repo
from core.persistence.models import IssueRow
from core.search import issues as search
from core.search.language import parse
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401
from tests.unit.test_sla import finding


def _project(s: Session, org: str, label: str, n: int) -> list[str]:
    set_session_org(s, org)
    sc = repo.create_scan(s, source_type="git", source_ref=f"https://example.com/{label}",
                          source_label=label, tools=["semgrep"], org_id=org)  # fmt: skip
    found = [finding(i, Severity.HIGH) for i in range(n)]
    sync = repo.sync_issues_for_scan(s, sc.id, found)
    repo.add_findings(s, sc.id, found, sync.updates)
    repo.finish_scan(s, sc.id, "completed")
    s.commit()
    set_session_org(s, org)
    return [i.id for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == sc.asset_id))]


def test_search_stays_in_its_org_and_estimates_past_the_cap(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    a, b = two_orgs
    with sessions() as s:
        mine = _project(s, a, "acme/payments-api", 6)
        theirs = _project(s, b, "acme/payments-secret", 4)
    ctx = search.Context(None, datetime.now(timezone.utc))
    with sessions() as s:
        set_session_org(s, a)
        for q in ("", "project:*", "project:acme/payments-secret", "status:open,fixed"):
            got = {r["id"] for r in search.search(s, a, parse(q), ctx=ctx, limit=200)["rows"]}
            assert not got & set(theirs), q
        page = search.search(s, a, parse(""), ctx=ctx, limit=200)
        assert {r["id"] for r in page["rows"]} == set(mine)
        assert page["count"] == {"value": 6, "exact": True}
        # A cursor naming the other org's Issue is only a place to start, and shows nothing of it.
        cursor = search._encode("priority", 99, theirs[0])
        after = search.search(s, a, parse(""), ctx=ctx, after=cursor, limit=200)
        assert not {r["id"] for r in after["rows"]} & set(theirs)
        # Past the cap, a quick full count is still exact.
        monkeypatch.setattr(search, "COUNT_CAP", 2)
        assert search.search(s, a, parse(""), ctx=ctx, limit=1)["count"] == {
            "value": 6, "exact": True}  # fmt: skip
        # A statement that runs out of time is cut off (None), inside a savepoint: the session,
        # its organization and its own time limit are as they were.
        before = s.scalar(text("SHOW statement_timeout"))
        assert search.bounded(s, text("SELECT pg_sleep(2)"), 50) is None
        assert s.scalar(text("SHOW statement_timeout")) == before
        assert search.bounded(s, text("SELECT 41 + 1"), 50) == 42
        assert s.scalar(text("SHOW statement_timeout")) == before
        assert {r["id"] for r in search.search(s, a, parse(""), ctx=ctx, limit=200)["rows"]} == set(
            mine
        )
    with sessions() as s:  # and the other way round
        set_session_org(s, b)
        got = {r["id"] for r in search.search(s, b, parse("project:*"), ctx=ctx)["rows"]}
        assert got == set(theirs)
