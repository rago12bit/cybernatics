"""Week 72 under REAL Row-Level Security (migration 0044): a report and its generated PDFs belong
to one organization. A link resolves with no organization set (`report_links` has no RLS, like
`api_tokens`), then the PDF is read under the link's organization; another organization's session
sees no report and no PDF, cannot list or revoke the link, and the link cannot be turned into a
read of another organization's PDF. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head)."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.persistence.models import Report, ReportLink, ReportRun
from core.reports import pdf, service
from core.reports.blocks import ReportError
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401


def test_reports_runs_and_links_stay_in_their_org(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pdf, "to_pdf", lambda html: b"%PDF-1.7 fake\n" + html.encode())
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        r = service.create(s, a, "token:alice", {"name": "Weekly", "template": "program-weekly"})
        run = service.generate(s, a, "token:alice", r.id)
        link, token = service.create_link(s, a, "token:alice", run.id, 7)
        s.commit()
        rid, run_id, link_id = r.id, run.id, link.id
        for model in (Report, ReportRun):
            assert s.scalar(select(func.count()).select_from(model)) == 1, model.__tablename__
    with sessions() as s:
        set_session_org(s, b)
        for model in (Report, ReportRun):
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert s.get(ReportRun, run_id) is None  # by id, still nothing
        for act in (
            lambda: service.get(s, b, rid),
            lambda: service.generate(s, b, "token:bob", rid),
            lambda: service.links(s, b, run_id),
            lambda: service.revoke_link(s, b, "token:bob", link_id),
        ):
            with pytest.raises(ReportError) as err:
                act()
            assert err.value.status == 404
            s.rollback()
            set_session_org(s, b)
    with sessions() as s:  # a visitor following the link: no organization yet
        found = service.resolve_link(s, token)
        assert found is not None and found.org_id == a
        assert s.get(ReportRun, run_id) is None  # under RLS, no org means no PDF
        set_session_org(s, found.org_id)
        got = s.get(ReportRun, found.run_id)
        assert got is not None and got.pdf.startswith(b"%PDF-")
    with sessions() as s:
        set_session_org(s, b)  # the link's row is visible here (no RLS), the PDF is not
        assert s.get(ReportLink, link_id) is not None and s.get(ReportRun, run_id) is None
