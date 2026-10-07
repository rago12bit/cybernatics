"""`/fix` on pull requests under REAL Row-Level Security (migration 0050, Week 76): another
organization cannot see or write a request or the runs it started; someone limited to some projects
sees only those projects' requests and runs -- including a run with no Issue, reached only through
its request; a run must name an Issue or a request; a GitHub login is linked to at most one person
per organization, without case. Needs `BULWARK_RLS_TEST_DATABASE_URL`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from core.identity import users as people
from core.persistence import repo
from core.persistence.models import PrFixRequest, User, VerifiedFixRun
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401

NOW = datetime.now(timezone.utc)


def _request(s: Session, org: str, label: str, user: str) -> tuple[str, str, str]:
    """A pull request scan of a project, a /fix request on it, and the run it started:
    (project id, request id, run id)."""
    set_session_org(s, org)
    sc = repo.create_scan(
        s, source_type="git", source_ref=f"https://github.com/{label}.git",
        source_label=f"{label}#7", asset_label=f"https://github.com/{label}.git",
        tools=["semgrep"], org_id=org, ref="refs/pull/7/head", github_repo=label,
        github_pr_number=7, github_installation_id="42", github_head_sha="a" * 40,
    )  # fmt: skip
    set_session_org(s, org)
    req = PrFixRequest(
        org_id=org, asset_id=sc.asset_id, scan_id=sc.id, installation_id="42", repo=label,
        pr_number=7, head_sha="a" * 40, code=f"C{label[-6:].upper()}"[:12], finding_ids=["f1"],
        tokens_per_finding=1000, token_cap=1000, status="started", requested_by=user,
        requested_login="ana-gh", created_at=NOW, expires_at=NOW + timedelta(hours=24),
    )  # fmt: skip
    s.add(req)
    s.flush()
    run = VerifiedFixRun(org_id=org, issue_id=None, pr_fix_request_id=req.id, finding_id="f1",
                         workflow_id=f"wf-{req.id}", verification_record=[])  # fmt: skip
    s.add(run)
    s.commit()
    assert sc.asset_id is not None
    return sc.asset_id, req.id, run.id


def _person(s: Session, org: str, email: str) -> str:
    set_session_org(s, org)
    u = people.create(s, org, "test", email=email, role="member")
    s.commit()
    return u.id


def test_requests_and_their_runs_stay_in_their_organization(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        ana = _person(s, a, "ana@a.test")
        bob = _person(s, b, "bob@b.test")
        _, req_a, run_a = _request(s, a, f"acme/{a[-6:]}", ana)
        _request(s, b, f"beta/{b[-6:]}", bob)
    with sessions() as s:
        set_session_org(s, b)
        assert s.get(PrFixRequest, req_a) is None
        assert s.get(VerifiedFixRun, run_a) is None
        assert all(r.org_id == b for r in s.scalars(select(PrFixRequest)))
        assert all(r.org_id == b for r in s.scalars(select(VerifiedFixRun)))
        # Nor can it write one into the other organization.
        s.execute(text("UPDATE pr_fix_requests SET status = 'cancelled' WHERE id = :i"),
                  {"i": req_a})  # fmt: skip
        s.commit()
    with sessions() as s:
        set_session_org(s, a)
        row = s.get(PrFixRequest, req_a)
        assert row is not None and row.status == "started"
    with sessions() as s, pytest.raises(ProgrammingError, match="row-level security"):
        set_session_org(s, b)
        s.execute(text(
            "INSERT INTO pr_fix_requests (id, org_id, asset_id, scan_id, installation_id, repo, "
            "pr_number, head_sha, code, finding_ids, tokens_per_finding, token_cap, status, "
            "requested_by, requested_login, created_at, expires_at) SELECT gen_random_uuid()::text, :a, asset_id, "
            "scan_id, '1', 'r/r', 1, head_sha, 'ZZZZZZ', '[]', 1, 1, 'previewed', requested_by, "
            "'x', now(), now() FROM pr_fix_requests WHERE org_id = :b LIMIT 1"
        ), {"a": a, "b": b})  # fmt: skip


def test_someone_limited_to_one_project_sees_only_its_requests_and_runs(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
) -> None:
    a, _ = two_orgs
    with sessions() as s:
        ana = _person(s, a, "ana@a.test")
        mine, req_p, run_p = _request(s, a, f"acme/p{a[-5:]}", ana)
        _, req_q, run_q = _request(s, a, f"acme/q{a[-5:]}", ana)
    with sessions() as s:
        set_session_org(s, a, projects=frozenset({mine}))
        assert {r.id for r in s.scalars(select(PrFixRequest))} == {req_p}
        # A pull request run has no Issue: it is reached only through its request.
        assert {r.id for r in s.scalars(select(VerifiedFixRun))} == {run_p}
        assert s.get(VerifiedFixRun, run_q) is None and s.get(PrFixRequest, req_q) is None
    with sessions() as s:
        set_session_org(s, a)
        assert {req_p, req_q} <= {r.id for r in s.scalars(select(PrFixRequest))}


def test_a_run_names_an_issue_or_a_request(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
) -> None:
    a, _ = two_orgs
    with (
        sessions() as s,
        pytest.raises(IntegrityError, match="ck_verified_fix_runs_issue_or_request"),
    ):
        set_session_org(s, a)
        s.add(VerifiedFixRun(org_id=a, issue_id=None, pr_fix_request_id=None,
                             workflow_id=f"wf-orphan-{a}", verification_record=[]))  # fmt: skip
        s.commit()


def test_a_github_login_belongs_to_one_person_per_organization(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        ana, also = _person(s, a, "ana@a.test"), _person(s, a, "also@a.test")
        bob = _person(s, b, "bob@b.test")
        set_session_org(s, a)
        people.update_user(s, a, "test", ana, {"github_login": "Ana-GH"})
        s.commit()
        with pytest.raises(people.UserError, match="already linked"):
            people.update_user(s, a, "test", also, {"github_login": "ana-gh"})
        s.rollback()
        # The database holds the line too, not only the service.
        set_session_org(s, a)
        with pytest.raises(IntegrityError, match="uq_users_org_github_login"):
            s.execute(text("UPDATE users SET github_login = 'ANA-gh' WHERE id = :i"), {"i": also})
        s.rollback()
        set_session_org(s, b)  # another organization may have its own person with that login
        people.update_user(s, b, "test", bob, {"github_login": "ana-gh"})
        s.commit()
        set_session_org(s, b)
        row = s.get(User, bob)
        assert row is not None and row.github_login == "ana-gh"
