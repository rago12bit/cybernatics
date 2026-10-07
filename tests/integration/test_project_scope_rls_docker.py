"""Week 75's two-project access test under REAL Row-Level Security (plan §51: "the two-tenant test
(§19.1) gains a two-project variant"). A session limited to one project sees that project's rows
and none of the other's -- in the project table itself, in tables that name a project, and in
tables that reach one through an Issue, a scan or an acceptance -- cannot change the other's, and a
session in the guest role that never said which projects it may see sees none; and a session
with every project is not in the guest role, so pays nothing for the policies. Needs
`BULWARK_RLS_TEST_DATABASE_URL`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text, update
from sqlalchemy.orm import Session, sessionmaker

from core.metrics import rollup
from core.persistence.models import (
    Asset,
    Engagement,
    FindingRow,
    IssueNote,
    IssueRow,
    MetricOpenIssue,
    RiskAcceptance,
    RiskAcceptanceIssue,
    Scan,
    SlaPolicy,
)
from core.sla import service as sla
from core.sla.policy import STARTER
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_issue_search_rls_docker import _project
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401

NOW = datetime.now(timezone.utc)


def _asset_of(s: Session, issue: str) -> str:
    row = s.get(IssueRow, issue)
    assert row is not None
    return row.asset_id


def test_a_session_limited_to_one_project_sees_and_changes_only_that_one(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
) -> None:
    a, _ = two_orgs
    with sessions() as s:
        mine = _project(s, a, "acme/payments-api", 3)
        theirs = _project(s, a, "acme/ledger", 3)
        set_session_org(s, a)
        p, q = _asset_of(s, mine[0]), _asset_of(s, theirs[0])
        # Something of each kind on the project the session must not see.
        ra = RiskAcceptance(org_id=a, asset_id=q, decision="accept", justification="x",
                            controls="", state="approved", expires_at=NOW + timedelta(days=9),
                            requested_by="t", requested_at=NOW)  # fmt: skip
        s.add(ra)
        s.flush()
        s.add(RiskAcceptanceIssue(acceptance_id=ra.id, issue_id=theirs[0], org_id=a))
        s.add(Engagement(org_id=a, asset_id=q, name="Q4", engagement_type="pentest",
                         status="active"))  # fmt: skip
        s.add(IssueNote(org_id=a, issue_id=theirs[0], body="secret plans", author="t"))
        s.add(IssueNote(org_id=a, issue_id=mine[0], body="fine", author="t"))
        s.commit()
        for project in (p, q):
            sla.save(s, org_id=a, asset_id=project, enabled=True, bands=STARTER, actor="t")
            set_session_org(s, a)
        rollup.refresh_all(s, a)

    with sessions() as s:
        set_session_org(s, a, frozenset({p}))
        assert set(s.scalars(select(Asset.id))) == {p}
        assert set(s.scalars(select(IssueRow.id))) == set(mine)
        assert {sc.asset_id for sc in s.scalars(select(Scan))} == {p}
        scans = set(s.scalars(select(Scan.id)))
        assert {f.scan_id for f in s.scalars(select(FindingRow))} <= scans
        assert s.scalars(select(RiskAcceptance)).all() == []
        assert s.scalars(select(RiskAcceptanceIssue)).all() == []
        assert s.scalars(select(Engagement)).all() == []
        assert [n.body for n in s.scalars(select(IssueNote))] == ["fine"]
        assert {r.asset_id for r in s.scalars(select(SlaPolicy))} == {p}
        assert {r.asset_id for r in s.scalars(select(MetricOpenIssue))} == {p}
        assert s.scalar(text("SELECT current_user")) == "bulwark_guest"
        # The other project's rows cannot be changed or added to either.
        changed = s.execute(update(IssueRow).where(IssueRow.id == theirs[1])
                            .values(title="pwned")).rowcount  # fmt: skip
        assert changed == 0
        s.rollback()

    with sessions() as s:  # nothing granted: nothing seen
        set_session_org(s, a, frozenset())
        assert s.scalars(select(Asset.id)).all() == []
        assert s.scalars(select(IssueRow.id)).all() == []

    with sessions() as s:  # the guest role without its list of projects: nothing
        s.execute(text("SELECT set_config('app.current_org', :o, false)"), {"o": a})
        s.execute(text("SET ROLE bulwark_guest"))
        assert s.scalars(select(Asset.id)).all() == []
        assert s.scalars(select(IssueRow.id)).all() == []
        s.rollback()
        s.execute(text("RESET ROLE"))

    with sessions() as s:  # every project, as every worker and organization role has
        set_session_org(s, a)
        assert s.scalar(text("SELECT current_user")) != "bulwark_guest"  # no policy cost at all
        assert set(s.scalars(select(Asset.id))) == {p, q}
        assert s.get(IssueRow, theirs[1]).title != "pwned"  # type: ignore[union-attr]


def test_through_the_api_a_guest_sees_only_their_project(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
    tmp_path: object,
) -> None:
    """The whole path on Postgres: a session cookie, the person's overrides, the guest role and its
    policies, the API's routes."""
    from pathlib import Path

    from fastapi.testclient import TestClient

    from api.deps import AppState
    from api.main import create_app
    from core.config import Settings
    from core.identity import sessions as web
    from core.identity import users as svc

    a, _ = two_orgs
    with sessions() as s:
        mine = _project(s, a, "acme/payments-api", 2)
        theirs = _project(s, a, "acme/ledger", 2)
        set_session_org(s, a)
        p, q = _asset_of(s, mine[0]), _asset_of(s, theirs[0])
        guest = svc.create(s, a, "t", email="contractor@example.com", role="none")
        svc.set_override(s, a, "t", guest.id, "project", p, "member")
        secret, _row = web.start(s, guest, "test")
        s.commit()
    tmp = Path(str(tmp_path))
    settings = Settings(database_url="", redis_url="", s3_endpoint=None, s3_access_key="",
                        s3_secret_key="", s3_bucket="b", api_token="x" * 32, workdir=tmp,
                        upload_dir=tmp / "u", max_upload_bytes=1000)  # fmt: skip
    client = TestClient(create_app(AppState(settings, sessions, lambda *_: None, None)))  # type: ignore[arg-type]
    cookie = {"Cookie": f"{web.COOKIE}={secret}"}
    assert [x["id"] for x in client.get("/assets", headers=cookie).json()] == [p]
    rows = client.get("/v2/issues", params={"q": "status:open,fixed"}, headers=cookie).json()[
        "rows"
    ]
    assert {r["id"] for r in rows} == set(mine)
    assert client.get(f"/assets/{q}/overview", headers=cookie).status_code == 404
    assert client.get(f"/assets/{q}/issues/{theirs[0]}", headers=cookie).status_code == 404
    assert client.get(f"/assets/{p}/overview", headers=cookie).status_code == 200
    assert client.get("/v2/dashboards", headers=cookie).status_code == 403


def test_an_oidc_sign_in_on_postgres(
    sessions: sessionmaker[Session],  # noqa: F811
    two_orgs: tuple[str, str],  # noqa: F811
    tmp_path: object,
) -> None:
    """Sign-in reads tables with and without RLS before it knows the organization (the domain,
    the attempt) and with it (the provider, the person, their linked identity): the whole flow, as
    the API's database role, on Postgres."""
    from pathlib import Path

    import httpx
    from fastapi.testclient import TestClient

    from api.deps import AppState
    from api.main import create_app
    from core.config import Settings
    from core.identity import oidc
    from core.identity import sso as sso_svc
    from tests.unit.test_oidc import CLIENT, ISSUER, SECRET, FakeIdP

    a, b = two_orgs
    fake = FakeIdP()
    oidc._JWKS.clear()
    http = httpx.Client(transport=httpx.MockTransport(fake.handler))
    domain = f"{a}.test"
    fake.claims = {"email": f"priya@{domain}"}
    with sessions() as s:
        set_session_org(s, a)
        p = sso_svc.save(s, a, "t", {"kind": "oidc", "name": "SSO", "issuer": ISSUER,
                                     "client_id": CLIENT, "client_secret": SECRET,
                                     "email_domains": [domain], "auto_create": True},
                         Settings.from_env(), http=http)  # fmt: skip
        s.commit()
        pid = p.id
    tmp = Path(str(tmp_path))
    settings = Settings(database_url="", redis_url="", s3_endpoint=None, s3_access_key="",
                        s3_secret_key="", s3_bucket="b", api_token="x" * 32, workdir=tmp,
                        upload_dir=tmp / "u", max_upload_bytes=1000)  # fmt: skip
    client = TestClient(create_app(AppState(settings, sessions, lambda *_: None, None,  # type: ignore[arg-type]
                                            sso_http=http)))  # fmt: skip
    assert client.get("/auth/sso/discover", params={"email": f"x@{domain}"}).json()["providers"]
    start = client.get(f"/auth/sso/{pid}/start", follow_redirects=False)
    r = client.get(fake.authorize(start.headers["location"]), follow_redirects=False)
    assert r.headers["location"] == "http://localhost:3000/app", r.headers
    cookie = {"Cookie": r.headers["set-cookie"].split(";", 1)[0]}
    me = client.get("/v2/me", headers=cookie).json()
    assert me["user"]["email"] == f"priya@{domain}"
    with sessions() as s:  # the other organization sees neither the provider nor the person
        set_session_org(s, b)
        from core.persistence.models import IdentityProvider, User, UserIdentity

        assert s.scalars(select(IdentityProvider)).all() == []
        assert s.scalars(select(User)).all() == []
        assert s.scalars(select(UserIdentity)).all() == []
