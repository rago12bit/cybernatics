"""Accounts, sessions and scoped roles (Week 75, plan §51): a session cookie signs a person in and
needs its CSRF token to change anything; roles decide what a person may do, project by project,
with business-unit and project overrides that only raise access; someone limited to some projects
sees nothing else; turning a person off ends their sessions and tokens at once; people with
accounts are people everywhere (mentions, assignment, approvers)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from core.identity import sessions as web
from core.identity import users as svc
from core.persistence.models import ApiToken, AuditEntry, IssueRow, User, UserSession
from core.tenancy import DEFAULT_ORG_ID as ORG
from core.tenancy import set_session_org
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_issue_search import org  # noqa: F401  (the fixture)


class Person:
    def __init__(self, env: Env, email: str, role: str, org_id: str = ORG) -> None:
        with env.sessions() as s:
            set_session_org(s, org_id)
            u = svc.create(s, org_id, "test", email=email, name=email.split("@")[0].title(),
                           role=role)  # fmt: skip
            self.id, self.actor = u.id, svc.actor_of(u.id)
            self.secret, row = web.start(s, u, "test")
            self.csrf = row.csrf
            s.commit()
        self.env = env

    @property
    def read(self) -> dict[str, str]:
        return {"Cookie": f"{web.COOKIE}={self.secret}"}

    @property
    def write(self) -> dict[str, str]:
        return {**self.read, web.CSRF_HEADER: self.csrf}

    def get(self, url: str, **kw: Any) -> Any:
        return self.env.client.get(url, headers=self.read, **kw)

    def post(self, url: str, **kw: Any) -> Any:
        return self.env.client.post(url, headers=self.write, **kw)


def triage(p: Person, project: str, issue: str) -> int:
    r = p.post(f"/assets/{project}/issues/{issue}/triage",
               json={"action": "not_a_risk", "reason": "test"})  # fmt: skip
    return int(r.status_code)


def project_of(env: Env, issue: str) -> str:
    with env.sessions() as s:
        row = s.get(IssueRow, issue)
        assert row is not None
        return row.asset_id


def test_a_session_signs_in_and_changes_need_its_csrf_token(env: Env) -> None:
    p = Person(env, "priya@example.com", "member")
    me = p.get("/v2/me").json()
    assert me["actor"] == p.actor and me["person"] and me["user"]["email"] == "priya@example.com"
    assert me["org_role"] == "member" and "scans:write" in me["scopes"]
    sess = p.get("/auth/session").json()
    assert sess["csrf"] == p.csrf and sess["user"]["role"] == "member"
    # A change with the cookie alone (what another site could make the browser send) is refused.
    r = env.client.post("/v2/issue-views", json={"name": "x"}, headers=p.read)
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]
    bad = {**p.read, web.CSRF_HEADER: "nope"}
    assert env.client.post("/v2/issue-views", json={"name": "x"}, headers=bad).status_code == 403
    assert p.post("/v2/issue-views", json={"name": "x"}).status_code == 201
    # Signing out ends it.
    assert env.client.post("/auth/logout", headers=p.read).status_code == 204
    assert p.get("/v2/me").status_code == 401
    assert p.get("/auth/session").status_code == 401
    assert env.client.get("/v2/me").status_code == 401  # and nothing at all is not signed in


def test_sessions_are_short(env: Env) -> None:
    p, q = Person(env, "a@example.com", "viewer"), Person(env, "b@example.com", "viewer")
    with env.sessions() as s:
        a = s.get(UserSession, web.digest(p.secret))
        b = s.get(UserSession, web.digest(q.secret))
        assert a is not None and b is not None
        assert a.expires_at - a.created_at == web.ABSOLUTE == timedelta(hours=12)
        a.last_seen_at = a.last_seen_at - web.IDLE  # idle too long
        b.expires_at = b.created_at  # past its absolute end
        s.commit()
    assert p.get("/v2/me").status_code == 401 and q.get("/v2/me").status_code == 401
    # Only the secret's hash is stored.
    with env.sessions() as s:
        assert s.get(UserSession, p.secret) is None


def test_roles_decide_what_a_person_may_do(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    issue = org["api"][0]
    project = project_of(env, issue)
    viewer, member = Person(env, "v@example.com", "viewer"), Person(env, "m@example.com", "member")
    admin = Person(env, "boss@example.com", "admin")
    assert viewer.get(f"/assets/{project}/overview").status_code == 200
    assert triage(viewer, project, issue) == 403
    assert triage(member, project, issue) == 200
    assert member.get("/v2/users").status_code == 403
    users = admin.get("/v2/users").json()
    assert {u["email"] for u in users} >= {"v@example.com", "m@example.com", "boss@example.com"}
    r = admin.post("/v2/users", json={"email": "New@Example.com", "role": "viewer"})
    assert r.status_code == 201 and r.json()["email"] == "new@example.com"
    assert admin.post("/v2/users", json={"email": "new@example.com"}).status_code == 409
    assert admin.post("/v2/users", json={"email": "nope", "role": "viewer"}).status_code == 422
    assert (
        admin.post("/v2/users", json={"email": "x@example.com", "role": "god"}).status_code == 422
    )
    # The last admin cannot stop being one.
    r = env.client.patch(f"/v2/users/{admin.id}", json={"role": "member"}, headers=admin.write)
    assert r.status_code == 409 and "at least one active admin" in r.json()["detail"]["message"]


def test_overrides_raise_access_on_one_project_or_unit(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    api, ledger = org["api"][0], org["ledger"][1]
    pa, pl = project_of(env, api), project_of(env, ledger)
    admin = Person(env, "boss@example.com", "admin")
    v = Person(env, "v@example.com", "viewer")
    r = env.client.put(f"/v2/users/{v.id}/roles", headers=admin.write,
                       json={"target_type": "project", "target_id": pa, "role": "member"})  # fmt: skip
    assert r.status_code == 200 and r.json()["roles"][0]["role"] == "member"
    assert triage(v, pa, api) == 200  # member on this project
    assert triage(v, pl, ledger) == 403  # still a viewer elsewhere
    # Organization-wide changes use the organization role.
    r = v.post("/v2/issues/bulk/preview", json={"q": "", "action": "reopen"})
    assert r.status_code == 403 and "this organization" in r.json()["detail"]
    # A business unit's role reaches its projects.
    r = env.client.put(f"/v2/users/{v.id}/roles", headers=admin.write,
                       json={"target_type": "portfolio", "target_id": org["units"]["plat"],
                             "role": "member"})  # fmt: skip
    assert r.status_code == 200
    assert triage(v, pl, ledger) == 200
    for bad, field in (({"target_type": "project", "target_id": "nope", "role": "member"}, "target_id"),
                       ({"target_type": "team", "target_id": pa, "role": "member"}, "target_type"),
                       ({"target_type": "project", "target_id": pa, "role": "none"}, "role")):  # fmt: skip
        r = env.client.put(f"/v2/users/{v.id}/roles", json=bad, headers=admin.write)
        assert r.json()["detail"]["field"] == field, bad
    with env.sessions() as s:
        actions = [a.action for a in s.scalars(select(AuditEntry).where(
            AuditEntry.target == v.actor).order_by(AuditEntry.seq))]  # fmt: skip
    assert actions.count("user.role_override.set") == 2


def test_someone_limited_to_some_projects_sees_nothing_else(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    """The two-project access test (plan §51; §19.1's two-tenant test, one level down)."""
    api, ledger = org["api"][0], org["ledger"][1]
    pa, pl = project_of(env, api), project_of(env, ledger)
    admin = Person(env, "boss@example.com", "admin")
    guest = Person(env, "contractor@example.com", "none")
    assert guest.get("/assets").status_code == 403  # nothing granted yet
    assert guest.get("/v2/dashboards").status_code == 403
    env.client.put(f"/v2/users/{guest.id}/roles", headers=admin.write,
                   json={"target_type": "project", "target_id": pa, "role": "viewer"})  # fmt: skip
    assert [a["id"] for a in guest.get("/assets").json()] == [pa]
    assert guest.get(f"/assets/{pa}/overview").status_code == 200
    assert guest.get(f"/assets/{pl}/overview").status_code == 404
    assert guest.get(f"/assets/{pl}/issues/{ledger}").status_code == 404
    rows = guest.get("/v2/issues", params={"q": "status:open,accepted,not_a_risk,fixed"}).json()
    assert {r["project_id"] for r in rows["rows"]} == {pa}
    assert guest.get("/v2/issues", params={"q": "project:acme/ledger"}).json()["rows"] == []
    assert triage(guest, pa, api) == 403  # a viewer there
    assert triage(guest, pl, ledger) == 404  # and not even there elsewhere
    # Organization-wide pages stay for organization roles, even once something is granted.
    for url in ("/v2/dashboards", "/v2/reports", "/v2/rules", "/v2/users", "/v2/metrics"):
        assert guest.get(url).status_code == 403, url


def test_turning_someone_off_ends_their_sessions_and_tokens_now(env: Env) -> None:
    admin = Person(env, "boss@example.com", "admin")
    leaver = Person(env, "leaver@example.com", "member")
    r = leaver.post("/v2/me/tokens", json={"name": "CI", "scopes": ["scans:read", "scans:write"]})
    assert r.status_code == 201
    token = {"Authorization": f"Bearer {r.json()['token']}"}
    me = env.client.get("/v2/me", headers=token).json()
    assert me["actor"] == leaver.actor  # a person's token acts as them
    # A token cannot make tokens.
    assert env.client.post("/v2/me/tokens", headers=token,
                           json={"name": "x", "scopes": ["scans:read"]}).status_code == 403  # fmt: skip
    r = env.client.patch(f"/v2/users/{leaver.id}", json={"active": False}, headers=admin.write)
    assert r.status_code == 200 and r.json()["active"] is False
    assert leaver.get("/v2/me").status_code == 401
    assert env.client.get("/v2/me", headers=token).status_code == 401
    with env.sessions() as s:
        assert s.scalar(select(ApiToken).where(ApiToken.user_id == leaver.id)).revoked_at  # type: ignore[union-attr]
        entry = s.scalar(select(AuditEntry).where(AuditEntry.action == "user.disabled"))
        assert entry is not None and entry.target == leaver.actor


def test_a_persons_token_never_does_more_than_their_role(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    issue = org["api"][0]
    project = project_of(env, issue)
    admin = Person(env, "boss@example.com", "admin")
    m = Person(env, "m@example.com", "member")
    raw = m.post(
        "/v2/me/tokens", json={"name": "CI", "scopes": ["scans:read", "scans:write"]}
    ).json()[
        "token"
    ]  # noqa: E501
    token = {"Authorization": f"Bearer {raw}"}
    r = env.client.post(f"/assets/{project}/issues/{issue}/triage", headers=token,
                        json={"action": "not_a_risk", "reason": "x"})  # fmt: skip
    assert r.status_code == 200
    env.client.patch(f"/v2/users/{m.id}", json={"role": "viewer"}, headers=admin.write)
    r = env.client.post(f"/assets/{project}/issues/{issue}/triage", headers=token,
                        json={"action": "reopen"})  # fmt: skip
    assert r.status_code == 403  # the role went down; the token went with it
    ro = m.post("/v2/me/tokens", json={"name": "ro", "scopes": ["scans:read"]}).json()["token"]
    r = env.client.post("/v2/issues/bulk/preview", headers={"Authorization": f"Bearer {ro}"},
                        json={"q": "", "action": "reopen"})  # fmt: skip
    assert r.status_code == 403
    listed = m.get("/v2/me/tokens").json()
    assert {t["name"] for t in listed} == {"CI", "ro"} and "token" not in listed[0]
    assert env.client.delete(f"/v2/me/tokens/{listed[0]['id']}", headers=m.write).status_code == 204
    assert (
        env.client.delete(f"/v2/me/tokens/{listed[0]['id']}", headers=admin.write).status_code
        == 404
    )


def test_people_with_accounts_are_people_everywhere(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811
    from core.acceptance.service import approvers
    from core.collab.people import names, people

    m = Person(env, "meera.s@example.com", "member")
    Person(env, "vic@example.com", "viewer")
    with env.sessions() as s:
        set_session_org(s, ORG)
        handles = {p.handle: p.actor for p in people(s, ORG)}
        assert handles["meera.s"] == m.actor
        assert names(s, ORG, {m.actor}) == {m.actor: "Meera.S"}
        could = {a["actor"] for a in approvers(s, ORG, excluding="x")}
        assert m.actor in could and not any("vic" in a for a in could)
    issue = org["api"][0]
    r = env.client.put(f"/v2/issues/{issue}/assignee", json={"to": "@meera.s"}, headers=AUTH)
    assert r.status_code == 200, r.text
    page = m.get("/v2/issues", params={"q": "assignee:me"}).json()
    assert [x["id"] for x in page["rows"]] == [issue]
    assert page["rows"][0]["assignee_name"] == "Meera.S"


def test_the_shared_token_and_old_tokens_work_as_before(env: Env) -> None:
    from tests.unit.test_risk_acceptance import token

    assert env.client.get("/v2/me", headers=AUTH).json()["user"] is None
    old = token(env, "Old laptop")
    me = env.client.get("/v2/me", headers=old).json()
    assert me["actor"].startswith("token:") and me["user"] is None
    assert env.client.get("/v2/me/tokens", headers=old).status_code == 409
    # Accounts are per organization.
    Person(env, "x@example.com", "admin", org_id=OTHER_ORG)
    other_org = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
    assert [u["email"] for u in env.client.get("/v2/users", headers=other_org).json()] == [
        "x@example.com"
    ]
    assert "x@example.com" not in {
        u["email"] for u in env.client.get("/v2/users", headers=AUTH).json()
    }


def test_users_service_checks(env: Env) -> None:
    with env.sessions() as s:
        set_session_org(s, ORG)
        u = svc.create(s, ORG, "t", email=" Mixed@Example.COM ", role="admin")
        assert (u.email, u.name) == ("mixed@example.com", "mixed")
        with pytest.raises(svc.UserError):
            svc.disable(s, ORG, "t", u.id, reason="x")  # the only admin
        other = svc.create(s, ORG, "t", email="two@example.com", role="admin")
        svc.disable(s, ORG, "t", u.id, reason="x")
        assert s.get(User, u.id).active is False  # type: ignore[union-attr]
        assert svc.update_user(s, ORG, "t", u.id, {"active": True}).active
        with pytest.raises(svc.UserError):
            svc.get(s, OTHER_ORG, other.id)
