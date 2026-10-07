"""SCIM 2.0 provisioning (Week 75, plan §51: "so someone leaving the company loses access within
minutes"): an identity provider creates, changes, turns off and deletes people with its own token,
in the shapes Okta and Entra ID send; turning someone off ends their sessions and tokens in the
same request; the provider's token can do nothing else, and nobody else can use SCIM."""

from __future__ import annotations

import time
from typing import Any

import pytest

from core.identity import scim
from tests.unit.test_accounts import Person
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)

ORG_B = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
OKTA_USER = {
    "schemas": [scim.USER], "userName": "Meera.S@acme.test", "externalId": "00u1",
    "name": {"givenName": "Meera", "familyName": "S"}, "emails": [
        {"value": "meera.s@acme.test", "primary": True, "type": "work"}], "active": True,
}  # fmt: skip


def provider(env: Env, headers: dict[str, str] = AUTH) -> dict[str, str]:  # noqa: F811
    r = env.client.post("/v2/scim/tokens", json={"name": "Okta"}, headers=headers)
    assert r.status_code == 201, r.text
    assert r.json()["base_url"] == "http://localhost:8000/scim/v2"
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_provision_change_and_find(env: Env) -> None:  # noqa: F811
    idp = provider(env)
    r = env.client.post("/scim/v2/Users", json=OKTA_USER, headers=idp)
    assert r.status_code == 201 and r.headers["content-type"].startswith("application/scim+json")
    u = r.json()
    assert (u["userName"], u["displayName"], u["externalId"], u["active"]) == (
        "meera.s@acme.test", "Meera S", "00u1", True)  # fmt: skip
    assert u["roles"] == [{"value": "viewer", "primary": True}]  # least access unless told
    assert r.headers["location"] == f"http://localhost:8000/scim/v2/Users/{u['id']}"
    dup = env.client.post("/scim/v2/Users", json=OKTA_USER, headers=idp)
    assert dup.status_code == 409 and dup.json()["scimType"] == "uniqueness"
    admin = env.client.post("/scim/v2/Users", headers=idp, json={
        "userName": "boss@acme.test", "displayName": "The Boss", "roles": [{"value": "admin"}]})  # fmt: skip
    assert admin.json()["roles"][0]["value"] == "admin"
    found = env.client.get("/scim/v2/Users", params={"filter": 'userName eq "MEERA.S@acme.test"'},
                           headers=idp).json()  # fmt: skip
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == u["id"]
    by_ext = env.client.get(
        "/scim/v2/Users", params={"filter": 'externalId eq "00u1"'}, headers=idp
    )
    assert by_ext.json()["totalResults"] == 1
    page = env.client.get(
        "/scim/v2/Users", params={"startIndex": 2, "count": 1}, headers=idp
    ).json()
    assert (page["totalResults"], page["startIndex"], page["itemsPerPage"]) == (2, 2, 1)
    bad = env.client.get("/scim/v2/Users", params={"filter": 'name.familyName co "S"'}, headers=idp)
    assert bad.status_code == 400 and bad.json()["scimType"] == "invalidFilter"
    put = env.client.put(f"/scim/v2/Users/{u['id']}", headers=idp,
                         json={**OKTA_USER, "displayName": "Meera Shah", "roles": [{"value": "member"}]})  # fmt: skip
    assert put.json()["displayName"] == "Meera Shah" and put.json()["roles"][0]["value"] == "member"
    for body in ({"schemas": [scim.PATCH], "Operations": [{"op": "remove", "path": "active"}]},
                 {"Operations": [{"op": "replace", "path": "active", "value": False}]},
                 {"schemas": [scim.PATCH], "Operations": [{"op": "replace", "value": "x"}]}):  # fmt: skip
        r = env.client.patch(f"/scim/v2/Users/{u['id']}", json=body, headers=idp)
        assert r.status_code == 400, body
    assert env.client.get("/scim/v2/Users/nope", headers=idp).status_code == 404
    cfg = env.client.get("/scim/v2/ServiceProviderConfig", headers=idp).json()
    assert cfg["patch"]["supported"] and not cfg["bulk"]["supported"]


@pytest.mark.parametrize("style", ["okta", "entra"])
def test_deprovisioning_ends_access_in_the_same_request(env: Env, style: str) -> None:  # noqa: F811
    idp = provider(env)
    Person(env, "boss@acme.test", "admin")  # so the leaver is not the last admin
    leaver = Person(env, "leaver@acme.test", "member")
    token = leaver.post("/v2/me/tokens", json={"name": "CI", "scopes": ["scans:read"]}).json()[
        "token"
    ]
    bearer = {"Authorization": f"Bearer {token}"}
    assert (
        leaver.get("/v2/me").status_code == 200
        and env.client.get("/v2/me", headers=bearer).status_code == 200
    )
    found = env.client.get("/scim/v2/Users", params={"filter": 'userName eq "leaver@acme.test"'},
                           headers=idp).json()["Resources"][0]  # fmt: skip
    op = ({"op": "replace", "value": {"active": False}} if style == "okta"
          else {"op": "Replace", "path": "active", "value": "False"})  # fmt: skip
    started = time.monotonic()
    r = env.client.patch(f"/scim/v2/Users/{found['id']}", headers=idp,
                         json={"schemas": [scim.PATCH], "Operations": [op]})  # fmt: skip
    assert r.status_code == 200 and r.json()["active"] is False
    assert leaver.get("/v2/me").status_code == 401  # the next request, not "within minutes"
    assert env.client.get("/v2/me", headers=bearer).status_code == 401
    assert time.monotonic() - started < 5
    # Turned back on, they can sign in again (the old session and token stay ended).
    r = env.client.patch(f"/scim/v2/Users/{found['id']}", headers=idp, json={
        "schemas": [scim.PATCH], "Operations": [{"op": "replace", "path": "active", "value": True}]})  # fmt: skip
    assert r.json()["active"] is True and leaver.get("/v2/me").status_code == 401


def test_delete_turns_off_unlinks_and_can_come_back(env: Env) -> None:  # noqa: F811
    idp = provider(env)
    Person(env, "boss@acme.test", "admin")
    u = env.client.post("/scim/v2/Users", json=OKTA_USER, headers=idp).json()
    assert env.client.delete(f"/scim/v2/Users/{u['id']}", headers=idp).status_code == 204
    assert env.client.get(f"/scim/v2/Users/{u['id']}", headers=idp).status_code == 404
    assert env.client.get("/scim/v2/Users", headers=idp).json()["totalResults"] == 1  # the boss
    users = {x["email"]: x for x in env.client.get("/v2/users", headers=AUTH).json()}
    assert users["meera.s@acme.test"]["active"] is False  # kept, for the audit trail
    back = env.client.post("/scim/v2/Users", json={**OKTA_USER, "externalId": "00u9"}, headers=idp)
    assert back.status_code == 201 and back.json()["id"] == u["id"] and back.json()["active"]


def test_the_last_admin_cannot_be_deprovisioned(env: Env) -> None:  # noqa: F811
    idp = provider(env)
    boss = env.client.post("/scim/v2/Users", headers=idp,
                           json={"userName": "only@acme.test", "roles": [{"value": "admin"}]}).json()  # fmt: skip
    r = env.client.patch(f"/scim/v2/Users/{boss['id']}", headers=idp, json={
        "schemas": [scim.PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]})  # fmt: skip
    assert r.status_code == 409 and "at least one active admin" in r.json()["detail"]


def test_the_provider_token_does_only_scim_and_only_it_does(env: Env) -> None:  # noqa: F811
    idp = provider(env)
    for url in ("/assets", "/v2/issues", "/v2/users", "/v2/me"):
        assert env.client.get(url, headers=idp).status_code in (401, 403), url
    admin = Person(env, "boss@acme.test", "admin")
    assert admin.get("/scim/v2/Users").status_code == 403  # people do not use SCIM
    assert env.client.get("/scim/v2/Users", headers=AUTH).status_code == 200  # the operator may
    # The provider is not a person anyone can mention or assign.
    from core.collab.people import people
    from core.tenancy import DEFAULT_ORG_ID as ORG
    from core.tenancy import set_session_org

    with env.sessions() as s:
        set_session_org(s, ORG)
        assert "okta" not in {p.handle for p in people(s, ORG)}
    # Its tokens are listed for admins, and revoked by them.
    listed = env.client.get("/v2/scim/tokens", headers=AUTH).json()["tokens"]
    assert [t["name"] for t in listed] == ["Okta"] and "token" not in listed[0]
    assert admin.get("/v2/scim/tokens").status_code == 200
    assert (
        env.client.delete(f"/v2/scim/tokens/{listed[0]['id']}", headers=admin.write).status_code
        == 204
    )
    assert env.client.get("/scim/v2/Users", headers=idp).status_code == 401


def test_each_organizations_provider_sees_only_its_people(env: Env) -> None:  # noqa: F811
    a, b = provider(env), provider(env, ORG_B)
    env.client.post("/scim/v2/Users", json=OKTA_USER, headers=a)
    assert env.client.get("/scim/v2/Users", headers=b).json()["totalResults"] == 0
    uid = env.client.get("/scim/v2/Users", headers=a).json()["Resources"][0]["id"]
    assert env.client.get(f"/scim/v2/Users/{uid}", headers=b).status_code == 404
    r = env.client.patch(f"/scim/v2/Users/{uid}", headers=b, json={
        "schemas": [scim.PATCH], "Operations": [{"op": "replace", "path": "active", "value": False}]})  # fmt: skip
    assert r.status_code == 404


def _unused(_: Any) -> None:
    pass
