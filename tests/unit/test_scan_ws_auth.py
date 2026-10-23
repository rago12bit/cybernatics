"""Who may follow a scan live over /scans/{id}/ws: the same people and tokens as GET /scans/{id}.

Before, the socket took the shared token only, so a person signed in with a session cookie, or
using a token of their own, was refused (4401) and the web app signed them out."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.websockets import WebSocketDisconnect

from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID as ORG
from tests.unit.test_accounts import Person
from tests.unit.test_api import TOKEN
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)

WEB = "http://localhost:3000"  # the default BULWARK_CORS_ORIGINS


def finished_scan(env: Env, org: str = ORG, label: str = "a/b") -> str:
    with env.sessions() as s:
        sid = repo.create_scan(s, source_type="git", source_ref=label, source_label=label,
                               asset_label=label, tools=["bandit"], org_id=org).id  # fmt: skip
        repo.finish_scan(s, sid, "completed")
    return sid


def follow(env: Env, sid: str, hello: dict[str, Any], **headers: str) -> dict[str, Any] | int:
    """The snapshot the socket sends, or the close code it ends with instead."""
    with env.client.websocket_connect(f"/scans/{sid}/ws", headers=headers) as ws:
        ws.send_json(hello)
        try:
            return dict(ws.receive_json())
        except WebSocketDisconnect as exc:
            return int(exc.code)


def cookie(p: Person) -> str:
    return p.read["Cookie"]


def test_a_signed_in_person_follows_their_organizations_scan(env: Env) -> None:  # noqa: F811
    sid = finished_scan(env)
    member = Person(env, "m@example.com", "member")
    snap = follow(env, sid, {}, cookie=cookie(member), origin=WEB)
    assert isinstance(snap, dict) and snap["type"] == "snapshot" and snap["id"] == sid


@pytest.mark.parametrize("origin", ["https://evil.example", None])
def test_a_session_cookie_counts_only_from_the_web_apps_origin(
    env: Env, origin: str | None  # noqa: F811
) -> None:
    sid = finished_scan(env)
    member = Person(env, "m@example.com", "member")
    headers = {"cookie": cookie(member)} | ({"origin": origin} if origin else {})
    assert follow(env, sid, {}, **headers) == 4401


def test_no_token_and_no_session_is_unauthorized(env: Env) -> None:  # noqa: F811
    sid = finished_scan(env)
    assert follow(env, sid, {}, origin=WEB) == 4401
    assert follow(env, sid, {}, cookie="bulwark_session=forged", origin=WEB) == 4401
    assert follow(env, sid, {"token": "wrong"}) == 4401


def test_a_persons_own_token_works_and_keeps_to_their_organization(
    env: Env,  # noqa: F811
) -> None:
    mine, theirs = finished_scan(env), finished_scan(env, OTHER_ORG, "x/y")
    member = Person(env, "m@example.com", "member")
    raw = member.post("/v2/me/tokens", json={"name": "t", "scopes": ["scans:read"]}).json()["token"]
    snap = follow(env, mine, {"token": raw})
    assert isinstance(snap, dict) and snap["id"] == mine
    # The "org" a client names is ignored for a token with an organization of its own.
    assert follow(env, theirs, {"token": raw, "org": OTHER_ORG}) == 4404


def test_a_token_without_scans_read_is_refused(env: Env) -> None:  # noqa: F811
    sid = finished_scan(env)
    member = Person(env, "m@example.com", "member")
    r = member.post("/v2/me/tokens", json={"name": "t", "scopes": ["ingest:read"]})
    assert follow(env, sid, {"token": r.json()["token"]}) == 4404


def test_someone_limited_to_other_projects_cannot_follow_this_one(env: Env) -> None:  # noqa: F811
    sid = finished_scan(env)
    admin = Person(env, "boss@example.com", "admin")
    guest = Person(env, "contractor@example.com", "none")
    assert follow(env, sid, {}, cookie=cookie(guest), origin=WEB) == 4404
    env.client.put(f"/v2/users/{guest.id}/roles", headers=admin.write,
                   json={"target_type": "project", "target_id": env.asset_id, "role": "viewer"})  # fmt: skip
    snap = follow(env, sid, {}, cookie=cookie(guest), origin=WEB)
    assert isinstance(snap, dict) and snap["id"] == sid


def test_the_shared_token_still_picks_the_organization(env: Env) -> None:  # noqa: F811
    theirs = finished_scan(env, OTHER_ORG, "x/y")
    assert follow(env, theirs, {"token": TOKEN}) == 4404  # the default organization's view
    snap = follow(env, theirs, {"token": TOKEN, "org": OTHER_ORG})
    assert isinstance(snap, dict) and snap["id"] == theirs
