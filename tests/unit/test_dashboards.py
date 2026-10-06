"""Dashboards (plan §48.2, §55.4): saved per person, shared with a role, read-only to others (who
can copy them), stale saves refused, widgets validated, every change audit-logged; the role each
person picks; nothing of another organization."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from core.dashboards import MAX_WIDGETS, PROGRAM
from core.persistence.models import AuditEntry
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token

PROJECT = "10e48a42-e7a8-4c5e-aa13-eef198cba5fa"


def widget(i: str = "a", metric: str = "open_issues", **over: Any) -> dict[str, Any]:
    return {"id": i, "metric": metric, "x": 0, "y": 0, "w": 6, "h": 4, **over}


def make(env: Env, who: dict[str, str], **body: Any) -> dict[str, Any]:
    r = env.client.post("/v2/dashboards", json={"name": "Mine", "widgets": [widget()], **body},
                        headers=who)  # fmt: skip
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def test_owner_edits_role_views_others_copy(env: Env) -> None:
    alice, bob, carol = token(env, "Alice"), token(env, "Bob"), token(env, "Carol")
    for who, role in ((bob, "lead"), (carol, "engineer")):
        assert (
            env.client.put("/v2/me/role", json={"role": role}, headers=who).json()["role"] == role
        )
    d = make(env, alice, name="Program", shared_with=["lead"],
             widgets=[widget("sla", "sla_adherence", filters={"days": 30}),
                      widget("risk", "open_risk", x=6, filters={"group": "portfolio",
                                                                "projects": [PROJECT]})])  # fmt: skip
    assert d["version"] == 1 and d["can_edit"] and d["shared_with"] == ["lead"]
    assert d["widgets"][1]["filters"] == {"group": "portfolio", "projects": [PROJECT]}

    # Bob (a lead) sees it, read-only; Carol (an engineer) does not.
    seen = env.client.get("/v2/dashboards", headers=bob).json()
    assert seen["role"] == "lead"
    mine = [x for x in seen["dashboards"] if x["id"] == d["id"]]
    assert mine and mine[0]["can_edit"] is False
    assert seen["dashboards"][-1]["id"] == PROGRAM["id"]  # the built-in one, always last
    assert env.client.get(f"/v2/dashboards/{d['id']}", headers=carol).status_code == 404
    r = env.client.put(f"/v2/dashboards/{d['id']}", json={"version": 1, "name": "x"}, headers=bob)
    assert r.status_code == 403
    assert env.client.delete(f"/v2/dashboards/{d['id']}", headers=bob).status_code == 403

    # Copying makes it Bob's, unshared.
    c = env.client.post(f"/v2/dashboards/{d['id']}/copy", headers=bob).json()
    assert c["owner"] != d["owner"] and c["shared_with"] == [] and c["name"] == "Program (copy)"
    assert c["widgets"] == d["widgets"] and c["can_edit"]
    b = env.client.post(f"/v2/dashboards/{PROGRAM['id']}/copy", headers=carol).json()
    assert b["name"] == "Program overview (copy)" and len(b["widgets"]) == len(PROGRAM["widgets"])

    # The shared token is the operator: it sees and may edit everything.
    everything = env.client.get("/v2/dashboards", headers=AUTH).json()["dashboards"]
    assert {d["id"], c["id"], b["id"]} <= {x["id"] for x in everything}
    assert all(x["can_edit"] for x in everything if not x["builtin"])


def test_a_stale_save_is_refused_and_every_change_is_logged(env: Env) -> None:
    alice = token(env, "Alice")
    d = make(env, alice)
    url = f"/v2/dashboards/{d['id']}"
    moved = [widget(x=6, y=2, w=4, h=3)]
    ok = env.client.put(url, json={"version": 1, "widgets": moved}, headers=alice)
    assert ok.status_code == 200 and ok.json()["version"] == 2
    assert ok.json()["widgets"][0] == {**moved[0], "filters": {}}
    stale = env.client.put(url, json={"version": 1, "name": "Other"}, headers=alice)
    assert stale.status_code == 409 and "version 2" in stale.json()["detail"]["message"]
    assert env.client.get(url, headers=alice).json()["name"] == "Mine"
    assert env.client.delete(url, headers=alice).status_code == 204
    assert env.client.get(url, headers=alice).status_code == 404
    with env.sessions() as s:
        actions = [e.action for e in s.scalars(
            select(AuditEntry).where(AuditEntry.target == f"dashboard:{d['id']}")
            .order_by(AuditEntry.seq))]  # fmt: skip
    assert actions == ["dashboard.created", "dashboard.saved", "dashboard.deleted"]


def test_widgets_and_fields_are_validated(env: Env) -> None:
    alice = token(env, "Alice")
    bad: list[tuple[dict[str, Any], str]] = [
        ({"name": ""}, "name"),
        ({"name": "x" * 81}, "name"),
        ({"shared_with": ["admin"]}, "shared_with"),
        ({"widgets": [widget(metric="made_up")]}, "widgets[0].metric"),
        ({"widgets": [widget(x=8, w=6)]}, "widgets[0].x"),  # off the 12-column grid
        ({"widgets": [widget(w=1)]}, "widgets[0].w"),
        ({"widgets": [widget(h=13)]}, "widgets[0].h"),
        ({"widgets": [widget(), widget()]}, "widgets[1].id"),  # ids must differ
        ({"widgets": [widget(filters={"projects": ["../etc"]})]}, "widgets[0].filters.projects"),
        ({"widgets": [widget(filters={"tag": "<b>"})]}, "widgets[0].filters.tag"),
        ({"widgets": [widget(filters={"days": 0})]}, "widgets[0].filters.days"),
        ({"widgets": [widget(filters={"group": "owner"})]}, "widgets[0].filters.group"),
        ({"widgets": [widget(filters={"sql": "1"})]}, "widgets[0].filters"),
        ({"widgets": [widget(str(i)) for i in range(MAX_WIDGETS + 1)]}, "widgets"),
    ]
    for body, field in bad:
        r = env.client.post("/v2/dashboards", json={"name": "N", "widgets": [], **body},
                            headers=alice)  # fmt: skip
        assert r.status_code == 422, (body, r.text)
        assert r.json()["detail"]["field"] == field, (body, r.json())
    assert env.client.put("/v2/me/role", json={"role": "admin"}, headers=alice).status_code == 422
    me = env.client.get("/v2/me", headers=alice).json()
    assert me["person"] is True and me["role"] is None and me["roles"] == ["lead", "engineer",
                                                                           "tester"]  # fmt: skip


def test_nothing_of_another_organization(env: Env) -> None:
    alice = token(env, "Alice")
    d = make(env, alice, shared_with=["lead", "engineer", "tester"])
    zed = token(env, "Zed", org=OTHER_ORG)
    env.client.put("/v2/me/role", json={"role": "lead"}, headers=zed)
    listed = env.client.get("/v2/dashboards", headers=zed).json()["dashboards"]
    assert [x["id"] for x in listed] == [PROGRAM["id"]]
    for method, path in (("get", ""), ("put", ""), ("delete", ""), ("post", "/copy")):
        r = env.client.request(method, f"/v2/dashboards/{d['id']}{path}",
                               json={"version": 1, "name": "x"} if method == "put" else None,
                               headers=zed)  # fmt: skip
        assert r.status_code == 404, (method, path, r.status_code)
    other_operator = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
    assert len(env.client.get("/v2/dashboards", headers=other_operator).json()["dashboards"]) == 1
