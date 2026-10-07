"""Saved views of the Issues list and per-person table settings (Week 73, plan §56): personal or
shared with a role, read-only to others (who can copy them), queries checked and stored canonically,
stale saves refused, every change audit-logged; browser-saved views imported once; columns and
density remembered per person; a report's issues block shows a saved view; nothing of another
organization."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from core.persistence.models import AuditEntry
from core.search.views import BUILTINS, DEFAULT_COLUMNS, MAX_OWN
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_issue_search import org  # noqa: F401  (the fixture)
from tests.unit.test_reports import fake_chromium  # noqa: F401  (the fixture)
from tests.unit.test_risk_acceptance import token

ORG_B = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


def make(env: Env, who: dict[str, str], **body: Any) -> dict[str, Any]:
    r = env.client.post("/v2/issue-views", json={"name": "Mine", "query": "sla:breached", **body},
                        headers=who)  # fmt: skip
    assert r.status_code == 201, r.text
    return r.json()  # type: ignore[no-any-return]


def test_owner_edits_role_sees_others_copy(env: Env) -> None:
    alice, bob, carol = token(env, "Alice"), token(env, "Bob"), token(env, "Carol")
    for who, role in ((bob, "lead"), (carol, "engineer")):
        assert env.client.put("/v2/me/role", json={"role": role}, headers=who).status_code == 200
    v = make(env, alice, name="Payments P1", query="project:payments-*   PRIORITY:p1 -status:accepted",
             sort="newest", columns=["project", "sla", "project"], shared_with=["lead"])  # fmt: skip
    # Stored written back canonically, columns once each, in the order given.
    assert v["query"] == "-status:accepted priority:P1 project:payments-*"
    assert v["sort"] == "newest" and v["columns"] == ["project", "sla"]
    assert v["version"] == 1 and v["can_edit"] and v["shared_with"] == ["lead"]

    seen = env.client.get("/v2/issue-views", headers=bob).json()
    mine = [x for x in seen if x["id"] == v["id"]]
    assert mine and mine[0]["can_edit"] is False
    assert [x["id"] for x in seen[-len(BUILTINS) :]] == [b.id for b in BUILTINS]  # built-ins last
    assert env.client.get(f"/v2/issue-views/{v['id']}", headers=carol).status_code == 404
    assert v["id"] not in {x["id"] for x in env.client.get("/v2/issue-views", headers=carol).json()}
    r = env.client.put(f"/v2/issue-views/{v['id']}", json={"version": 1, "name": "x"}, headers=bob)
    assert r.status_code == 403
    assert env.client.delete(f"/v2/issue-views/{v['id']}", headers=bob).status_code == 403

    c = env.client.post(f"/v2/issue-views/{v['id']}/copy", headers=bob).json()
    assert c["name"] == "Payments P1 (copy)" and c["shared_with"] == [] and c["can_edit"]
    assert (c["query"], c["sort"], c["columns"]) == (v["query"], v["sort"], v["columns"])
    b = env.client.post("/v2/issue-views/builtin:mine/copy", headers=carol).json()
    assert b["query"] == "assignee:me" and b["name"] == "Assigned to me (copy)"
    builtin = env.client.get("/v2/issue-views/builtin:past-sla", headers=carol).json()
    assert builtin["builtin"] and builtin["query"] == "sla:breached" and not builtin["can_edit"]
    for method in ("put", "delete"):
        r = env.client.request(method.upper(), "/v2/issue-views/builtin:mine",
                               json={"version": 0, "name": "x"}, headers=AUTH)  # fmt: skip
        assert r.status_code == 403

    # The shared token is the operator: it sees and may edit every saved view.
    everything = env.client.get("/v2/issue-views", headers=AUTH).json()
    assert {v["id"], c["id"], b["id"]} <= {x["id"] for x in everything}
    assert all(x["can_edit"] for x in everything if not x["builtin"])


def test_queries_are_checked_with_the_span_at_fault(env: Env) -> None:
    r = env.client.post("/v2/issue-views", json={"name": "Bad", "query": "severity:huge"},
                        headers=AUTH)  # fmt: skip
    assert r.status_code == 422
    body = r.json()["detail"]
    assert body["field"] == "query" and (body["start"], body["end"]) == (9, 13)
    assert "huge" in body["message"]
    for bad, field in (({"name": ""}, "name"), ({"sort": "random"}, "sort"),
                       ({"columns": ["title"]}, "columns"), ({"shared_with": ["admin"]}, "shared_with"),
                       ({"query": 5}, "query")):  # fmt: skip
        r = env.client.post("/v2/issue-views", json={"name": "x", **bad}, headers=AUTH)
        assert r.status_code == 422 and r.json()["detail"]["field"] == field, (bad, r.text)


def test_a_stale_save_is_refused_and_every_change_is_logged(env: Env) -> None:
    alice = token(env, "Alice")
    v = make(env, alice)
    url = f"/v2/issue-views/{v['id']}"
    ok = env.client.put(url, json={"version": 1, "query": "sla:due_soon"}, headers=alice)
    assert ok.status_code == 200 and ok.json()["version"] == 2
    assert ok.json()["query"] == "sla:due_soon" and ok.json()["name"] == "Mine"
    stale = env.client.put(url, json={"version": 1, "name": "Other"}, headers=alice)
    assert stale.status_code == 409 and "version 2" in stale.json()["detail"]["message"]
    assert env.client.delete(url, headers=alice).status_code == 204
    assert env.client.get(url, headers=alice).status_code == 404
    with env.sessions() as s:
        actions = [a.action for a in s.scalars(
            select(AuditEntry).where(AuditEntry.target == f"saved_view:{v['id']}")
            .order_by(AuditEntry.seq))]  # fmt: skip
    assert actions == ["saved_view.created", "saved_view.saved", "saved_view.deleted"]


def test_at_most_so_many_views_each(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    import core.search.views as views

    monkeypatch.setattr(views, "MAX_OWN", 2)
    alice = token(env, "Alice")
    make(env, alice)
    make(env, alice)
    r = env.client.post("/v2/issue-views", json={"name": "3"}, headers=alice)
    assert r.status_code == 409 and "At most 2" in r.json()["detail"]["message"]
    assert MAX_OWN == 100


def test_nothing_of_another_organization(env: Env) -> None:
    v = make(env, AUTH)
    assert env.client.get(f"/v2/issue-views/{v['id']}", headers=ORG_B).status_code == 404
    assert v["id"] not in {x["id"] for x in env.client.get("/v2/issue-views", headers=ORG_B).json()}
    r = env.client.put(
        f"/v2/issue-views/{v['id']}", json={"version": 1, "name": "x"}, headers=ORG_B
    )
    assert r.status_code == 404
    assert env.client.post(f"/v2/issue-views/{v['id']}/copy", headers=ORG_B).status_code == 404
    assert env.client.delete(f"/v2/issue-views/{v['id']}", headers=ORG_B).status_code == 404


def test_browser_saved_views_are_imported_once(env: Env) -> None:
    alice = token(env, "Alice")
    make(env, alice, name="Breached")
    views = [
        {"name": "Breached", "query": "project:acme/api sla:breached severity:critical"},
        {"name": "Mine again", "query": "sla:breached"},  # the same as one Alice has: skipped
        {"name": "Risky", "query": 'project:"acme/api" sort', "sort": "severity"},
    ]
    r = env.client.post("/v2/issue-views/import", json={"views": views}, headers=alice)
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["skipped"] == 1
    assert [(v["name"], v["query"], v["sort"], v["shared_with"]) for v in got["imported"]] == [
        ("Breached (imported)", "severity:critical sla:breached project:acme/api", "priority", []),
        ("Risky", "project:acme/api sort", "severity", []),
    ]
    # Importing again adds nothing: each is now the same as one Alice has.
    again = env.client.post("/v2/issue-views/import", json={"views": views}, headers=alice).json()
    assert again == {"imported": [], "skipped": 3}
    # One that cannot be read refuses the lot, naming it.
    r = env.client.post("/v2/issue-views/import", headers=alice,
                        json={"views": [{"name": "ok", "query": "sla:due_soon"},
                                        {"name": "bad", "query": "sla:late"}]})  # fmt: skip
    assert r.status_code == 422 and r.json()["detail"]["field"] == "views[1].query"
    names = [v["name"] for v in env.client.get("/v2/issue-views", headers=alice).json()]
    assert "ok" not in names
    assert env.client.post("/v2/issue-views/import", json={"views": []},
                           headers=alice).status_code == 422  # fmt: skip


def test_columns_and_density_are_remembered_per_person(env: Env) -> None:
    alice, bob = token(env, "Alice"), token(env, "Bob")
    fresh = env.client.get("/v2/me/tables/issues", headers=alice).json()
    assert fresh["columns"] == list(DEFAULT_COLUMNS) and fresh["density"] == "comfortable"
    assert fresh["saved"] is False and "path" in fresh["all_columns"]
    r = env.client.put(
        "/v2/me/tables/issues", json={"columns": ["path", "severity"]}, headers=alice
    )
    assert r.status_code == 200 and r.json()["columns"] == ["path", "severity"]
    r = env.client.put("/v2/me/tables/issues", json={"density": "compact"}, headers=alice)
    assert r.json()["columns"] == ["path", "severity"] and r.json()["density"] == "compact"
    assert env.client.get("/v2/me/tables/issues", headers=alice).json()["saved"] is True
    assert env.client.get("/v2/me/tables/issues", headers=bob).json()["density"] == "comfortable"
    for bad in ({"columns": []}, {"columns": ["title"]}, {"density": "tiny"}):
        assert env.client.put("/v2/me/tables/issues", json=bad, headers=alice).status_code == 422
    assert env.client.get("/v2/me/tables/other", headers=alice).status_code == 404


def test_a_report_shows_a_saved_view_as_its_owner_sees_it(
    env: Env, org: dict[str, Any], fake_chromium: list[str]  # noqa: F811
) -> None:
    alice = org["alice"]
    v = make(env, alice, name="Payments breached", query="project:payments-* sla:breached")
    hidden = make(env, token(env, "Bob"), name="Bob's")
    blocks = [
        {"id": "v", "type": "issues", "config": {"kind": "view", "view_id": v["id"], "limit": 10}},
        {"id": "me", "type": "issues", "config": {"kind": "view", "view_id": "builtin:mine"}},
    ]
    r = env.client.post("/v2/reports", json={"name": "Weekly", "blocks": blocks}, headers=alice)
    assert r.status_code == 201, r.text
    rep = r.json()
    assert rep["blocks"][0]["config"] == {"kind": "view", "view_id": v["id"], "band": None,
                                          "filters": {}, "limit": 10, "title": ""}  # fmt: skip
    # A view Alice cannot see is refused, naming the block.
    bad = [
        *blocks,
        {"id": "h", "type": "issues", "config": {"kind": "view", "view_id": hidden["id"]}},
    ]
    r = env.client.put(
        f"/v2/reports/{rep['id']}", json={"version": 1, "blocks": bad}, headers=alice
    )
    assert r.status_code == 422 and r.json()["detail"]["field"] == "blocks[2].config.view_id"
    r = env.client.put(f"/v2/reports/{rep['id']}", headers=alice,
                       json={"version": 1, "blocks": [{"id": "x", "type": "issues",
                                                       "config": {"kind": "view"}}]})  # fmt: skip
    assert r.status_code == 422 and r.json()["detail"]["field"] == "blocks[0].config.view_id"

    assert env.client.post(f"/v2/reports/{rep['id']}/runs", headers=alice).status_code == 202
    html = fake_chromium[-1]
    assert "Payments breached" in html and "SQL injection in checkout" in html
    assert "saved view “Payments breached”: sla:breached project:payments-*" in html
    # "Assigned to me" is the report owner's: Alice has exactly one Issue.
    assert "Assigned to me" in html

    # The view is deleted: the block says so, and the report still generates.
    assert env.client.delete(f"/v2/issue-views/{v['id']}", headers=alice).status_code == 204
    assert env.client.post(f"/v2/reports/{rep['id']}/runs", headers=alice).status_code == 202
    assert "The saved view this table showed no longer exists." in fake_chromium[-1]
