"""Collaboration (Week 64, plan §49): threaded notes with @mentions, files on notes served only from
the separate attachments origin, and tags inherited from portfolio to project to issue."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.deps import AppState
from api.main import create_app
from core.collab.notes import mentioned
from core.collab.people import Person, handle_of
from core.models import Severity
from core.persistence.models import AuditEntry, IssueRow, OutboxEvent
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token
from tests.unit.test_sla import finding, scan

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


@pytest.fixture
def crew(env: Env) -> dict[str, Any]:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.LOW)])
    with env.sessions() as s:
        issues = {i.title: i.id for i in s.scalars(select(IssueRow))}
    return {
        "priya": token(env, "Priya N."),
        "arjun": token(env, "Arjun K."),
        "issue": issues["Problem 1"],
        "other_issue": issues["Problem 2"],
    }


def post(env: Env, issue: str, body: str, who: Any, parent: str | None = None) -> Any:
    return env.client.post(f"/v2/issues/{issue}/notes", json={"body": body, "parent_id": parent},
                           headers=who)  # fmt: skip


# --- mentions ---------------------------------------------------------------------------------------


def test_handles_and_mention_parsing() -> None:
    assert handle_of("Priya N.") == "priyan" and handle_of("Arjun K") == "arjunk"
    assert handle_of("-- Ops.Team_1 --") == "ops.team_1"
    people = [Person("token:a", "Priya N", "priyan"), Person("token:b", "Arjun K", "arjunk"),
              Person("token:c", "Arjun Kumar", "arjunk")]  # fmt: skip
    body = "@PriyaN please check, cc @arjunk. Not a@priyan or email@arjunk.com; @nobody"
    assert mentioned(body, people) == ["token:a", "token:b", "token:c"]  # both Arjun Ks
    assert mentioned("no mentions here", people) == []


# --- notes ------------------------------------------------------------------------------------------


def test_a_thread_with_mentions_replies_and_names(env: Env, crew: dict[str, Any]) -> None:
    r = post(env, crew["issue"], "Reproduced on staging. @arjunk can you retest after #412?",
             crew["priya"])  # fmt: skip
    assert r.status_code == 201, r.text
    top = r.json()["notes"][0]
    assert top["mentions"] and r.json()["names"][top["mentions"][0]] == "Arjun K."
    reply = post(env, crew["issue"], "On it.", crew["arjun"], parent=top["id"]).json()["notes"]
    deeper = post(env, crew["issue"], "Thanks", crew["priya"], parent=reply[1]["id"]).json()
    assert [n["parent_id"] for n in deeper["notes"]] == [None, top["id"], top["id"]]  # one level
    listing = env.client.get(f"/v2/issues/{crew['issue']}/notes", headers=crew["arjun"]).json()
    assert [n["body"] for n in listing["notes"]][:2] == [top["body"], "On it."]
    # Arjun finds it under Mentions; Priya, who wrote it, does not
    mine = env.client.get("/v2/mentions", headers=crew["arjun"]).json()["mentions"]
    assert [m["note"]["id"] for m in mine] == [top["id"]]
    assert mine[0]["issue_title"] == "Problem 1"
    assert env.client.get("/v2/mentions", headers=crew["priya"]).json()["mentions"] == []
    with env.sessions() as s:
        ev = s.scalars(select(OutboxEvent).where(OutboxEvent.event_type == "note.mentioned")).all()
        assert len(ev) == 1 and ev[0].payload["issue_id"] == crew["issue"]
        assert "Note added" in [e["label"] for e in env.client.get(
            f"/assets/{env.asset_id}/issues/{crew['issue']}/history", headers=AUTH).json()]  # fmt: skip


def test_only_the_author_edits_or_deletes(env: Env, crew: dict[str, Any]) -> None:
    note = post(env, crew["issue"], "First draft", crew["priya"]).json()["notes"][0]
    url = f"/v2/notes/{note['id']}"
    assert (
        env.client.patch(url, json={"body": "Hijacked"}, headers=crew["arjun"]).status_code == 403
    )
    edited = env.client.patch(url, json={"body": "Now with @arjunk"}, headers=crew["priya"]).json()
    assert edited["notes"][0]["body"] == "Now with @arjunk" and edited["notes"][0]["edited_at"]
    assert env.client.delete(url, headers=crew["arjun"]).status_code == 403
    gone = env.client.delete(url, headers=crew["priya"]).json()["notes"][0]
    assert gone["deleted"] is True and gone["body"] == ""
    assert env.client.patch(url, json={"body": "back"}, headers=crew["priya"]).status_code == 409
    with env.sessions() as s:
        actions = [a.action for a in s.scalars(select(AuditEntry))]
        assert {"issue.note.added", "issue.note.edited", "issue.note.deleted"} <= set(actions)
        # the edit newly mentioned Arjun: one announcement
        assert len(s.scalars(select(OutboxEvent).where(
            OutboxEvent.event_type == "note.mentioned")).all()) == 1  # fmt: skip


def test_notes_are_validated_and_stay_in_their_org(env: Env, crew: dict[str, Any]) -> None:
    assert post(env, crew["issue"], "   ", crew["priya"]).status_code == 422
    assert post(env, crew["issue"], "x" * 10_001, crew["priya"]).status_code == 422
    note = post(env, crew["issue"], "hi", crew["priya"]).json()["notes"][0]
    wrong = post(env, crew["other_issue"], "reply", crew["priya"], parent=note["id"])
    assert wrong.status_code == 404  # a reply goes on its own issue
    assert env.client.get(f"/v2/issues/{crew['issue']}/notes", headers=OTHER).status_code == 404
    assert post(env, crew["issue"], "x", OTHER).status_code == 404
    assert env.client.delete(f"/v2/notes/{note['id']}", headers=OTHER).status_code == 404


def test_people_lists_live_personal_tokens(env: Env, crew: dict[str, Any]) -> None:
    people = env.client.get("/v2/people", headers=AUTH).json()
    assert [(p["name"], p["handle"]) for p in people] == [
        ("Arjun K.", "arjunk"),
        ("Priya N.", "priyan"),
    ]


# --- files on notes and the attachments origin -------------------------------------------------------


def test_a_file_on_a_note_downloads_only_from_the_attachments_origin(
    env: Env, crew: dict[str, Any]
) -> None:
    note = post(env, crew["issue"], "Capture attached", crew["priya"]).json()["notes"][0]
    files = {"file": ("capture.html", b"<html><script>alert(1)</script></html>", "text/html")}
    assert env.client.post(f"/v2/notes/{note['id']}/attachments", files=files,
                           headers=crew["arjun"]).status_code == 403  # fmt: skip
    up = env.client.post(f"/v2/notes/{note['id']}/attachments", files=files, headers=crew["priya"])
    assert up.status_code == 201, up.text
    assert up.json()["active_content"] is True and up.json()["sniffed_type"] == "text/html"
    listing = env.client.get(f"/v2/issues/{crew['issue']}/notes", headers=AUTH).json()
    assert listing["notes"][0]["files"][0]["file_name"] == "capture.html"

    # A separate, cookieless origin for files: the app built with one configured.
    st = env.client.app.state.bulwark  # type: ignore[attr-defined]
    files_app = create_app(AppState(
        settings=st.settings.__class__(**{**st.settings.__dict__,
                                          "attachments_origin": "http://files.localhost:8000"}),
        sessions=st.sessions, enqueue=st.enqueue, subscriber=st.subscriber,
    ))  # fmt: skip
    api = TestClient(files_app, base_url="http://localhost:8000")
    link = api.post(f"/v2/note-attachments/{up.json()['id']}/link", headers=AUTH).json()["url"]
    assert link.startswith("http://files.localhost:8000/v2/attachments/")
    path = link.removeprefix("http://files.localhost:8000")
    files_host = TestClient(files_app, base_url="http://files.localhost:8000")
    got = files_host.get(path)
    assert got.status_code == 200 and got.content.startswith(b"<html>")
    assert got.headers["content-disposition"].startswith("attachment")
    assert got.headers["content-type"] == "application/octet-stream"
    assert "set-cookie" not in got.headers
    assert api.get(path).status_code == 404  # never from the API's own host
    # the files host serves nothing else: not the API, not with a token
    assert files_host.get(f"/v2/issues/{crew['issue']}/notes", headers=AUTH).status_code == 404
    assert files_host.post(f"/v2/note-attachments/{up.json()['id']}/link",
                           headers=AUTH).status_code == 404  # fmt: skip
    # a manual finding's evidence link is not a note's
    assert api.post("/v2/note-attachments/00000000-0000-4000-8000-000000000000/link",
                    headers=AUTH).status_code == 404  # fmt: skip
    # deleting the note removes its files
    env.client.delete(f"/v2/notes/{note['id']}", headers=crew["priya"])
    assert files_host.get(path).status_code == 404


# --- tags -------------------------------------------------------------------------------------------


def test_tags_inherit_from_portfolio_to_project_to_issue(env: Env, crew: dict[str, Any]) -> None:
    p = env.client.post("/v2/portfolios", json={"name": "Payments"}, headers=AUTH).json()
    assert env.client.put(f"/v2/portfolios/{p['id']}/tags", json={"tags": ["PCI DSS", "tier-1"]},
                          headers=AUTH).json()["tags"] == ["pci-dss", "tier-1"]  # fmt: skip
    env.client.put(f"/v2/projects/{env.asset_id}/tags", json={"tags": ["payments"]}, headers=AUTH)
    project = env.client.put(f"/v2/projects/{env.asset_id}/portfolio",
                             json={"portfolio_id": p["id"]}, headers=AUTH).json()  # fmt: skip
    assert project["own"] == ["payments"] and project["portfolio"]["name"] == "Payments"
    assert [t["name"] for t in project["inherited"]] == ["pci-dss", "tier-1"]
    issue = env.client.put(f"/v2/issues/{crew['issue']}/tags", json={"tags": ["idor", "tier-1"]},
                           headers=AUTH).json()  # fmt: skip
    assert issue["own"] == ["idor", "tier-1"]
    assert [(t["name"], t["from"]) for t in issue["inherited"]] == [
        ("payments", "project"),
        ("pci-dss", "portfolio"),
    ]  # its own tier-1 is not repeated

    # the issues table filters by a tag wherever it was set
    def titles(tag: str) -> list[str]:
        r = env.client.get(f"/assets/{env.asset_id}/issues", params={"tag": tag}, headers=AUTH)
        assert r.status_code == 200, r.text
        return sorted(i["title"] for i in r.json()["items"])

    assert titles("idor") == ["Problem 1"]
    assert titles("payments") == ["Problem 1", "Problem 2"]
    assert titles("PCI DSS") == ["Problem 1", "Problem 2"]
    assert titles("nothing") == []
    env.client.put(
        f"/v2/projects/{env.asset_id}/portfolio", json={"portfolio_id": None}, headers=AUTH
    )
    assert titles("pci-dss") == []


def test_tags_are_validated_and_audited(env: Env, crew: dict[str, Any]) -> None:
    url = f"/v2/issues/{crew['issue']}/tags"
    for bad in (["<script>"], ["-leading"], ["x" * 51]):
        r = env.client.put(url, json={"tags": bad}, headers=AUTH)
        assert r.status_code == 422 and r.json()["detail"]["field"] == "tags", bad
    assert (
        env.client.put(url, json={"tags": [f"t{i}" for i in range(21)]}, headers=AUTH).status_code
        == 422
    )
    assert env.client.put(url, json={"tags": ["a", "A", " a "]}, headers=AUTH).json()["own"] == [
        "a"
    ]
    env.client.put(url, json={"tags": ["a"]}, headers=AUTH)  # no change: no entry
    assert env.client.get(f"/assets/{env.asset_id}/issues", params={"tag": "<x>"},
                          headers=AUTH).status_code == 422  # fmt: skip
    assert env.client.put(url, json={"tags": ["x"]}, headers=OTHER).status_code == 404
    assert env.client.put(f"/v2/projects/{env.asset_id}/portfolio", headers=AUTH,
                          json={"portfolio_id": "00000000-0000-4000-8000-000000000000"}).status_code == 422  # fmt: skip
    with env.sessions() as s:
        assert (
            len(s.scalars(select(AuditEntry).where(AuditEntry.action == "tags.changed")).all()) == 1
        )
