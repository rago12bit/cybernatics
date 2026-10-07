"""Bulk changes across the org's Issues (Week 73, plan §56): a preview of the effect as counts
before anything changes (principle 9); applying names the count the person saw, and a list that
changed since changes nothing; one audit entry per Issue and one per batch; Undo within the window
puts back exactly what the batch changed and leaves alone what someone changed since; risk
acceptance stays in its own flow; nothing of another organization."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import select

from core.persistence import repo
from core.persistence.models import AuditEntry, IssueBatch, IssueRow, OutboxEvent, Tag
from core.search import bulk
from core.tenancy import DEFAULT_ORG_ID as ORG
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_issue_search import org  # noqa: F401  (the fixture)
from tests.unit.test_risk_acceptance import token

ORG_B = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


def preview(env: Env, headers: dict[str, str] = AUTH, **body: Any) -> dict[str, Any]:
    r = env.client.post("/v2/issues/bulk/preview", json=body, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def apply(env: Env, headers: dict[str, str] = AUTH, status: int = 200, **body: Any) -> Any:
    r = env.client.post("/v2/issues/bulk", json=body, headers=headers)
    assert r.status_code == status, r.text
    return r.json()


def rows(env: Env, ids: list[str]) -> dict[str, IssueRow]:
    with env.sessions() as s:
        return {i.id: i for i in s.scalars(select(IssueRow).where(IssueRow.id.in_(ids)))}


def test_assign_everything_matching_then_undo(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    bob = token(env, "Bob")
    alice = org["alice"]
    q = "project:payments-*"  # the active queue: api[0], ui[0] (acceptance ran out), ui[1..3]
    p = preview(env, alice, q=q, action="assign", params={"to": "@bob"})
    assert (p["selected"], p["will_change"], p["unchanged"], p["skipped"]) == (5, 5, 0, [])
    assert p["expected_count"] == 5 and p["reversible"] is True
    assert {x["project"]: x["count"] for x in p["by_project"]} == {"acme/payments-api": 1,
                                                                  "acme/payments-ui": 4}  # fmt: skip
    assert p["sentence"] == "Assign to Bob: 5 Issues will change."
    picked = [org["api"][0], *org["ui"]]
    assert all(r.assignee != "x" for r in rows(env, picked).values())  # preview changed nothing
    before = {k: r.assignee for k, r in rows(env, picked).items()}

    done = apply(env, alice, q=q, action="assign", params={"to": "bob"}, expected_count=5)
    assert done["changed"] == 5 and done["sentence"] == "Assign to Bob: 5 Issues changed."
    assert done["undo_until"]
    now = rows(env, picked)
    bob_actor = next(iter({r.assignee for r in now.values()}))
    assert (
        bob_actor
        and bob_actor.startswith("token:")
        and len({r.assignee for r in now.values()}) == 1
    )
    with env.sessions() as s:
        per_issue = list(s.scalars(select(AuditEntry).where(AuditEntry.target.in_(picked),
                                                             AuditEntry.action == "issue.assigned")))  # fmt: skip
        assert len(per_issue) == 5
        batch = s.scalar(
            select(AuditEntry).where(AuditEntry.target == f"issue_batch:{done['batch_id']}")
        )
        assert batch is not None and batch.action == "issues.bulk.applied"
        events = [e for e in s.scalars(select(OutboxEvent).where(OutboxEvent.event_type == "issue.assigned"))
                  if e.payload.get("batch_id") == done["batch_id"]]  # fmt: skip
        assert len(events) == 5
        # The chain still verifies with many entries written in one commit.
        from core.audit import verify_chain

        assert verify_chain(repo.list_audit_entries(s)).ok

    # Bob cannot undo Alice's change; Alice can, once.
    url = f"/v2/issue-batches/{done['batch_id']}/undo"
    assert env.client.post(url, headers=bob).status_code == 403
    r = env.client.post(url, headers=alice)
    assert r.status_code == 200, r.text
    assert r.json() == {"restored": 5, "kept": 0, "sentence": "Undone: 5 Issues back as they were."}
    assert {k: r.assignee for k, r in rows(env, picked).items()} == before
    assert env.client.post(url, headers=alice).status_code == 409
    with env.sessions() as s:
        labels = [e["label"] for e in repo.issue_history(s, org["api"][0])]
    assert labels.count("Assigned") == 1 and "Bulk change undone" in labels


def test_a_list_that_changed_since_the_preview_changes_nothing(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    body = {"q": "project:payments-*", "action": "tag", "params": {"tag": "pci"}}
    assert preview(env, **body)["expected_count"] == 5
    r = env.client.post("/v2/issues/bulk", json={**body, "expected_count": 4}, headers=AUTH)
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["selected"] == 5 and "5 Issues match now, not 4" in detail["message"]
    with env.sessions() as s:
        assert s.scalar(select(Tag).where(Tag.name == "pci")) is None
        assert s.scalar(select(IssueBatch)) is None
    for bad in (None, "5", True):
        r = env.client.post("/v2/issues/bulk", json={**body, "expected_count": bad}, headers=AUTH)
        assert r.status_code == 422 and r.json()["detail"]["field"] == "expected_count"


def test_not_a_risk_leaves_accepted_and_fixed_alone_and_undo_keeps_later_changes(
    env: Env, org: dict[str, Any]  # noqa: F811
) -> None:
    api = org["api"]
    q = "project:acme/payments-api status:open,accepted,fixed"
    r = env.client.post("/v2/issues/bulk/preview", headers=AUTH,
                        json={"q": q, "action": "not_a_risk", "params": {}})  # fmt: skip
    assert r.status_code == 422 and r.json()["detail"]["field"] == "reason"
    p = preview(env, q=q, action="not_a_risk", params={"reason": "Test fixtures only"})
    assert (p["selected"], p["will_change"]) == (3, 1)
    assert sorted((x["reason"], x["count"]) for x in p["skipped"]) == [
        (bulk.FIXED, 1), (bulk.UNDER_ACCEPTANCE, 1)]  # fmt: skip
    assert "1 left alone (under a risk acceptance: decide it there)" in p["sentence"]
    done = apply(env, q=q, action="not_a_risk", params={"reason": "Test fixtures only"},
                 expected_count=3)  # fmt: skip
    after = rows(env, api)
    assert after[api[0]].triage_status == "not_a_risk"
    assert after[api[0]].triage_reason == "Test fixtures only"
    assert after[api[1]].triage_status == "accepted" and after[api[3]].state == "fixed"

    # Reopen in bulk, then someone marks one again on its own before the reopen is undone.
    reopened = apply(env, q="project:acme/payments-api status:not_a_risk", action="reopen",
                     params={}, expected_count=2)  # fmt: skip
    assert reopened["changed"] == 2
    with env.sessions() as s:
        repo.triage_issue(s, api[2], org_id=ORG, action="not_a_risk", reason="Really",
                          actor="token:someone")  # fmt: skip
    u = env.client.post(f"/v2/issue-batches/{reopened['batch_id']}/undo", headers=AUTH).json()
    assert (u["restored"], u["kept"]) == (1, 1)
    assert "1 Issue changed since by someone else and was left as it is." in u["sentence"]
    after = rows(env, api)
    assert after[api[0]].triage_status == "not_a_risk"  # back, from the undo
    assert after[api[2]].triage_reason == "Really"  # someone's later change, kept
    # api[0] is again as the first batch left it, so that batch can still be undone.
    u = env.client.post(f"/v2/issue-batches/{done['batch_id']}/undo", headers=AUTH).json()
    assert u["restored"] == 1 and rows(env, api)[api[0]].triage_status == "open"


def test_undo_has_a_window(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    done = apply(env, q="project:acme/ledger", action="tag", params={"tag": "Q4 Audit"},
                 expected_count=4)  # fmt: skip
    assert done["sentence"] == "Add the tag “q4-audit”: 4 Issues changed."
    with env.sessions() as s:
        b = s.get(IssueBatch, done["batch_id"])
        assert b is not None
        b.undo_until = b.undo_until - timedelta(seconds=bulk.UNDO_SECONDS + bulk.GRACE_SECONDS + 1)
        s.commit()
    r = env.client.post(f"/v2/issue-batches/{done['batch_id']}/undo", headers=AUTH)
    assert r.status_code == 409 and "Too late" in r.json()["detail"]["message"]
    assert env.client.post("/v2/issue-batches/nope/undo", headers=AUTH).status_code == 404


def test_tags_on_picked_issues_only_and_never_another_orgs(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    ledger, other = org["ledger"], org["other"]
    picked = [ledger[0], ledger[1], other[0]]
    p = preview(env, q="", ids=picked, action="tag", params={"tag": "pci"})
    assert p["selected"] == 2  # another organization's Issue is not selectable
    done = apply(env, q="", ids=picked, action="tag", params={"tag": "pci"}, expected_count=2)
    with env.sessions() as s:
        tagged = set(s.scalars(select(Tag.target_id).where(Tag.name == "pci")))
    assert tagged == {ledger[0], ledger[1]}
    again = preview(env, q="", ids=picked, action="tag", params={"tag": "pci"})
    assert (again["will_change"], again["unchanged"]) == (0, 2)
    gone = apply(env, q="tag:pci", action="untag", params={"tag": "pci"}, expected_count=2)
    assert gone["changed"] == 2
    u = env.client.post(f"/v2/issue-batches/{gone['batch_id']}/undo", headers=AUTH).json()
    assert u["restored"] == 2
    with env.sessions() as s:
        assert set(s.scalars(select(Tag.target_id).where(Tag.name == "pci"))) == tagged
    u = env.client.post(f"/v2/issue-batches/{done['batch_id']}/undo", headers=AUTH).json()
    assert u["restored"] == 2
    with env.sessions() as s:
        assert s.scalar(select(Tag).where(Tag.name == "pci")) is None

    # From the other organization, the default org's Issues and batches are not there.
    assert (
        preview(env, ORG_B, q="", ids=picked[:2], action="tag", params={"tag": "x"})["selected"]
        == 0
    )
    assert env.client.post(f"/v2/issue-batches/{done['batch_id']}/undo",
                           headers=ORG_B).status_code == 404  # fmt: skip


def test_risk_acceptance_is_its_own_flow(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    p = preview(env, q="project:payments-* status:open,accepted", action="accept", params={})
    assert p["reversible"] is False
    projects = {x["project"]: x for x in p["flow"]["projects"]}
    assert set(projects) == {"acme/payments-api", "acme/payments-ui"}
    assert projects["acme/payments-ui"]["count"] == 4  # including the one whose acceptance ran out
    assert projects["acme/payments-api"]["issue_ids"] == [org["api"][0]]
    assert dict((x["reason"], x["count"]) for x in p["skipped"]) == {bulk.UNDER_ACCEPTANCE: 1}
    assert "one request per project, which a second person approves" in p["sentence"]
    r = env.client.post("/v2/issues/bulk", headers=AUTH,
                        json={"q": "", "action": "accept", "params": {}, "expected_count": 5})  # fmt: skip
    assert r.status_code == 409 and "second person" in r.json()["detail"]["message"]


def test_requests_are_checked(
    env: Env, org: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:  # noqa: F811,E501
    r = env.client.post("/v2/issues/bulk/preview", headers=AUTH,
                        json={"q": "severity:huge", "action": "reopen"})  # fmt: skip
    assert r.status_code == 422 and (r.json()["detail"]["start"], r.json()["detail"]["end"]) == (
        9,
        13,
    )
    for body, field in (({"action": "delete"}, "action"),
                        ({"action": "assign", "params": {"to": "@nobody"}}, "to"),
                        ({"action": "tag", "params": {"tag": "!"}}, "tag"),
                        ({"action": "reopen", "ids": []}, "ids"),
                        ({"action": "reopen", "ids": "x"}, "ids")):  # fmt: skip
        r = env.client.post("/v2/issues/bulk/preview", json={"q": "", **body}, headers=AUTH)
        assert r.status_code == 422 and r.json()["detail"]["field"] == field, (body, r.text)
    monkeypatch.setattr(bulk, "MAX_BULK", 3)
    r = env.client.post("/v2/issues/bulk/preview", json={"q": "", "action": "reopen"}, headers=AUTH)
    assert r.status_code == 413 and "At most 3 Issues at once" in r.json()["detail"]["message"]
    reader = token(env, "Reader", scopes=["scans:read"])
    r = env.client.post(
        "/v2/issues/bulk/preview", json={"q": "", "action": "reopen"}, headers=reader
    )
    assert r.status_code == 403
