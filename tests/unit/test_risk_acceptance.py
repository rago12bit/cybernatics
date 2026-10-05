"""Risk acceptance (Week 62, plan §44.2): the Issues stay open until someone else approves; the
server, not a screen, enforces who that can be; expiry reopens them (and can restart their SLA);
expire now, reinstate and extend; every change audited; legacy accept-by-triage is closed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from core.acceptance import service
from core.models import Severity
from core.persistence import repo
from core.persistence.models import AuditEntry, IssueRow, OutboxEvent, RiskAcceptance
from core.sla.policy import STARTER
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_sla import age, finding, scan

SOON = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()


def token(
    env: Env, name: str, scopes: list[str] | None = None, org: str = DEFAULT_ORG_ID
) -> dict[str, str]:
    with env.sessions() as s:
        _, raw = repo.create_api_token(
            s, org_id=org, name=name, scopes=scopes or ["scans:read", "scans:write"]
        )
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture
def people(env: Env) -> dict[str, dict[str, str]]:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH), finding(3, Severity.CRITICAL)])
    return {
        "alice": token(env, "Alice"),
        "bob": token(env, "Bob"),
        "carol": token(env, "Carol"),
        "reader": token(env, "Reader", ["scans:read"]),
    }


def ids(env: Env, *titles: str) -> list[str]:
    with env.sessions() as s:
        rows = {i.title: i.id for i in s.scalars(select(IssueRow))}
    return [rows[t] for t in titles]


def ask(env: Env, who: dict[str, str], issue_ids: list[str], **over: Any) -> Any:
    body = {"issue_ids": issue_ids, "decision": "accept",
            "justification": "Legacy export service, retired on 30 November.",
            "controls": "WAF rule 9412 blocks the payload pattern.", "expires_at": SOON, **over}  # fmt: skip
    return env.client.post(f"/v2/projects/{env.asset_id}/risk-acceptances", json=body, headers=who)


def act(env: Env, who: dict[str, str], ra_id: str, action: str, **body: Any) -> Any:
    return env.client.post(f"/v2/risk-acceptances/{ra_id}/{action}", json=body or None, headers=who)


def triage(env: Env) -> dict[str, tuple[str, Any]]:
    with env.sessions() as s:
        return {
            i.title: (i.triage_status, i.triage_expires_at) for i in s.scalars(select(IssueRow))
        }


# --- requesting -----------------------------------------------------------------------------------


def test_a_request_leaves_the_issues_open_until_someone_else_approves(
    env: Env, people: Any
) -> None:
    r = ask(env, people["alice"], ids(env, "Problem 1", "Problem 2"), restart_sla=True)
    assert r.status_code == 201, r.text
    ra = r.json()
    assert (ra["state"], ra["issue_count"], ra["can_decide"]) == ("requested", 2, False)
    assert ra["requested_by"].startswith("token:") and ra["days"] in (29, 30)
    assert {t for t, _ in triage(env).values()} == {"open"}

    assert act(env, people["alice"], ra["id"], "approve").status_code == 403  # the requester
    assert act(env, AUTH, ra["id"], "approve").status_code == 403  # the shared token: anyone
    assert act(env, people["reader"], ra["id"], "approve").status_code == 403  # cannot write
    done = act(env, people["bob"], ra["id"], "approve", note="Checked the WAF rule.")
    assert done.status_code == 200, done.text
    assert (done.json()["state"], done.json()["decided_by"]) == (
        "approved",
        done.json()["decided_by"],
    )
    assert done.json()["decided_by"] != ra["requested_by"]
    states = triage(env)
    assert states["Problem 1"][0] == "accepted" and states["Problem 2"][0] == "accepted"
    assert states["Problem 3"][0] == "open"
    # Approved issues leave the active queue; the policy gate still sees the expiry.
    assert all(i["title"] == "Problem 3" for i in env.client.get(
        f"/assets/{env.asset_id}/issues", headers=AUTH).json()["items"])  # fmt: skip


def test_a_designated_approver_is_the_only_one_who_can_decide(env: Env, people: Any) -> None:
    pol = env.client.get("/v2/risk-acceptance-policy", headers=people["alice"]).json()
    names = [a["name"] for a in pol["approvers"]]
    assert names == ["Bob", "Carol"] and pol["max_days"] == 90 and pol["can_approve"] is True
    bob = next(a["actor"] for a in pol["approvers"] if a["name"] == "Bob")
    ra = ask(env, people["alice"], ids(env, "Problem 1"), approver=bob).json()
    assert act(env, people["carol"], ra["id"], "approve").status_code == 403
    assert act(env, people["bob"], ra["id"], "approve").status_code == 200
    me = ask(env, people["alice"], ids(env, "Problem 2"), approver=pol["you"])
    assert me.status_code == 422 and me.json()["detail"]["field"] == "approver"
    assert env.client.get("/v2/risk-acceptance-policy", headers=AUTH).json()["can_approve"] is False


@pytest.mark.parametrize(
    ("over", "field"),
    [
        ({"justification": "  "}, "justification"),
        ({"controls": ""}, "controls"),
        ({"decision": "ignore"}, "decision"),
        ({"expires_at": None}, "expires_at"),
        ({"expires_at": "2020-01-01T00:00:00Z"}, "expires_at"),
        (
            {"expires_at": (datetime.now(timezone.utc) + timedelta(days=91)).isoformat()},
            "expires_at",
        ),
        ({"proof_links": ["javascript:alert(1)"]}, "proof_links"),
    ],
)
def test_a_request_is_validated_with_the_field_named(
    env: Env, people: Any, over: dict[str, Any], field: str
) -> None:
    r = ask(env, people["alice"], ids(env, "Problem 1"), **over)
    assert r.status_code == 422 and r.json()["detail"]["field"] == field, r.text


def test_an_issue_is_covered_by_one_live_acceptance_and_must_be_this_projects(
    env: Env, people: Any
) -> None:
    one = ids(env, "Problem 1")
    assert ask(env, people["alice"], one).status_code == 201
    again = ask(env, people["bob"], one)
    assert again.status_code == 409 and "already covered" in again.json()["detail"]["message"]
    other = token(env, "Other org", org=OTHER_ORG)
    assert ask(env, other, one).status_code == 404  # another org's project
    r = env.client.post(f"/v2/projects/{env.other_asset_id}/risk-acceptances",
                        json={"issue_ids": one, "decision": "accept", "justification": "x",
                              "controls": "y", "expires_at": SOON}, headers=other)  # fmt: skip
    assert r.status_code == 404  # the Issue is not in that org's project


def test_rejecting_needs_a_reason_and_withdrawing_is_the_requesters(env: Env, people: Any) -> None:
    ra = ask(env, people["alice"], ids(env, "Problem 1")).json()
    assert act(env, people["bob"], ra["id"], "reject").status_code == 422
    assert act(env, people["bob"], ra["id"], "withdraw").status_code == 403
    no = act(env, people["bob"], ra["id"], "reject", note="Not retired yet.").json()
    assert (no["state"], no["decision_note"]) == ("rejected", "Not retired yet.")
    assert act(env, people["carol"], ra["id"], "approve").status_code == 409
    second = ask(env, people["alice"], ids(env, "Problem 1")).json()  # the Issue is free again
    assert act(env, people["alice"], second["id"], "withdraw").json()["state"] == "withdrawn"


def test_single_person_accept_through_triage_is_closed(env: Env, people: Any) -> None:
    issue = ids(env, "Problem 1")[0]
    r = env.client.post(f"/assets/{env.asset_id}/issues/{issue}/triage", headers=people["alice"],
                        json={"action": "accepted", "expires_at": SOON})  # fmt: skip
    assert r.status_code == 409 and "approval" in r.json()["detail"]
    r = env.client.post(f"/assets/{env.asset_id}/issues/bulk-triage", headers=people["alice"],
                        json={"issue_ids": [issue], "action": "accepted", "expires_at": SOON})  # fmt: skip
    assert r.status_code == 409
    ok = env.client.post(f"/assets/{env.asset_id}/issues/{issue}/triage", headers=people["alice"],
                         json={"action": "not_a_risk", "reason": "test fixture"})  # fmt: skip
    assert ok.status_code == 200


# --- the lifecycle --------------------------------------------------------------------------------


def approved(env: Env, people: Any, *titles: str, **over: Any) -> dict[str, Any]:
    ra = ask(env, people["alice"], ids(env, *titles), **over).json()
    return act(env, people["bob"], ra["id"], "approve").json()  # type: ignore[no-any-return]


def test_expiry_reopens_and_can_restart_the_sla_clock(env: Env, people: Any) -> None:
    age(env, {"Problem 1": 40, "Problem 2": 40})
    env.client.put(f"/v2/projects/{env.asset_id}/sla", json={"enabled": True, "bands": STARTER},
                   headers=AUTH)  # fmt: skip
    restart = approved(env, people, "Problem 1", restart_sla=True)
    keep = approved(env, people, "Problem 2")
    later = datetime.now(timezone.utc) + timedelta(days=31)
    sent: list[str] = []
    with env.sessions() as s:
        out = service.expire_due(s, DEFAULT_ORG_ID, now=later, notify=lambda *a: sent.append(a[2]))
        assert {r.id for r in out.expired} == {restart["id"], keep["id"]}
        rows = {i.title: i for i in s.scalars(select(IssueRow))}
        assert (
            rows["Problem 1"].triage_status == "open" and rows["Problem 2"].triage_status == "open"
        )
        assert rows["Problem 1"].sla_started_at == later  # its 30 days start again
        assert rows["Problem 2"].sla_started_at is None  # still from first detection: breached
        assert service.expire_due(s, DEFAULT_ORG_ID, now=later).expired == []  # once
    assert sent == ["expired", "expired"]
    assert env.client.get(f"/v2/risk-acceptances/{restart['id']}", headers=AUTH).json()[
        "ended_reason"] == "expiry"  # fmt: skip


def test_a_request_whose_date_passes_unapproved_lapses(env: Env, people: Any) -> None:
    ra = ask(env, people["alice"], ids(env, "Problem 1")).json()
    with env.sessions() as s:
        service.expire_due(s, DEFAULT_ORG_ID, now=datetime.now(timezone.utc) + timedelta(days=31))
    got = env.client.get(f"/v2/risk-acceptances/{ra['id']}", headers=AUTH).json()
    assert (got["state"], got["ended_reason"]) == ("withdrawn", "lapsed")


def test_expire_now_then_reinstate_within_the_approved_dates(env: Env, people: Any) -> None:
    ra = approved(env, people, "Problem 1")
    gone = act(env, people["carol"], ra["id"], "expire").json()
    assert (gone["state"], gone["ended_reason"]) == ("expired", "expire_now")
    assert triage(env)["Problem 1"][0] == "open"
    back = act(env, people["carol"], ra["id"], "reinstate").json()
    assert back["state"] == "approved" and triage(env)["Problem 1"][0] == "accepted"
    assert act(env, people["carol"], ra["id"], "reinstate").status_code == 409  # not expired


def test_an_extension_is_a_new_request_and_needs_its_own_approval(env: Env, people: Any) -> None:
    ra = approved(env, people, "Problem 1", "Problem 2")
    later = (datetime.now(timezone.utc) + timedelta(days=80)).isoformat()
    ext = act(env, people["alice"], ra["id"], "extend", expires_at=later,
              justification="Retirement slipped to January.").json()  # fmt: skip
    assert (ext["state"], ext["extends_id"], ext["issue_count"]) == ("requested", ra["id"], 2)
    assert (
        env.client.get(f"/v2/risk-acceptances/{ra['id']}", headers=AUTH).json()["state"]
        == "approved"
    )
    assert act(env, people["alice"], ext["id"], "approve").status_code == 403  # still four eyes
    assert act(env, people["carol"], ext["id"], "approve").json()["state"] == "approved"
    assert (
        env.client.get(f"/v2/risk-acceptances/{ra['id']}", headers=AUTH).json()["state"]
        == "extended"
    )
    with env.sessions() as s:
        exp = {
            i.triage_expires_at
            for i in s.scalars(select(IssueRow))
            if i.triage_status == "accepted"
        }
    assert len(exp) == 1 and abs(next(iter(exp)) - datetime.fromisoformat(later)) < timedelta(
        seconds=1
    )
    shorter = act(env, people["alice"], ext["id"], "extend", expires_at=SOON)
    assert shorter.status_code == 422


def test_every_change_is_audited_and_shows_on_the_issue(env: Env, people: Any) -> None:
    ra = approved(env, people, "Problem 1")
    act(env, people["carol"], ra["id"], "expire")
    detail = env.client.get(f"/v2/risk-acceptances/{ra['id']}", headers=AUTH).json()
    assert [t["action"] for t in detail["trail"]] == ["requested", "approved", "expired"]
    issue = ids(env, "Problem 1")[0]
    labels = [e["label"] for e in env.client.get(
        f"/assets/{env.asset_id}/issues/{issue}/history", headers=AUTH).json()]  # fmt: skip
    assert labels[-3:] == ["Risk acceptance requested", "Risk acceptance approved",
                           "Risk acceptance expired"]  # fmt: skip
    with env.sessions() as s:
        events = [e.event_type for e in s.scalars(
            select(OutboxEvent).where(OutboxEvent.event_type.like("risk_acceptance.%")))]  # fmt: skip
        assert events == ["risk_acceptance.requested", "risk_acceptance.approved",
                          "risk_acceptance.expired"]  # fmt: skip
        entry = s.scalars(
            select(AuditEntry).where(AuditEntry.action == "risk_acceptance.approved")
        ).one()
        assert entry.target == f"risk_acceptance:{ra['id']}" and entry.actor.startswith("token:")


def test_lists_the_queue_and_another_org_sees_nothing(env: Env, people: Any) -> None:
    ra = ask(env, people["alice"], ids(env, "Problem 1")).json()
    queue = env.client.get(
        "/v2/risk-acceptances", params={"state": "requested"}, headers=people["bob"]
    ).json()
    assert [q["id"] for q in queue] == [ra["id"]] and queue[0]["can_decide"] is True
    by_issue = env.client.get(f"/v2/projects/{env.asset_id}/risk-acceptances",
                              params={"issue_id": ids(env, "Problem 1")[0]}, headers=AUTH).json()  # fmt: skip
    assert [q["id"] for q in by_issue] == [ra["id"]]
    other = token(env, "Other org", org=OTHER_ORG)
    assert env.client.get("/v2/risk-acceptances", headers=other).json() == []
    assert env.client.get(f"/v2/risk-acceptances/{ra['id']}", headers=other).status_code == 404
    assert act(env, other, ra["id"], "approve").status_code == 404


def test_proof_files_are_stored_with_the_acceptance(env: Env, people: Any) -> None:
    ra = ask(env, people["alice"], ids(env, "Problem 1")).json()
    r = env.client.post(f"/v2/risk-acceptances/{ra['id']}/attachments", headers=people["alice"],
                        files={"file": ("waf-rule.png", b"\x89PNG\r\n\x1a\n" + b"0" * 64, "image/png")})  # fmt: skip
    assert r.status_code == 201, r.text
    assert r.json()["content_type"] == "image/png"
    detail = env.client.get(f"/v2/risk-acceptances/{ra['id']}", headers=AUTH).json()
    assert [f["file_name"] for f in detail["proof_files"]] == ["waf-rule.png"]
    link = env.client.post(f"/v2/attachments/{r.json()['id']}/link", headers=AUTH)
    assert link.status_code == 200  # downloaded the same way as manual-finding evidence
    act(env, people["bob"], ra["id"], "reject", note="no")
    late = env.client.post(f"/v2/risk-acceptances/{ra['id']}/attachments", headers=people["alice"],
                           files={"file": ("x.png", b"\x89PNG\r\n\x1a\n0", "image/png")})  # fmt: skip
    assert late.status_code == 409


def test_notifications_say_who_must_decide(
    env: Env, people: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.integrations import slack

    got: list[str] = []
    monkeypatch.setattr(slack, "send", lambda url, payload: got.append(payload["text"]))
    with env.sessions() as s:
        repo.set_integration_settings(s, DEFAULT_ORG_ID, actor="t",
                                      slack_webhook_url="https://hooks.slack.com/services/x")  # fmt: skip
    ra = ask(env, people["alice"], ids(env, "Problem 1", "Problem 2")).json()
    act(env, people["bob"], ra["id"], "approve")
    assert got[0].startswith("🛡️ Risk acceptance requested for 2 issues in *")
    assert "Waiting for someone other than the requester." in got[0]
    assert got[1].startswith("✅ Risk acceptance approved by token:")


def test_the_service_refuses_what_the_api_refuses(env: Env, people: Any) -> None:
    ra = ask(env, people["alice"], ids(env, "Problem 1")).json()
    with env.sessions() as s:
        row = s.get(RiskAcceptance, ra["id"])
        assert row is not None
        with pytest.raises(service.AcceptanceError):
            service.approve(s, row, actor=row.requested_by, note=None)
        with pytest.raises(service.AcceptanceError):
            service.approve(s, row, actor=service.SHARED, note=None)
