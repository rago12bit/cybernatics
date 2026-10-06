"""Ticket sync with Jira and GitHub Issues both ways (Week 66, plan §49), one source of truth per
field, and issue groups on one ticket.

No Jira site or GitHub repository was available, so these run against a recorder that answers in
the documented response formats (Jira Cloud REST v3, GitHub REST 2022-11-28) and keeps every
request, so the tests check what Bulwark sends as well as what it does with the answer."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from core.dispatch import drain
from core.models import Severity
from core.persistence import repo
from core.persistence.models import ExternalIssueLinkRow, IssueRow, OutboxEvent
from core.tenancy import DEFAULT_ORG_ID
from core.tickets import sync
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token
from tests.unit.test_sla import finding, scan

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
JIRA = "https://acme.atlassian.net"


@dataclass
class Recorder:
    """Jira and GitHub as their docs describe them, in memory."""

    calls: list[tuple[str, str, Any]] = field(default_factory=list)
    jira: dict[str, dict[str, Any]] = field(default_factory=dict)
    gh: dict[int, dict[str, Any]] = field(default_factory=dict)
    fail: str | None = None

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
        data = json.loads(body) if body else None
        self.calls.append((method, url, data))
        if self.fail and self.fail in url:
            return 503, None
        if url.startswith(JIRA):
            return self._jira(method, url.removeprefix(JIRA), data)
        return self._github(method, url.removeprefix("https://api.github.com"), data)

    def _jira(self, method: str, path: str, data: Any) -> Any:
        if method == "POST" and path == "/rest/api/3/issue":
            key = f"PAY-{len(self.jira) + 1}"
            self.jira[key] = {
                "summary": data["fields"]["summary"],
                "labels": data["fields"].get("labels", []),
                "status": ("To Do", "new"),
                "assignee": None,
                "comments": [],
            }
            return 201, {"id": "10001", "key": key, "self": f"{JIRA}/rest/api/3/issue/10001"}
        key = path.split("/")[5].split("?")[0]
        t = self.jira[key]
        if method == "GET" and "/transitions" in path:
            return 200, {
                "expand": "transitions",
                "transitions": [
                    {
                        "id": "21",
                        "name": "Start",
                        "to": {
                            "name": "In Progress",
                            "statusCategory": {
                                "id": 4,
                                "key": "indeterminate",
                                "name": "In Progress",
                            },
                        },
                    },
                    {
                        "id": "31",
                        "name": "Done",
                        "to": {
                            "name": "Done",
                            "statusCategory": {"id": 3, "key": "done", "name": "Done"},
                        },
                    },
                ],
            }
        if method == "POST" and "/transitions" in path:
            t["status"] = {"21": ("In Progress", "indeterminate"), "31": ("Done", "done")}[
                data["transition"]["id"]
            ]
            return 204, None
        if method == "POST" and path.endswith("/comment"):
            t["comments"].append(data["body"]["content"][0]["content"][0]["text"])
            return 201, {"id": "1"}
        if method == "PUT":
            t["summary"] = data["fields"]["summary"]
            for op in data.get("update", {}).get("labels", []):
                if "add" in op and op["add"] not in t["labels"]:
                    t["labels"].append(op["add"])
                if "remove" in op and op["remove"] in t["labels"]:
                    t["labels"].remove(op["remove"])
            return 204, None
        name, cat = t["status"]
        return 200, {
            "id": "10001",
            "key": key,
            "fields": {
                "status": {"name": name, "id": "3", "statusCategory": {"id": 3, "key": cat}},
                "assignee": (
                    {"accountId": "5b10", "displayName": t["assignee"]} if t["assignee"] else None
                ),
            },
        }

    def _github(self, method: str, path: str, data: Any) -> Any:
        if method == "POST" and path == "/repos/acme/payments/issues":
            n = len(self.gh) + 1
            self.gh[n] = {
                "title": data["title"],
                "labels": list(data.get("labels", [])),
                "state": "open",
                "state_reason": None,
                "assignee": None,
                "comments": [],
            }
            return 201, {"number": n, "html_url": f"https://github.com/acme/payments/issues/{n}"}
        n = int(path.split("/")[5])
        t = self.gh[n]
        if path.endswith("/comments"):
            t["comments"].append(data["body"])
            return 201, {"id": 1}
        if method == "PATCH":
            for k in ("title", "labels", "state"):
                if k in data:
                    t[k] = data[k]
            return 200, {"number": n}
        return 200, {
            "number": n,
            "state": t["state"],
            "state_reason": t["state_reason"],
            "title": t["title"],
            "labels": [{"name": x} for x in t["labels"]],
            "assignee": {"login": t["assignee"]} if t["assignee"] else None,
        }


@pytest.fixture
def rec(monkeypatch: pytest.MonkeyPatch) -> Recorder:
    r = Recorder()
    monkeypatch.setattr(sync, "TRANSPORT", r)
    monkeypatch.setattr(sync, "RESOLVER", lambda host: ["104.192.141.1"])
    return r


def creds(env: Env) -> None:
    with env.sessions() as s:
        repo.set_integration_settings(
            s,
            DEFAULT_ORG_ID,
            actor="t",
            jira_base_url=JIRA,
            jira_email="bot@acme.example",
            jira_api_token="secret",
            github_token="ghp_x",
        )


def configure(env: Env, **kw: Any) -> Any:
    body = {"provider": "jira", "target": "PAY", **kw}
    return env.client.put(f"/v2/projects/{env.asset_id}/tickets", json=body, headers=AUTH)


def issues(env: Env) -> dict[str, IssueRow]:
    with env.sessions() as s:
        return {
            i.title: i for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id))
        }


def test_settings_are_validated_and_need_credentials(env: Env, rec: Recorder) -> None:
    assert configure(env).json()["detail"]["field"] == "provider"  # no credentials yet
    creds(env)
    for kw, bad_field in (
        ({"provider": "linear"}, "provider"),
        ({"target": "pay"}, "target"),
        ({"provider": "github", "target": "nope"}, "target"),
        ({"status_source": "both"}, "status_source"),
        ({"status_map": {"Done": "close_it"}}, "status_map"),
    ):
        r = configure(env, **kw)
        assert r.status_code == 422 and r.json()["detail"]["field"] == bad_field, (kw, r.json())
    r = configure(env, status_map={"In Review": "ready_for_retest"})
    assert r.status_code == 200
    body = r.json()
    assert body["effective_map"] == {"done": "ready_for_retest", "in review": "ready_for_retest"}
    assert body["credentials"] == {"jira": True, "github": True}
    assert env.client.get(f"/v2/projects/{env.asset_id}/tickets", headers=OTHER).status_code == 404


def test_jira_both_ways_with_status_from_the_ticket(env: Env, rec: Recorder) -> None:
    creds(env)
    configure(env, status_map={"In Review": "ready_for_retest"})
    scan(env, [finding(1, Severity.HIGH)])
    issue = issues(env)["Problem 1"]
    r = env.client.post(f"/v2/issues/{issue.id}/ticket", headers=AUTH)
    assert r.status_code == 200, r.text
    t = r.json()["ticket"]
    assert (t["id"], t["url"]) == ("PAY-1", f"{JIRA}/browse/PAY-1")
    sent = rec.calls[0][2]["fields"]
    assert sent["summary"] == "[Bulwark] Problem 1" and sent["labels"] == [
        "bulwark",
        "bulwark-severity-high",
    ]
    assert sent["issuetype"] == {"name": "Bug"} and sent["project"] == {"key": "PAY"}
    # Filing again updates, never duplicates.
    env.client.post(f"/v2/issues/{issue.id}/ticket", headers=AUTH)
    assert len(rec.jira) == 1

    # The ticket moves to "In Review" (mapped): Bulwark marks the issue ready for retest, as the
    # ticket; it never marks it fixed.
    env.client.post(f"/v2/issues/{issue.id}/ticket/sync", headers=AUTH)  # first sight: To Do
    rec.jira["PAY-1"]["status"] = ("In Review", "indeterminate")
    rec.jira["PAY-1"]["assignee"] = "Mia Krystof"
    v = env.client.post(f"/v2/issues/{issue.id}/ticket/sync", headers=AUTH).json()
    assert (v["ticket"]["status"], v["ticket"]["assignee"]) == ("In Review", "Mia Krystof")
    after = issues(env)["Problem 1"]
    assert after.retest_status == "requested" and after.state != "fixed"
    assert after.retest_requested_by == "ticket:PAY-1"
    labels = [
        e["label"]
        for e in env.client.get(
            f"/assets/{env.asset_id}/issues/{issue.id}/history", headers=AUTH
        ).json()
    ]
    assert "Ticket filed" in labels and "Marked ready for retest by its ticket, PAY-1" in labels

    # The platform's fields win: severity changes, the label follows, a hand-added label stays.
    rec.jira["PAY-1"]["labels"].append("team-payments")
    with env.sessions() as s:
        s.get(IssueRow, issue.id).severity = "CRITICAL"  # type: ignore[union-attr]
        s.commit()
        assert sync.push(s, DEFAULT_ORG_ID, "jira", "PAY-1") is True
        assert sync.push(s, DEFAULT_ORG_ID, "jira", "PAY-1") is False  # nothing new to say
    assert rec.jira["PAY-1"]["labels"] == ["bulwark", "team-payments", "bulwark-severity-critical"]

    # A scan no longer finds it: with the ticket owning status, Bulwark comments, never closes.
    scan(env, [finding(2, Severity.LOW)])
    with env.sessions() as s:
        drain(s, DEFAULT_ORG_ID)
    assert rec.jira["PAY-1"]["comments"] == ["Bulwark no longer detects this issue."]
    assert rec.jira["PAY-1"]["status"] == ("In Review", "indeterminate")


def test_platform_owned_status_closes_and_reopens_by_category(env: Env, rec: Recorder) -> None:
    creds(env)
    configure(env, status_source="platform")
    scan(env, [finding(1, Severity.HIGH)])
    issue = issues(env)["Problem 1"]
    env.client.post(f"/v2/issues/{issue.id}/ticket", headers=AUTH)
    scan(env, [finding(2, Severity.LOW)])  # fixed
    with env.sessions() as s:
        drain(s, DEFAULT_ORG_ID)
    assert rec.jira["PAY-1"]["status"] == ("Done", "done")
    posted = [d for m, u, d in rec.calls if m == "POST" and u.endswith("/transitions")]
    assert posted == [{"transition": {"id": "31"}}]
    # Closing the ticket by hand would not mark anything here (the platform owns status).
    rec.jira["PAY-1"]["status"] = ("To Do", "new")
    with env.sessions() as s:
        sync.pull(s, DEFAULT_ORG_ID, "jira", "PAY-1")
        rec.jira["PAY-1"]["status"] = ("Done", "done")
        sync.pull(s, DEFAULT_ORG_ID, "jira", "PAY-1")
    assert issues(env)["Problem 1"].retest_status is None
    scan(env, [finding(1, Severity.HIGH)])  # reintroduced
    with env.sessions() as s:
        drain(s, DEFAULT_ORG_ID)
    assert rec.jira["PAY-1"]["status"][1] == "indeterminate"


def test_a_group_is_one_github_ticket_and_watchers_hear_status(env: Env, rec: Recorder) -> None:
    creds(env)
    configure(env, provider="github", target="acme/payments")
    scan(env, [finding(i, Severity.MEDIUM) for i in (1, 2, 3)] + [finding(4, Severity.CRITICAL)])
    got = issues(env)
    priya = token(env, "Priya N.")
    for t in ("Problem 1", "Problem 4"):
        r = env.client.put(
            f"/v2/issues/{got[t].id}/group", json={"name": "jinja2 upgrade"}, headers=AUTH
        )
        assert r.status_code == 200 and r.json()["group"]["count"] in (1, 2)
    env.client.put(f"/v2/issues/{got['Problem 1'].id}/watch", headers=priya)
    v = env.client.post(f"/v2/issues/{got['Problem 1'].id}/ticket", headers=AUTH).json()
    assert v["ticket"]["id"] == "acme/payments#1" and v["group"]["count"] == 2
    assert rec.gh[1]["title"] == "[Bulwark] jinja2 upgrade (2 issues)"
    assert rec.gh[1]["labels"] == ["bulwark", "bulwark-severity-critical"]
    # Another member joins later: same ticket, with a comment.
    env.client.put(
        f"/v2/issues/{got['Problem 2'].id}/group", json={"name": "jinja2 upgrade"}, headers=AUTH
    )
    v2 = env.client.post(f"/v2/issues/{got['Problem 2'].id}/ticket", headers=AUTH).json()
    assert v2["ticket"]["id"] == "acme/payments#1" and len(rec.gh) == 1
    assert rec.gh[1]["title"] == "[Bulwark] jinja2 upgrade (3 issues)"
    assert "added 1 issue" in rec.gh[1]["comments"][0]
    group = env.client.get(f"/v2/groups/{v['group']['id']}", headers=AUTH).json()
    assert len(group["issues"]) == 3 and group["ticket"]["id"] == "acme/payments#1"
    # The developer closes it on GitHub (webhook-equivalent): every open member is ready for
    # retest, and Priya, who watches one, is told.
    with env.sessions() as s:
        sync.pull(s, DEFAULT_ORG_ID, "github", "acme/payments#1")  # first sight
        rec.gh[1].update(state="closed", state_reason="completed")
        assert (
            sync.pull(s, DEFAULT_ORG_ID, "github", "acme/payments#1")
            == ["marked ready for retest"] * 3
        )
        drain(s, DEFAULT_ORG_ID)
    assert {i.retest_status for t, i in issues(env).items() if t != "Problem 3"} == {"requested"}
    inbox = env.client.get("/v2/notifications", headers=priya).json()
    assert not any("retest" in n["title"] for n in inbox["notifications"])  # said once
    assert any(
        "acme/payments#1" in n["title"] and "“closed”" in n["title"] for n in inbox["notifications"]
    ), inbox
    # "closed (not planned)" maps to nothing by default.
    with env.sessions() as s:
        assert (
            sync.apply_remote(
                s,
                DEFAULT_ORG_ID,
                "github",
                "acme/payments#1",
                sync.Remote("closed (not planned)", True, None, None),
            )
            == ["none"] * 3
        )


def test_failures_and_isolation(env: Env, rec: Recorder, monkeypatch: pytest.MonkeyPatch) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    issue = issues(env)["Problem 1"]
    assert env.client.post(f"/v2/issues/{issue.id}/ticket", headers=AUTH).status_code == 409
    creds(env)
    configure(env)
    rec.fail = "/rest/api/3/issue"
    r = env.client.post(f"/v2/issues/{issue.id}/ticket", headers=AUTH)
    assert r.status_code == 502 and "HTTP 503" in r.json()["detail"]
    rec.fail = None
    # Jira's address must pass the SSRF guard on every call.
    monkeypatch.setattr(sync, "RESOLVER", lambda host: ["169.254.169.254"])
    r = env.client.post(f"/v2/issues/{issue.id}/ticket", headers=AUTH)
    assert r.status_code == 422 and "non-public" in r.json()["detail"]
    assert env.client.post(f"/v2/issues/{issue.id}/ticket", headers=OTHER).status_code == 404
    viewer = token(env, "Viewer", ["scans:read"])
    assert env.client.post(f"/v2/issues/{issue.id}/ticket", headers=viewer).status_code == 403


def test_a_rule_files_and_groups(env: Env, rec: Recorder) -> None:
    creds(env)
    configure(env)
    r = env.client.post(
        "/v2/rules",
        headers=AUTH,
        json={
            "name": "Deps on one ticket",
            "trigger": "issue.created",
            "condition": "",
            "actions": [{"type": "group", "name": "Upgrades"}, {"type": "ticket"}],
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["summary"][2:] == [
        "THEN put in a group “Upgrades”",
        "THEN file or update its ticket",
    ]
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.LOW)])
    with env.sessions() as s:
        drain(s, DEFAULT_ORG_ID)
    assert len(rec.jira) == 1 and rec.jira["PAY-1"]["summary"] == "[Bulwark] Upgrades (2 issues)"
    assert {i.group_id for i in issues(env).values()} != {None}


def test_the_poll_reads_and_writes_stale_tickets(env: Env, rec: Recorder) -> None:
    creds(env)
    configure(env)
    scan(env, [finding(1, Severity.HIGH)])
    env.client.post(f"/v2/issues/{issues(env)['Problem 1'].id}/ticket", headers=AUTH)
    with env.sessions() as s:
        assert sync.sync_due(s, DEFAULT_ORG_ID) == 0  # read when it was filed
        for ln in s.scalars(select(ExternalIssueLinkRow)):
            ln.synced_at = datetime.now(timezone.utc) - timedelta(minutes=11)
        s.commit()
        assert sync.sync_due(s, DEFAULT_ORG_ID) == 1
        assert sync.sync_due(s, DEFAULT_ORG_ID) == 0  # synced just now
        assert sync.sync_due(s, OTHER_ORG) == 0
        assert (
            s.scalars(
                select(OutboxEvent).where(OutboxEvent.event_type == "issue.ticket_status")
            ).first()
            is None
        )  # no change of status, nothing to say
