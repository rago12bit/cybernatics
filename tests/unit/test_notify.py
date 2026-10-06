"""Notifications (Week 66, plan §49): watchers, the inbox, email now or in the daily digest,
preferences per kind and channel, the team channels (with Microsoft Teams) choosing instant,
digest or off."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from core.dispatch import drain
from core.models import Severity
from core.notify import email as mail
from core.notify import service as notify
from core.persistence import repo
from core.persistence.models import IssueRow, Notification, OutboxEvent
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token
from tests.unit.test_sla import age, finding, scan
from tests.unit.test_sla import put as put_sla

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
SMTP = mail.SmtpConfig(host="mail.test", port=1025, sender="bulwark@acme.example", tls="none")


@pytest.fixture
def mails(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, str]]:
    sent: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        mail, "send", lambda cfg, to, subject, body: sent.append((to, subject, body))
    )
    monkeypatch.setattr(mail.SmtpConfig, "from_env", staticmethod(lambda: SMTP))
    return sent


@pytest.fixture
def crew(env: Env) -> dict[str, Any]:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.LOW)])
    with env.sessions() as s:
        ids = {i.title: i.id for i in s.scalars(select(IssueRow))}
    return {
        "priya": token(env, "Priya N."),
        "arjun": token(env, "Arjun K."),
        "admin": token(env, "Meera S.", ["scans:read", "scans:write", "rules:write"]),
        "issue": ids["Problem 1"],
    }


def dispatch(env: Env) -> None:
    with env.sessions() as s:
        drain(s, DEFAULT_ORG_ID)


def inbox(env: Env, who: Any) -> dict[str, Any]:
    r = env.client.get("/v2/notifications", headers=who)
    assert r.status_code == 200, r.text
    return dict(r.json())


def prefs(env: Env, who: Any, **body: Any) -> Any:
    return env.client.put("/v2/notification-prefs", json=body, headers=who)


def test_mentions_assignments_and_notes_reach_the_right_people(
    env: Env, crew: dict[str, Any], mails: list[Any]
) -> None:
    i = crew["issue"]
    env.client.post(
        f"/v2/issues/{i}/notes", json={"body": "@arjunk can you look?"}, headers=crew["priya"]
    )
    env.client.put(f"/v2/issues/{i}/assignee", json={"to": "@priyan"}, headers=crew["arjun"])
    env.client.put(f"/v2/issues/{i}/assignee", json={"to": "@arjunk"}, headers=crew["arjun"])
    dispatch(env)
    arjun = inbox(env, crew["arjun"])
    titles = [n["title"] for n in arjun["notifications"]]
    assert titles == ["Priya N. mentioned you on “Problem 1”"]  # not his own reassignment
    assert arjun["unread"] == 1 and arjun["notifications"][0]["body"] == "@arjunk can you look?"
    priya = inbox(env, crew["priya"])
    assert [n["title"] for n in priya["notifications"]] == ["Arjun K. assigned “Problem 1” to you"]
    # Taking part makes you a watcher: Priya wrote a note and was assigned; Arjun was mentioned.
    w = env.client.get(f"/v2/issues/{i}/watchers", headers=crew["arjun"]).json()
    assert {x["reason"] for x in w["watchers"]} == {"note", "mentioned"} and w["watching"]
    # A later note reaches the watchers, but not its author or the person it mentions.
    env.client.post(f"/v2/issues/{i}/notes", json={"body": "Fixed in #412"}, headers=crew["arjun"])
    dispatch(env)
    assert (
        inbox(env, crew["priya"])["notifications"][0]["title"]
        == "Arjun K. wrote a note on “Problem 1”"
    )
    assert len(inbox(env, crew["arjun"])["notifications"]) == 1
    # Read one, then all.
    nid = arjun["notifications"][0]["id"]
    r = env.client.post("/v2/notifications/read", json={"ids": [nid]}, headers=crew["arjun"])
    assert r.json() == {"marked": 1, "unread": 0}
    assert (
        env.client.post("/v2/notifications/read", json={}, headers=crew["priya"]).json()["unread"]
        == 0
    )
    # Emails default to the daily digest, so nothing was sent yet.
    assert mails == []
    with env.sessions() as s:
        assert s.scalars(select(Notification.email_state)).all() == [None, None, None]  # no address


def test_redelivery_never_notifies_twice(env: Env, crew: dict[str, Any]) -> None:
    env.client.post(
        f"/v2/issues/{crew['issue']}/notes", json={"body": "@arjunk"}, headers=crew["priya"]
    )
    with env.sessions() as s:
        events = repo.pending_outbox_events(s, DEFAULT_ORG_ID)
        from core.rules.engine import Event

        batch = [Event.of(e) for e in events]
        notify.on_events(s, DEFAULT_ORG_ID, batch)
        notify.on_events(s, DEFAULT_ORG_ID, batch)
    assert len(inbox(env, crew["arjun"])["notifications"]) == 1


def test_preferences_email_now_and_the_daily_digest(
    env: Env, crew: dict[str, Any], mails: list[Any]
) -> None:
    bad = prefs(env, crew["arjun"], email="not an address")
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "email"
    bad = prefs(env, crew["arjun"], modes={"mention": {"email": "hourly"}})
    assert bad.json()["detail"]["field"] == "modes.mention.email"
    assert prefs(env, AUTH, email="x@acme.example").status_code == 409  # the shared token is nobody
    ok = prefs(
        env,
        crew["arjun"],
        email="arjun@acme.example",
        digest_hour=9,
        modes={"mention": {"email": "instant"}, "note": {"in_app": "off", "email": "off"}},
    )
    assert ok.status_code == 200, ok.text
    view = {k["key"]: k["modes"] for k in ok.json()["kinds"]}
    assert view["mention"] == {"in_app": "instant", "email": "instant"}
    assert view["assigned"] == {"in_app": "instant", "email": "digest"}  # the default
    assert ok.json()["email_available"] is True
    i = crew["issue"]
    env.client.post(f"/v2/issues/{i}/notes", json={"body": "@arjunk look"}, headers=crew["priya"])
    env.client.post(f"/v2/issues/{i}/notes", json={"body": "and this"}, headers=crew["priya"])
    env.client.put(f"/v2/issues/{i}/assignee", json={"to": "@arjunk"}, headers=crew["priya"])
    dispatch(env)
    # The mention went at once; the note was turned off; the assignment waits for the digest.
    assert [(to, subj) for to, subj, _ in mails] == [
        ("arjun@acme.example", "[Bulwark] Priya N. mentioned you on “Problem 1”")
    ]
    assert [n["title"] for n in inbox(env, crew["arjun"])["notifications"]] == [
        "Priya N. assigned “Problem 1” to you",
        "Priya N. mentioned you on “Problem 1”",
    ]
    today9 = datetime.now(timezone.utc).replace(hour=9, minute=5, second=0, microsecond=0)
    with env.sessions() as s:
        r = notify.run_digests(s, DEFAULT_ORG_ID, now=today9, smtp=SMTP)
        assert r.emails == 1
        assert (
            notify.run_digests(s, DEFAULT_ORG_ID, now=today9 + timedelta(hours=3), smtp=SMTP).emails
            == 0
        )  # once a day
    to, subject, body = mails[-1]
    assert subject == "[Bulwark] Your daily digest: 1 update"
    assert "An issue is assigned to you (1):" in body and "Priya N. assigned" in body


def test_email_headers_cannot_be_injected_and_titles_stay_one_line(
    env: Env, crew: dict[str, Any]
) -> None:
    msg = mail.build(SMTP, "a@acme.example", "Problem\r\nBcc: attacker@evil.example", "body")
    assert msg["Bcc"] is None and msg["Subject"] == "Problem Bcc: attacker@evil.example"
    assert msg.get_content_type() == "text/plain"
    with env.sessions() as s:
        s.get(IssueRow, crew["issue"]).title = "SQL injection\r\nBcc: attacker@evil.example"  # type: ignore[union-attr]
        s.commit()
    env.client.put(
        f"/v2/issues/{crew['issue']}/assignee", json={"to": "@arjunk"}, headers=crew["priya"]
    )
    dispatch(env)
    [n] = inbox(env, crew["arjun"])["notifications"]
    assert n["title"] == "Priya N. assigned “SQL injection Bcc: attacker@evil.example” to you"


def test_no_mail_server_means_skipped_not_stuck(
    env: Env, crew: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(mail.SmtpConfig, "from_env", staticmethod(lambda: None))
    prefs(env, crew["arjun"], email="arjun@acme.example")
    env.client.post(
        f"/v2/issues/{crew['issue']}/notes", json={"body": "@arjunk"}, headers=crew["priya"]
    )
    dispatch(env)
    with env.sessions() as s:
        r = notify.run_digests(
            s, DEFAULT_ORG_ID, now=datetime.now(timezone.utc) + timedelta(days=1), smtp=None
        )
        assert r.skipped == 1
        assert s.scalars(select(Notification.email_state)).all() == ["skipped"]


def test_sla_retest_held_rules_and_acceptances(env: Env, crew: dict[str, Any]) -> None:
    i = crew["issue"]
    env.client.put(f"/v2/issues/{i}/watch", headers=crew["arjun"])
    env.client.put(f"/v2/issues/{i}/assignee", json={"to": "@priyan"}, headers=crew["arjun"])
    env.client.post(f"/v2/issues/{i}/retest", json={"action": "request"}, headers=crew["priya"])
    # An SLA breach reaches the assignee and the watchers.
    assert put_sla(env).status_code == 200
    age(env, {"Problem 1": 40})  # HIGH is 30 days in the starter policy
    from core.sla.service import sweep

    with env.sessions() as s:
        sweep(s, DEFAULT_ORG_ID, notify=lambda *a: None)
    # A held rule run reaches whoever can confirm it.
    env.client.post(
        "/v2/rules",
        headers=crew["admin"],
        json={
            "name": "Tag all",
            "trigger": "issue.created",
            "condition": "",
            "confirm_over": 1,
            "actions": [{"type": "tag", "tags": ["x"]}],
        },
    )
    scan(env, [finding(i, Severity.LOW) for i in (5, 6, 7)])
    dispatch(env)
    dispatch(env)
    arjun = [n["title"] for n in inbox(env, crew["arjun"])["notifications"]]
    assert "“Problem 1” marked ready for retest (Priya N.)" in arjun
    assert "“Problem 1” breached its SLA" in arjun
    assert "“Problem 1” breached its SLA" in [
        n["title"] for n in inbox(env, crew["priya"])["notifications"]
    ]
    meera = [n["title"] for n in inbox(env, crew["admin"])["notifications"]]
    assert meera == ["The rule “Tag all” waits for confirmation: 3 issues"]
    assert inbox(env, crew["admin"])["notifications"][0]["link"] == "/app/automation"


def test_team_channels_choose_instant_digest_or_off(
    env: Env, crew: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.integrations import discord, slack, teams

    out: list[tuple[str, Any]] = []
    monkeypatch.setattr(slack, "send", lambda url, p, **_: out.append(("slack", p)))
    monkeypatch.setattr(discord, "send", lambda url, p, **_: out.append(("discord", p)))
    monkeypatch.setattr(teams, "send", lambda url, p, **_: out.append(("teams", p)))
    with env.sessions() as s:
        repo.set_integration_settings(
            s,
            DEFAULT_ORG_ID,
            actor="t",
            slack_webhook_url="https://hooks.slack.com/services/x",
            teams_webhook_url="https://acme.webhook.office.com/x",
        )
    from core.integrations.dispatch import notify_scan_result
    from core.issues import SyncResult

    def scan_note() -> None:
        with env.sessions() as s:
            notify_scan_result(
                s,
                DEFAULT_ORG_ID,
                "a/b",
                "scan-1",
                SyncResult(
                    updates=[], new_count=2, reintroduced_count=0, fixed_count=0, fixed_issue_ids=[]
                ),
                {},
            )

    scan_note()
    assert [k for k, _ in out] == ["teams", "slack"]  # instant, the default, now with Teams
    card = out[0][1]["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and "2 new" in card["body"][-1]["text"]
    out.clear()
    member = token(env, "Viewer", ["scans:read"])
    body = {"modes": {"scan": {"team": "digest"}, "sla": {"team": "off"}}, "digest_hour": 7}
    assert (
        env.client.put("/v2/notification-prefs/team", json=body, headers=member).status_code == 403
    )
    r = env.client.put("/v2/notification-prefs/team", json=body, headers=AUTH)
    assert r.status_code == 200, r.text
    scan_note()
    scan_note()
    assert out == []  # held for the digest
    with env.sessions() as s:
        r2 = notify.run_digests(
            s, DEFAULT_ORG_ID, now=datetime.now(timezone.utc).replace(hour=7, minute=30)
        )
        assert r2.team_messages == 1
    assert [k for k, _ in out] == ["teams", "slack"]
    text = out[1][1]["text"]
    assert text.startswith("Bulwark daily digest") and "A scan or import completes (2):" in text
    with env.sessions() as s:
        assert (
            notify.run_digests(
                s, DEFAULT_ORG_ID, now=datetime.now(timezone.utc).replace(hour=8)
            ).team_messages
            == 0
        )


def test_teams_cards_escape_markdown() -> None:
    from core.integrations.teams import card, escape

    assert (
        escape("[click](https://evil.example) **x**")
        == "\\[click\\]\\(https://evil.example\\) \\*\\*x\\*\\*"
    )
    body = card("t [x](y)", "Title_")["attachments"][0]["content"]["body"]
    assert body[0]["text"] == "Title\\_" and body[1]["text"] == "t \\[x\\]\\(y\\)"


def test_inboxes_are_personal_and_per_org(env: Env, crew: dict[str, Any]) -> None:
    env.client.post(
        f"/v2/issues/{crew['issue']}/notes", json={"body": "@arjunk"}, headers=crew["priya"]
    )
    dispatch(env)
    assert inbox(env, crew["priya"])["notifications"] == []
    shared = inbox(env, AUTH)
    assert shared["notifications"] == [] and shared["person"] is False
    other = token(env, "Arjun K.", org=OTHER_ORG)
    assert inbox(env, other)["notifications"] == []
    assert env.client.put(f"/v2/issues/{crew['issue']}/watch", headers=other).status_code == 404
    nid = inbox(env, crew["arjun"])["notifications"][0]["id"]
    assert (
        env.client.post(
            "/v2/notifications/read", json={"ids": [nid]}, headers=crew["priya"]
        ).json()["marked"]
        == 0
    )
    with env.sessions() as s:
        assert s.scalars(
            select(OutboxEvent).where(OutboxEvent.event_type == "issue.note_added")
        ).first()
