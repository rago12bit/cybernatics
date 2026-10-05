"""The SLA engine (Week 61, plan §44.1): per-project policies by severity, a clock from first
detection that reimport never restarts, on track / due soon / breached, a filter that agrees with
the rules, and a sweep that announces each crossing exactly once."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from core.models import Category, Evidence, Finding, Location, Scoring, Severity, Taxonomy
from core.persistence import repo
from core.persistence.models import AuditEntry, IssueRow, OutboxEvent
from core.sla import service
from core.sla.policy import STARTER, STARTER_POLICY, Policy, PolicyError, evaluate, parse_bands
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    SARIF,
    Env,
    env,  # noqa: F401  (the fixture)
)

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
ON = Policy(True, "severity", parse_bands(STARTER))


def ev(policy: Policy = ON, **over: Any) -> str:
    args: dict[str, Any] = {
        "severity": "HIGH", "state": "open", "first_seen_at": NOW - timedelta(days=1),
        "sla_started_at": None, "fixed_at": None, "triage_status": "open",
        "triage_expires_at": None, "now": NOW, **over,
    }  # fmt: skip
    return evaluate(policy, **args).state


# --- the rules ------------------------------------------------------------------------------------


def test_states_by_time_left_with_the_starter_bands() -> None:
    # High: 30 days, due soon in the last 7.
    assert ev(first_seen_at=NOW - timedelta(days=22, hours=23)) == "on_track"
    assert ev(first_seen_at=NOW - timedelta(days=23)) == "due_soon"  # exactly 7 days left
    assert ev(first_seen_at=NOW - timedelta(days=29, hours=23)) == "due_soon"
    assert ev(first_seen_at=NOW - timedelta(days=30)) == "breached"  # the deadline itself
    assert ev(severity="CRITICAL", first_seen_at=NOW - timedelta(days=6)) == "due_soon"
    assert ev(severity="INFO", first_seen_at=NOW - timedelta(days=900)) == "none"


def test_no_policy_or_a_disabled_one_means_no_sla() -> None:
    assert ev(STARTER_POLICY, first_seen_at=NOW - timedelta(days=900)) == "none"
    assert STARTER_POLICY.enabled is False


def test_a_restarted_clock_runs_from_its_restart() -> None:
    old = NOW - timedelta(days=200)
    assert ev(first_seen_at=old) == "breached"
    assert ev(first_seen_at=old, sla_started_at=NOW - timedelta(days=2)) == "on_track"


def test_triaged_away_is_exempt_until_the_decision_lapses() -> None:
    old = NOW - timedelta(days=200)
    assert ev(first_seen_at=old, triage_status="not_a_risk") == "exempt"
    later = NOW + timedelta(days=5)
    assert ev(first_seen_at=old, triage_status="accepted", triage_expires_at=later) == "exempt"
    expired = NOW - timedelta(days=1)
    assert ev(first_seen_at=old, triage_status="accepted", triage_expires_at=expired) == "breached"


def test_a_fixed_issue_met_or_missed_its_deadline() -> None:
    seen = NOW - timedelta(days=60)
    assert ev(state="fixed", first_seen_at=seen, fixed_at=seen + timedelta(days=29)) == "met"
    assert ev(state="fixed", first_seen_at=seen, fixed_at=seen + timedelta(days=31)) == "missed"
    assert ev(state="fixed", first_seen_at=seen, fixed_at=None) == "none"


@pytest.mark.parametrize(
    ("bands", "field"),
    [
        ({"HIGH": {"days": 0, "warn": 0}}, "bands.HIGH.days"),
        ({"HIGH": {"days": 10, "warn": 10}}, "bands.HIGH.warn"),
        ({"HIGH": {"days": True}}, "bands.HIGH.days"),
        ({"HIGH": {"days": "7"}}, "bands.HIGH.days"),
        ({"URGENT": {"days": 1}}, "bands"),
        ([], "bands"),
    ],
)
def test_bands_are_validated_with_the_field_named(bands: Any, field: str) -> None:
    with pytest.raises(PolicyError) as caught:
        parse_bands(bands)
    assert caught.value.field == field


def test_every_severity_is_spelled_out_and_lowercase_is_accepted() -> None:
    got = parse_bands({"high": {"days": 10, "warn": 2}})
    assert set(got) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert (got["HIGH"].days, got["HIGH"].warn, got["LOW"].days) == (10, 2, None)


# --- a project with Issues ------------------------------------------------------------------------


def finding(i: int, severity: Severity) -> Finding:
    path = f"app/m{i}.py"
    return Finding(
        id=f"sla:{i}", title=f"Problem {i}", description="d",
        location=Location(path, i + 1, i + 1, f"line {i}", Location.hash_snippet(f"line {i}")),
        taxonomy=Taxonomy(Category.SAST, cwe=("CWE-89",)),
        scoring=Scoring(native_severity={"semgrep": severity.value}, normalized_severity=severity,
                        risk_score=50, confidence=0.8),
        evidence=Evidence(reported_by=["semgrep"], rule_ids={"semgrep": [f"rule-{i}"]}),
        fingerprint=f"sla-{i}",
    )  # fmt: skip


def scan(env: Env, findings: list[Finding]) -> str:
    with env.sessions() as s:
        sc = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/a/b", source_label="a/b",
            tools=["semgrep"],
        )  # fmt: skip
        sc.asset_id = env.asset_id
        s.commit()
        sync = repo.sync_issues_for_scan(s, sc.id, findings)
        repo.add_findings(s, sc.id, findings, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        return sc.id


def age(env: Env, days_by_title: dict[str, float]) -> None:
    with env.sessions() as s:
        for issue in s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id)):
            if issue.title in days_by_title:
                issue.first_seen_at = datetime.now(timezone.utc) - timedelta(
                    days=days_by_title[issue.title]
                )
        s.commit()


def put(env: Env, enabled: bool = True, bands: Any = None, **kw: Any) -> Any:
    body = {"enabled": enabled, "bands": STARTER if bands is None else bands, **kw}
    return env.client.put(f"/v2/projects/{env.asset_id}/sla", json=body, headers=AUTH)


def issues(env: Env, **params: Any) -> list[dict[str, Any]]:
    r = env.client.get(f"/assets/{env.asset_id}/issues", params=params, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()["items"]  # type: ignore[no-any-return]


def test_the_policy_api_offers_the_starter_values_off_then_versions_changes(env: Env) -> None:
    r = env.client.get(f"/v2/projects/{env.asset_id}/sla", headers=AUTH).json()
    assert (r["enabled"], r["version"], r["bands"]["HIGH"]) == (False, 0, {"days": 30, "warn": 7})
    first = put(env).json()
    assert (first["enabled"], first["version"]) == (True, 1)
    second = put(env, bands={**STARTER, "HIGH": {"days": 14, "warn": 3}}, note="tighter").json()
    assert second["version"] == 2 and second["bands"]["HIGH"] == {"days": 14, "warn": 3}
    assert [h["version"] for h in second["history"]] == [2, 1]
    assert second["history"][0]["note"] == "tighter"
    with env.sessions() as s:
        actions = [e.action for e in s.scalars(select(AuditEntry))]
    assert actions.count("sla.policy.changed") == 2


def test_policy_errors_name_the_field_and_another_org_cannot_see_it(env: Env) -> None:
    r = put(env, bands={"HIGH": {"days": 5, "warn": 9}})
    assert r.status_code == 422 and r.json()["detail"]["field"] == "bands.HIGH.warn"
    r = put(env, bands={"INFO": {"days": None}})
    assert r.status_code == 422 and "at least one severity" in r.json()["detail"]["message"]
    other = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
    assert env.client.get(f"/v2/projects/{env.asset_id}/sla", headers=other).status_code == 404
    assert env.client.put(f"/v2/projects/{env.asset_id}/sla", json={"enabled": True,
                          "bands": STARTER}, headers=other).status_code == 404  # fmt: skip


def test_issues_carry_their_sla_and_filter_by_it(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH), finding(3, Severity.CRITICAL),
               finding(4, Severity.LOW), finding(5, Severity.INFO)])  # fmt: skip
    age(env, {"Problem 1": 31, "Problem 2": 25, "Problem 3": 1, "Problem 4": 10, "Problem 5": 999})
    assert {i["issue"]["sla"]["state"] for i in issues(env)} == {"none"}  # no policy yet
    assert issues(env, sla="breached") == []
    put(env)
    by_title = {i["title"]: i["issue"]["sla"] for i in issues(env)}
    assert {k: v["state"] for k, v in by_title.items()} == {
        "Problem 1": "breached", "Problem 2": "due_soon", "Problem 3": "on_track",
        "Problem 4": "on_track", "Problem 5": "none",
    }  # fmt: skip
    assert by_title["Problem 1"]["days"] == 30 and by_title["Problem 1"]["due_at"]
    assert [i["title"] for i in issues(env, sla="breached")] == ["Problem 1"]
    assert sorted(i["title"] for i in issues(env, sla=["due_soon", "breached"])) == [
        "Problem 1",
        "Problem 2",
    ]
    one = issues(env)[0]["issue"]["id"]
    detail = env.client.get(f"/assets/{env.asset_id}/issues/{one}", headers=AUTH).json()
    assert detail["issue"]["sla"]["state"] in ("breached", "due_soon", "on_track", "none")
    bad = env.client.get(f"/assets/{env.asset_id}/issues", params={"sla": "late"}, headers=AUTH)
    assert bad.status_code == 422


def test_the_sql_filter_agrees_with_the_rules_at_every_boundary(env: Env) -> None:
    sevs = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    ages = [0, 4.9, 5.1, 22.9, 23.1, 29.9, 30.1, 75.9, 76.1, 89.9, 90.1, 149.9, 150.1, 181]
    combos = list(itertools.product(sevs, ages))
    scan(env, [finding(i, sev) for i, (sev, _) in enumerate(combos)])
    age(env, {f"Problem {i}": a for i, (_, a) in enumerate(combos)})
    put(env)
    expected: dict[str, set[str]] = {"on_track": set(), "due_soon": set(), "breached": set()}
    for item in issues(env, limit=500):
        expected[item["issue"]["sla"]["state"]].add(item["title"])
    assert all(expected.values())
    for state, titles in expected.items():
        assert {i["title"] for i in issues(env, sla=state, limit=500)} == titles, state


def test_reimporting_does_not_restart_the_clock(env: Env) -> None:
    assert env.import_and_get(SARIF)["status"] == "applied"
    with env.sessions() as s:
        rows = list(s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id)))
        for r in rows:
            r.first_seen_at = datetime.now(timezone.utc) - timedelta(days=400)
        s.commit()
        before = {r.id: r.first_seen_at for r in rows}
    env.import_and_get(SARIF + b"\n")  # the same report again, a new upload
    with env.sessions() as s:
        after = {r.id: r.first_seen_at for r in s.scalars(select(IssueRow))}
        policy = Policy(True, "severity", parse_bands(STARTER))
        states = {service.status_of(policy, r).state for r in s.scalars(select(IssueRow))}
    assert after == before
    assert states <= {"breached", "none"} and "breached" in states


def test_a_lower_severity_moves_the_deadline(env: Env) -> None:
    scan(env, [finding(1, Severity.CRITICAL)])
    age(env, {"Problem 1": 10})
    put(env)
    assert issues(env)[0]["issue"]["sla"]["state"] == "breached"
    scan(env, [finding(1, Severity.MEDIUM)])  # the scanner now rates it Medium (90 days)
    assert issues(env)[0]["issue"]["sla"]["state"] == "on_track"


# --- the sweep ------------------------------------------------------------------------------------


class Sent:
    def __init__(self) -> None:
        self.calls: list[tuple[str, list[service.Crossing]]] = []

    def __call__(self, s: Any, org_id: str, project: str, crossings: list[Any]) -> None:
        self.calls.append((project, crossings))


def test_each_crossing_is_announced_once(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH), finding(3, Severity.HIGH)])
    age(env, {"Problem 1": 31, "Problem 2": 25, "Problem 3": 1})
    put(env)
    sent = Sent()
    with env.sessions() as s:
        first = service.sweep(s, DEFAULT_ORG_ID, notify=sent)
        again = service.sweep(s, DEFAULT_ORG_ID, notify=sent)
        events = [
            (e.event_type, e.payload["title"])
            for e in s.scalars(select(OutboxEvent).where(OutboxEvent.event_type.like("sla.%")))
        ]
    assert first.announced == 2 and again.announced == 0
    assert len(sent.calls) == 1
    assert sorted((c.title, c.state) for c in sent.calls[0][1]) == [
        ("Problem 1", "breached"),
        ("Problem 2", "due_soon"),
    ]
    assert sorted(events) == [("sla.breached", "Problem 1"), ("sla.due_soon", "Problem 2")]

    # Due soon, then breached: a second, different announcement.
    age(env, {"Problem 2": 31})
    with env.sessions() as s:
        third = service.sweep(s, DEFAULT_ORG_ID, notify=sent)
    assert [(c.title, c.state) for c in third.crossings[env.asset_id]] == [
        ("Problem 2", "breached")
    ]


def test_leaving_the_state_clears_it_so_a_later_crossing_is_announced_again(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    age(env, {"Problem 1": 31})
    put(env)
    sent = Sent()
    with env.sessions() as s:
        assert service.sweep(s, DEFAULT_ORG_ID, notify=sent).announced == 1
    scan(env, [])  # fixed
    with env.sessions() as s:
        cleared = service.sweep(s, DEFAULT_ORG_ID, notify=sent)
        assert cleared.cleared == 1 and cleared.announced == 0
    scan(env, [finding(1, Severity.HIGH)])  # reintroduced: same Issue, same first detection
    with env.sessions() as s:
        assert service.sweep(s, DEFAULT_ORG_ID, notify=sent).announced == 1


def test_a_policy_change_that_puts_issues_on_track_clears_them(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    age(env, {"Problem 1": 31})
    put(env)
    with env.sessions() as s:
        assert service.sweep(s, DEFAULT_ORG_ID, notify=Sent()).announced == 1
    put(env, bands={**STARTER, "HIGH": {"days": 365, "warn": 30}})
    with env.sessions() as s:
        assert service.sweep(s, DEFAULT_ORG_ID, notify=Sent()).cleared == 1
        assert s.scalars(select(IssueRow)).one().sla_notified is None


def test_a_failing_notification_does_not_stop_the_sweep(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    age(env, {"Problem 1": 31})
    put(env)

    def broken(*_: Any) -> None:
        raise RuntimeError("slack is down")

    with env.sessions() as s:
        assert service.sweep(s, DEFAULT_ORG_ID, notify=broken).announced == 1
        assert s.scalars(select(IssueRow)).one().sla_notified == "breached"


def test_the_sweep_stays_in_its_organization(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    age(env, {"Problem 1": 31})
    put(env)
    with env.sessions() as s:
        assert service.sweep(s, OTHER_ORG, notify=Sent()).announced == 0


def test_the_message_names_the_project_and_the_most_urgent() -> None:
    crossings = [
        service.Crossing("a", "SQL injection", "HIGH", "breached", NOW - timedelta(days=3)),
        service.Crossing("b", "Weak hash", "MEDIUM", "due_soon", NOW + timedelta(days=5)),
        service.Crossing("c", "XSS", "CRITICAL", "due_soon", NOW + timedelta(hours=3)),
    ]
    text = service.message("payments-api", crossings, NOW)
    assert text.splitlines()[0] == "⏰ Bulwark SLA for *payments-api*: 1 breached, 2 due soon."
    assert "• High: SQL injection -- overdue by 3 days" in text
    assert "• Critical: XSS -- due today" in text and "due in 5 days" in text


def test_notifications_go_to_each_configured_channel(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.integrations import discord, slack

    got: list[tuple[str, Any]] = []
    monkeypatch.setattr(slack, "send", lambda url, payload: got.append(("slack", payload)))
    monkeypatch.setattr(discord, "send", lambda url, payload: got.append(("discord", payload)))
    with env.sessions() as s:
        repo.set_integration_settings(
            s, DEFAULT_ORG_ID, actor="t", slack_webhook_url="https://hooks.slack.com/services/x",
            discord_webhook_url="https://discord.com/api/webhooks/x",
        )  # fmt: skip
        c = [service.Crossing("a", "SQL injection", "HIGH", "breached", NOW)]
        service.notify_integrations(s, DEFAULT_ORG_ID, "payments-api", c)
    assert [k for k, _ in got] == ["slack", "discord"]
    assert got[0][1]["text"].startswith("⏰ Bulwark SLA for *payments-api*")
    assert got[1][1]["content"].startswith("⏰ Bulwark SLA for **payments-api**")
