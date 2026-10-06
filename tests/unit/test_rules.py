"""The rules engine (Week 65, plan §45): WHEN a trigger, IF a Rego condition, THEN actions -- with a
dry run, bulk confirmation, a depth limit, the AI budget on fix requests, Admin-only writes and an
audit entry for every run (threat T26)."""

from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select

from core.dispatch import dispatch, drain
from core.models import Severity
from core.persistence import repo
from core.persistence.models import (
    ApiToken,
    Asset,
    AuditEntry,
    AutomationRule,
    IssueRow,
    OutboxEvent,
    RiskAcceptance,
    RuleRun,
)
from core.rules import engine, rego
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token
from tests.unit.test_sla import finding, scan

pytestmark = pytest.mark.skipif(not shutil.which("opa"), reason="opa not available")
OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
P1 = 'input.issue.severity == "CRITICAL"'


def rule(env: Env, headers: Any = AUTH, **kw: Any) -> Any:
    body: dict[str, Any] = {
        "name": "Critical to Priya", "trigger": "issue.created", "condition": P1,
        "actions": [{"type": "assign", "to": "@priyan"}], **kw,
    }  # fmt: skip
    return env.client.post("/v2/rules", json=body, headers=headers)


def run_outbox(env: Env) -> int:
    with env.sessions() as s:
        return drain(s, DEFAULT_ORG_ID)


def issues(env: Env) -> dict[str, IssueRow]:
    with env.sessions() as s:
        return {i.title: i for i in s.scalars(select(IssueRow).where(
            IssueRow.asset_id == env.asset_id))}  # fmt: skip


def runs(env: Env, **filters: Any) -> list[dict[str, Any]]:
    r = env.client.get("/v2/rule-runs", params=filters, headers=AUTH)
    assert r.status_code == 200, r.text
    return list(r.json())


@pytest.fixture
def priya(env: Env) -> dict[str, str]:
    return token(env, "Priya N.")


# --- the condition --------------------------------------------------------------------------------


def test_conditions_compile_without_network_or_environment() -> None:
    assert rego.matches(
        P1, [{"issue": {"severity": "CRITICAL"}}, {"issue": {"severity": "LOW"}}]
    ) == {0}
    assert rego.matches("", [{}, {}]) == {0, 1}  # no condition: always
    many = 'input.issue.tags[_] == "payments"\ninput.issue.priority_band == "P1"'
    items = [{"issue": {"tags": ["x", "payments"], "priority_band": "P1"}},
             {"issue": {"tags": ["payments"], "priority_band": "P2"}}]  # fmt: skip
    assert rego.matches(many, items) == {0}
    for bad, says in (
        ('x := http.send({"method": "get", "url": "https://example.com"})', "http.send"),
        ('opa.runtime().env.HOME == "/root"', "opa.runtime"),
        ('net.lookup_ip_addr("example.com")', "net.lookup_ip_addr"),
        ("input.issue.severity ==", "rego_parse_error"),
        ("package evil", "added for you"),
        ("x" * 5000, "at most"),
    ):
        with pytest.raises(rego.ConditionError) as exc:
            rego.check(bad)
        assert says in str(exc.value), (bad, str(exc.value))
    # OPA's line numbers are the condition's own, not the wrapper's.
    with pytest.raises(rego.ConditionError) as exc:
        rego.check('input.issue.severity == "HIGH"\nundefined_fn(1)')
    assert "line 2" in str(exc.value)


# --- writing rules ----------------------------------------------------------------------------------


def test_create_validates_everything_and_audits(env: Env, priya: dict[str, str]) -> None:
    cases = [
        ({"trigger": "issue.exploded"}, "trigger"),
        ({"condition": "input.issue.severity =="}, "condition"),
        ({"actions": []}, "actions"),
        ({"actions": [{"type": "assign", "to": "@nobody"}]}, "actions.0.to"),
        ({"actions": [{"type": "set_priority", "band": "P9"}]}, "actions.0.band"),
        ({"actions": [{"type": "tag", "tags": ["no spaces allowed!"]}]}, "actions.0.tags"),
        ({"trigger": "project.quiet", "trigger_params": {"days": 0}}, "trigger_params.days"),
        ({"trigger": "scan.completed"}, "actions.0.type"),  # assign needs an issue
        ({"confirm_over": 0}, "confirm_over"),
        ({"name": "  "}, "name"),
    ]
    for kw, field in cases:
        r = rule(env, **kw)
        assert r.status_code == 422, (kw, r.text)
        assert r.json()["detail"]["field"] == field, (kw, r.json())
    r = rule(env)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["summary"] == ["WHEN an issue is found in any project",
                               f"IF {P1}", "THEN assign to @priyan"]  # fmt: skip
    assert "package bulwark.rule" in body["rego"] and P1 in body["rego"]
    assert body["version"] == 1
    upd = env.client.put(
        f"/v2/rules/{body['id']}",
        headers=AUTH,
        json={
            "name": "Critical to Priya",
            "trigger": "issue.created",
            "condition": P1,
            "actions": [{"type": "assign", "to": "priyan"}, {"type": "set_priority", "band": "p1"}],
        },
    )
    assert upd.json()["version"] == 2 and upd.json()["actions"][1] == {"type": "set_priority",
                                                                      "band": "P1"}  # fmt: skip
    off = env.client.put(f"/v2/rules/{body['id']}/enabled", json={"enabled": False}, headers=AUTH)
    assert off.json()["enabled"] is False and off.json()["version"] == 3
    assert env.client.delete(f"/v2/rules/{body['id']}", headers=AUTH).status_code == 204
    assert env.client.get(f"/v2/rules/{body['id']}", headers=AUTH).status_code == 404
    with env.sessions() as s:
        actions = [a for (a,) in s.execute(select(AuditEntry.action).where(
            AuditEntry.target == f"rule:{body['id']}").order_by(AuditEntry.seq))]  # fmt: skip
    assert actions == ["rule.created", "rule.updated", "rule.disabled", "rule.deleted"]


def test_only_admins_write_rules_and_orgs_are_apart(env: Env, priya: dict[str, str]) -> None:
    member = token(env, "Member", ["scans:read", "scans:write"])
    assert rule(env, headers=member).status_code == 403
    admin = token(env, "Admin", ["scans:read", "rules:write"])
    created = rule(env, headers=admin)
    assert created.status_code == 201
    rid = created.json()["id"]
    assert env.client.get("/v2/rules", headers=member).status_code == 200  # reading is fine
    assert env.client.post(f"/v2/rules/{rid}/test", headers=member).status_code == 403
    assert env.client.get(f"/v2/rules/{rid}", headers=OTHER).status_code == 404
    assert env.client.get("/v2/rules", headers=OTHER).json() == []
    other_project = rule(env, project_id=env.other_asset_id)
    assert (
        other_project.status_code == 422 and other_project.json()["detail"]["field"] == "asset_id"
    )


# --- firing ---------------------------------------------------------------------------------------


def test_a_rule_assigns_sets_priority_tags_and_says_why(env: Env, priya: dict[str, str]) -> None:
    r = rule(env, actions=[{"type": "assign", "to": "@priyan"},
                           {"type": "set_priority", "band": "P1"},
                           {"type": "tag", "tags": ["oncall"]}])  # fmt: skip
    assert r.status_code == 201
    scan(env, [finding(1, Severity.CRITICAL), finding(2, Severity.LOW)])
    assert run_outbox(env) > 0
    got = issues(env)
    crit, low = got["Problem 1"], got["Problem 2"]
    assert crit.assignee and crit.assignee.startswith("token:") and low.assignee is None
    assert crit.priority_override == "P1" and low.priority_override is None
    owner = env.client.get(f"/v2/issues/{crit.id}/assignee", headers=AUTH).json()
    assert owner["assignee_name"] == "Priya N." and owner["assignee_handle"] == "priyan"
    assert owner["names"][owner["priority_override_by"]] == "the rule “Critical to Priya”"
    tags = env.client.get(f"/v2/issues/{crit.id}/tags", headers=AUTH).json()
    assert tags["own"] == ["oncall"]
    [run] = runs(env)
    assert run["status"] == "applied" and run["subject_ids"] == [crit.id]
    assert run["cause_label"] == "a scan" and run["subjects"][0]["title"] == "Problem 1"
    assert {(x["action"], x["outcome"]) for x in run["results"]} == {
        ("assign", "changed"),
        ("set_priority", "changed"),
        ("tag", "changed"),
    }
    labels = [e["label"] for e in env.client.get(
        f"/assets/{env.asset_id}/issues/{crit.id}/history", headers=AUTH).json()]  # fmt: skip
    assert "Assigned by the rule “Critical to Priya”" in labels
    assert "Priority set by the rule “Critical to Priya”" in labels
    # The override is the band everywhere: the issues table filters by it.
    table = env.client.get(f"/assets/{env.asset_id}/issues", params={"priority": "P1"},
                           headers=AUTH).json()  # fmt: skip
    assert [i["title"] for i in table["items"]] == ["Problem 1"]
    with env.sessions() as s:
        audit = s.scalars(select(AuditEntry.action).where(AuditEntry.action.like("rule.run.%")))
        assert list(audit) == ["rule.run.applied"]


def test_redelivery_never_acts_twice_and_old_events_never_fire(
    env: Env, priya: dict[str, str]
) -> None:
    scan(env, [finding(1, Severity.CRITICAL)])  # before the rule exists
    assert rule(env).status_code == 201
    run_outbox(env)
    assert issues(env)["Problem 1"].assignee is None and runs(env) == []
    scan(env, [finding(1, Severity.CRITICAL), finding(3, Severity.CRITICAL)])
    with env.sessions() as s:
        pending = [e.id for e in repo.pending_outbox_events(s, DEFAULT_ORG_ID)]
        dispatch(s, DEFAULT_ORG_ID)
        # As if the worker died before marking the batch: hand it over again.
        for e in s.scalars(select(OutboxEvent).where(OutboxEvent.id.in_(pending))):
            e.dispatched_at = None
        s.commit()
        dispatch(s, DEFAULT_ORG_ID)
    assert len(runs(env)) == 1
    with env.sessions() as s:
        assigned = s.scalars(select(OutboxEvent).where(OutboxEvent.event_type == "issue.assigned"))
        assert len(list(assigned)) == 1


def test_more_than_the_threshold_waits_for_an_admin(env: Env, priya: dict[str, str]) -> None:
    assert rule(env, condition="", confirm_over=2).status_code == 201
    scan(env, [finding(i, Severity.HIGH) for i in range(1, 6)])
    run_outbox(env)
    [held] = runs(env)
    assert held["status"] == "held" and len(held["subject_ids"]) == 5
    assert all(i.assignee is None for i in issues(env).values())  # nothing applied
    member = token(env, "Member", ["scans:read", "scans:write"])
    assert env.client.post(f"/v2/rule-runs/{held['id']}/confirm", headers=member).status_code == 403
    done = env.client.post(f"/v2/rule-runs/{held['id']}/confirm", headers=AUTH).json()
    assert done["status"] == "confirmed" and done["decided_by"] == "shared-token"
    assert env.client.get("/v2/rules", headers=AUTH).json()[0]["last_fired_at"] is not None
    assert all(i.assignee for i in issues(env).values())
    assert env.client.post(f"/v2/rule-runs/{held['id']}/dismiss", headers=AUTH).status_code == 409
    with env.sessions() as s:
        assert s.scalars(select(OutboxEvent).where(OutboxEvent.event_type == "rule.held")).first()


def test_a_held_run_can_be_dismissed(env: Env, priya: dict[str, str]) -> None:
    rule(env, condition="", confirm_over=1)
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH)])
    run_outbox(env)
    [held] = runs(env, status="held")
    r = env.client.post(f"/v2/rule-runs/{held['id']}/dismiss", headers=AUTH).json()
    assert r["status"] == "dismissed"
    assert all(i.assignee is None for i in issues(env).values())


def test_chains_stop_at_the_depth_limit(env: Env, priya: dict[str, str]) -> None:
    """Four rules, each set off by the one before; the fourth is beyond the limit of three."""
    token(env, "Arjun K.")
    token(env, "Meera S.")
    assert (
        rule(env, name="A", condition="", actions=[{"type": "tag", "tags": ["a"]}]).status_code
        == 201
    )
    for name, to in (("B", "priyan"), ("C", "arjunk"), ("D", "meeras")):
        assert (
            rule(
                env,
                name=name,
                trigger="issue.assigned" if name != "B" else "issue.created",
                condition="",
                actions=[{"type": "assign", "to": to}],
            ).status_code
            == 201
        )
    # A and B fire on the scan (depth 0); B's assignment fires C (1) and D (1); each of those
    # reassigns, firing C and D again (2), then (3) -- which the limit stops.
    scan(env, [finding(1, Severity.HIGH)])
    run_outbox(env)
    statuses = [r["status"] for r in runs(env, limit=200)]
    assert "depth_limited" in statuses
    assert max(r["depth"] for r in runs(env, limit=200)) <= 3
    with env.sessions() as s:
        assert all(int((e.payload.get("rule") or {}).get("depth", 0)) <= 3
                   for e in s.scalars(select(OutboxEvent)))  # fmt: skip


def test_a_failing_action_is_reported_not_fatal(env: Env, priya: dict[str, str]) -> None:
    rule(env, condition="", actions=[{"type": "assign", "to": "@priyan"},
                                      {"type": "request_retest"}])  # fmt: skip
    with env.sessions() as s:  # Priya's token is revoked after the rule was written
        t = s.scalars(select(ApiToken).where(ApiToken.name == "Priya N.")).one()
        repo.revoke_api_token(s, t.id)
    scan(env, [finding(1, Severity.HIGH)])
    run_outbox(env)
    [run] = runs(env)
    outcomes = {(x["action"], x["outcome"]) for x in run["results"]}
    assert ("assign", "failed") in outcomes and ("request_retest", "changed") in outcomes
    assert run["status"] == "applied"
    assert issues(env)["Problem 1"].retest_status == "requested"


def test_a_rule_scoped_to_a_project_ignores_others(env: Env, priya: dict[str, str]) -> None:
    with env.sessions() as s:
        other = repo.get_or_create_asset(s, source_type="git", source_label="c/d",
                                         org_id=DEFAULT_ORG_ID)  # fmt: skip
        other_id = other.id
    assert rule(env, condition="", project_id=other_id).status_code == 201
    scan(env, [finding(1, Severity.HIGH)])
    run_outbox(env)
    assert runs(env) == []


# --- triggers the sweep fires -------------------------------------------------------------------


def test_no_scan_for_n_days_fires_once_per_quiet_stretch(env: Env, priya: dict[str, str]) -> None:
    sent: list[str] = []
    import core.rules.notify as notify_mod

    real = notify_mod.send_rule_message
    notify_mod.send_rule_message = lambda s, org, text: (sent.append(text), ["Slack"])[1]  # type: ignore[assignment]
    try:
        r = rule(env, name="Quiet", trigger="project.quiet", trigger_params={"days": 7},
                 condition="input.project.days_since_scan >= 7",
                 actions=[{"type": "notify", "message": "Is the pipeline broken?"}])  # fmt: skip
        assert r.status_code == 201, r.text
        scan(env, [finding(1, Severity.LOW)])
        now = datetime.now(timezone.utc)
        with env.sessions() as s:
            s.get(AutomationRule, r.json()["id"]).created_at = now - timedelta(days=30)  # type: ignore[union-attr]
            s.commit()
            assert engine.sweep(s, DEFAULT_ORG_ID, now + timedelta(days=3)).applied == 0
            assert engine.sweep(s, DEFAULT_ORG_ID, now + timedelta(days=8)).applied == 1
            assert engine.sweep(s, DEFAULT_ORG_ID, now + timedelta(days=9)).applied == 0  # once
        assert "a/b has had no scan for 8 days" in sent[0] and "Is the pipeline broken?" in sent[0]
        scan(env, [finding(1, Severity.LOW)])  # a scan starts the count again
        with env.sessions() as s:
            assert engine.sweep(s, DEFAULT_ORG_ID, now + timedelta(days=16)).applied == 1
    finally:
        notify_mod.send_rule_message = real  # type: ignore[assignment]


def test_a_schedule_fires_once_per_slot_on_open_issues(env: Env, priya: dict[str, str]) -> None:
    r = rule(env, name="Weekly", trigger="schedule",
             trigger_params={"every": "week", "weekday": 0, "hour": 9},
             condition='input.issue.sla.state != "breached"',
             actions=[{"type": "tag", "tags": ["weekly-review"]}])  # fmt: skip
    assert r.status_code == 201, r.text
    assert r.json()["summary"][0] == "WHEN mondays at 09:00 UTC in any project"
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH)])
    monday = datetime(2030, 1, 7, 10, 0, tzinfo=timezone.utc)
    with env.sessions() as s:
        assert engine.schedule_slot({"every": "week", "weekday": 0, "hour": 9}, monday) == datetime(
            2030, 1, 7, 9, 0, tzinfo=timezone.utc
        )
        assert engine.schedule_slot({"every": "day", "hour": 11}, monday) == datetime(
            2030, 1, 6, 11, 0, tzinfo=timezone.utc
        )
        assert engine.sweep(s, DEFAULT_ORG_ID, monday).applied == 1
        assert engine.sweep(s, DEFAULT_ORG_ID, monday + timedelta(hours=5)).applied == 0
    tags = env.client.get(f"/v2/issues/{issues(env)['Problem 1'].id}/tags", headers=AUTH).json()
    assert tags["own"] == ["weekly-review"]


def test_risk_acceptance_expiring_is_announced_once(env: Env, priya: dict[str, str]) -> None:
    from core.acceptance.service import warn_expiring

    scan(env, [finding(1, Severity.HIGH)])
    issue = issues(env)["Problem 1"]
    now = datetime.now(timezone.utc)
    with env.sessions() as s:
        ra = RiskAcceptance(org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, decision="accept",
                            justification="j", controls="c", expires_at=now + timedelta(days=5),
                            state="approved", requested_by="token:x")  # fmt: skip
        s.add(ra)
        s.flush()
        from core.persistence.models import RiskAcceptanceIssue

        s.add(RiskAcceptanceIssue(acceptance_id=ra.id, issue_id=issue.id, org_id=DEFAULT_ORG_ID))
        s.commit()
        assert warn_expiring(s, DEFAULT_ORG_ID, now=now) == 1
        assert warn_expiring(s, DEFAULT_ORG_ID, now=now) == 0
    rule(env, trigger="risk_acceptance.expiring", condition="",
         actions=[{"type": "tag", "tags": ["expiring"]}])  # fmt: skip
    with env.sessions() as s:  # the rule existed before the event (as in production order)
        s.query(AutomationRule).update({"created_at": now - timedelta(days=1)})
        s.commit()
    run_outbox(env)
    assert env.client.get(f"/v2/issues/{issue.id}/tags", headers=AUTH).json()["own"] == ["expiring"]


# --- the dry run -----------------------------------------------------------------------------------


def test_dry_run_counts_the_last_seven_days_without_acting(env: Env, priya: dict[str, str]) -> None:
    scan(env, [finding(i, Severity.CRITICAL) for i in range(1, 4)] + [finding(9, Severity.LOW)])
    draft = {"name": "Draft", "trigger": "issue.created", "condition": P1,
             "actions": [{"type": "assign", "to": "@priyan"}], "confirm_over": 2}  # fmt: skip
    r = env.client.post("/v2/rules/test", json=draft, headers=AUTH)
    assert r.status_code == 200, r.text
    d = r.json()
    assert (d["matched"], d["runs"], d["would_hold"]) == (3, 1, 1)
    assert d["sentence"] == ("This rule would have matched 3 issues in the last 7 days; 1 of its "
                             "1 run would wait for an Admin to confirm.")  # fmt: skip
    assert {x["title"] for x in d["sample"]} == {"Problem 1", "Problem 2", "Problem 3"}
    assert "as it is now" in d["note"]
    assert all(i.assignee is None for i in issues(env).values())  # nothing happened
    with env.sessions() as s:
        assert s.scalars(select(RuleRun)).first() is None
    bad = env.client.post("/v2/rules/test", json={**draft, "condition": "input.x =="}, headers=AUTH)
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "condition"
    quiet = env.client.post("/v2/rules/test", headers=AUTH, json={
        **draft, "trigger": "project.quiet", "trigger_params": {"days": 1}, "condition": "",
        "actions": [{"type": "notify"}]}).json()  # fmt: skip
    assert quiet["subject"] == "project" and quiet["matched"] == 0  # scanned just now


# --- request a verified fix: the AI budget -------------------------------------------------------


def test_fix_requests_respect_the_budget_and_the_daily_cap(
    env: Env, priya: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.fixagent import start as fix_start
    from core.llm import budget

    started: list[str] = []

    async def fake_start(s: Any, org: str, asset: Asset, issue_id: str, **_: Any) -> Any:
        started.append(issue_id)
        return fix_start.Started(run_id=f"run-{len(started)}", workflow_id="w")

    monkeypatch.setattr(fix_start, "start", fake_start)
    rule(env, condition="", actions=[{"type": "request_fix", "max_per_day": 2}])
    scan(env, [finding(i, Severity.HIGH) for i in range(1, 4)])
    run_outbox(env)
    [run] = runs(env)
    outcomes = sorted(x["outcome"] for x in run["results"])
    assert outcomes == ["changed", "changed", "skipped"] and len(started) == 2
    assert "already requested 2 fixes" in next(
        x["detail"] for x in run["results"] if x["outcome"] == "skipped"
    )
    monkeypatch.setattr(budget.BudgetConfig, "from_env",
                        staticmethod(lambda: budget.BudgetConfig(per_org_month=0)))  # fmt: skip
    rule(env, name="Fix all", condition="", actions=[{"type": "request_fix", "max_per_day": 20}])
    scan(env, [finding(i, Severity.HIGH) for i in range(4, 6)])
    run_outbox(env)
    latest = runs(env)[0]
    assert all(x["outcome"] == "skipped" and "AI budget" in x["detail"] for x in latest["results"])
    assert len(started) == 2


# --- notify ---------------------------------------------------------------------------------------


def test_notify_sends_one_escaped_message_per_run(env: Env, priya: dict[str, str],
                                                  monkeypatch: pytest.MonkeyPatch) -> None:  # fmt: skip
    from core.integrations import discord, slack
    from core.rules.notify import slack_escape

    to_slack: list[dict[str, Any]] = []
    to_discord: list[dict[str, Any]] = []
    monkeypatch.setattr(slack, "send", lambda url, payload, **_: to_slack.append(payload))
    monkeypatch.setattr(discord, "send", lambda url, payload, **_: to_discord.append(payload))
    with env.sessions() as s:
        repo.set_integration_settings(s, DEFAULT_ORG_ID, actor="t",
                                      slack_webhook_url="https://hooks.slack.com/services/x",
                                      discord_webhook_url="https://discord.com/api/webhooks/x")  # fmt: skip
    rule(env, condition="", actions=[{"type": "notify", "message": "Look now"}])
    evil = finding(1, Severity.HIGH)
    from dataclasses import replace

    evil = replace(evil, title="<!channel> @everyone <https://evil.example|click>")
    scan(env, [evil, finding(2, Severity.HIGH)])
    run_outbox(env)
    assert len(to_slack) == 1 and len(to_discord) == 1
    text = to_slack[0]["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text and "Look now" in text
    assert to_discord[0]["allowed_mentions"] == {"parse": []}
    assert slack_escape("a & <b>") == "a &amp; &lt;b&gt;"
    [run] = runs(env)
    assert run["results"][0]["outcome"] == "changed" and "Slack" in run["results"][0]["detail"]


def test_assign_and_priority_by_hand(env: Env, priya: dict[str, str]) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    issue = issues(env)["Problem 1"]
    r = env.client.put(f"/v2/issues/{issue.id}/assignee", json={"to": "@priyan"}, headers=priya)
    assert r.status_code == 200 and r.json()["assignee_name"] == "Priya N."
    nobody = env.client.put(f"/v2/issues/{issue.id}/assignee", json={"to": "@ghost"}, headers=AUTH)
    assert nobody.status_code == 422 and "Nobody" in nobody.json()["detail"]["message"]
    p = env.client.put(f"/v2/issues/{issue.id}/priority", json={"band": "p2"}, headers=AUTH)
    assert p.json()["priority_override"] == "P2"
    assert env.client.put(f"/v2/issues/{issue.id}/priority", json={"band": "P7"},
                          headers=AUTH).status_code == 422  # fmt: skip
    cleared = env.client.put(f"/v2/issues/{issue.id}/assignee", json={"to": None}, headers=AUTH)
    assert cleared.json()["assignee"] is None
    assert env.client.put(f"/v2/issues/{issue.id}/assignee", json={"to": "@priyan"},
                          headers=OTHER).status_code == 404  # fmt: skip
    viewer = token(env, "Viewer", ["scans:read"])
    assert env.client.put(f"/v2/issues/{issue.id}/priority", json={"band": "P1"},
                          headers=viewer).status_code == 403  # fmt: skip


def test_the_migration_left_old_events_dispatched_and_catalogue_lists_everything(env: Env) -> None:
    cat = env.client.get("/v2/rules/catalogue", headers=AUTH).json()
    assert {t["key"] for t in cat["triggers"]} >= {"issue.created", "project.quiet", "schedule",
                                                     "sla.breached", "risk_acceptance.expiring"}  # fmt: skip
    assert {a["key"] for a in cat["actions"]} == {"assign", "set_priority", "tag", "request_retest",
                                                   "request_fix", "notify", "group",
                                                   "ticket"}  # fmt: skip
    assert cat["limits"]["max_depth"] == 3


def test_another_org_cannot_see_or_decide_runs(env: Env, priya: dict[str, str]) -> None:
    rule(env, condition="", confirm_over=1)
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH)])
    run_outbox(env)
    [held] = runs(env)
    assert env.client.get(f"/v2/rule-runs/{held['id']}", headers=OTHER).status_code == 404
    assert env.client.post(f"/v2/rule-runs/{held['id']}/confirm", headers=OTHER).status_code == 404
    assert env.client.get("/v2/rule-runs", headers=OTHER).json() == []
    with env.sessions() as s:
        assert dispatch(s, OTHER_ORG) == 0


def test_every_template_compiles_and_saves_once_filled_in(env: Env, priya: dict[str, str]) -> None:
    gallery = env.client.get("/v2/rules/templates", headers=AUTH).json()
    assert len(gallery) >= 8 and len({t["key"] for t in gallery}) == len(gallery)
    for t in gallery:
        draft = dict(t["draft"])
        for need in t["needs"]:
            _, i, field = need.split(".")
            draft["actions"][int(i)][field] = "@priyan" if field == "to" else ["priyan"]
        r = env.client.post("/v2/rules/test", json=draft, headers=AUTH)
        assert r.status_code == 200, (t["key"], r.text)
        created = env.client.post("/v2/rules", json=draft, headers=AUTH)
        assert created.status_code == 201, (t["key"], created.text)
        assert created.json()["template"] == t["key"]


def test_a_completed_scan_says_what_it_changed(env: Env, priya: dict[str, str]) -> None:
    sent: list[str] = []
    import core.rules.notify as notify_mod

    real = notify_mod.send_rule_message
    notify_mod.send_rule_message = lambda s, org, text: (sent.append(text), ["Slack"])[1]  # type: ignore[assignment]
    try:
        rule(env, name="New things", trigger="scan.completed",
             condition="input.scan.counts.new >= 2", actions=[{"type": "notify"}])  # fmt: skip
        scan(env, [finding(1, Severity.HIGH)])
        run_outbox(env)
        assert sent == []  # one new: below the condition
        scan(env, [finding(i, Severity.HIGH) for i in (1, 2, 3)])
        run_outbox(env)
        assert len(sent) == 1 and "a scan of a/b completed: 2 new" in sent[0]
    finally:
        notify_mod.send_rule_message = real  # type: ignore[assignment]
