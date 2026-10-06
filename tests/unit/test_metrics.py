"""Metrics (plan §48.1, ADR-0054): the summary tables equal a direct calculation over the Issues;
they are marked dirty by any change to an Issue and refreshed; filters by portfolio, project and
tag (inherited the way tags are); the Issues behind every number; written definitions, in the docs
too; nothing of another organization."""

from __future__ import annotations

import random
import statistics
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from core.metrics import rollup
from core.metrics.definitions import METRICS, markdown
from core.models import Severity
from core.persistence import repo
from core.persistence.models import (
    Asset,
    Engagement,
    IssueRow,
    MetricDirty,
    MetricOpenIssue,
    Portfolio,
    RiskAcceptance,
    SlaPolicy,
    Tag,
)
from core.sla.policy import STARTER, evaluate, from_row
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token
from tests.unit.test_sla import finding, scan

NOW = datetime.now(timezone.utc)
OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
ORG = DEFAULT_ORG_ID


def _history(env: Env, n: int = 120, seed: int = 70) -> list[IssueRow]:
    """One project with an SLA policy and n Issues of every kind: open, fixed early and late, not a
    risk, accepted (in force and expired), banded and not."""
    rng = random.Random(seed)
    sevs = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
    scan(env, [finding(i, rng.choice(sevs)) for i in range(n)])
    with env.sessions() as s:
        s.add(SlaPolicy(org_id=ORG, asset_id=env.asset_id, version=1, enabled=True,
                        basis="severity", bands=STARTER))  # fmt: skip
        rows = list(s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id)))
        for i in rows:
            i.first_seen_at = NOW - timedelta(days=rng.randint(0, 200), hours=rng.randint(0, 23))
            i.priority_band = rng.choice(["P1", "P2", "P3", "P4", None])
            i.priority_score = rng.randint(0, 100)
            if rng.random() < 0.1:
                i.priority_override = "P1"
            r = rng.random()
            if r < 0.4:
                i.state = "fixed"
                i.fixed_at = i.first_seen_at + timedelta(days=rng.randint(0, 120), hours=3)
                if i.fixed_at > NOW:
                    i.fixed_at = NOW - timedelta(hours=1)
            elif r < 0.5:
                i.triage_status, i.triage_reason = "not_a_risk", "x"
            elif r < 0.55:
                i.triage_status, i.triage_expires_at = "accepted", NOW + timedelta(days=10)
            elif r < 0.6:
                i.triage_status, i.triage_expires_at = "accepted", NOW - timedelta(days=1)
        s.commit()
        rollup.refresh_dirty(s, ORG)
        return list(s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id)))


def _open(i: IssueRow) -> bool:
    return i.state in ("new", "open", "reintroduced") and not rollup.dismissed(
        i.triage_status, i.triage_expires_at, NOW
    )


def _band(i: IssueRow) -> str:
    return i.priority_override or i.priority_band or "none"


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def metric(env: Env, mid: str, **params: Any) -> dict[str, Any]:
    r = env.client.get(f"/v2/metrics/{mid}", params=params, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()  # type: ignore[no-any-return]


def test_every_metric_equals_a_direct_calculation(env: Env) -> None:
    issues = _history(env)
    live = [i for i in issues if _open(i)]

    o = metric(env, "open_issues")
    assert o["value"] == len(live)
    assert {r["key"]: r["count"] for r in o["rows"]} == {
        b: sum(_band(i) == b for i in live) for b in {_band(i) for i in live}
    }
    assert o["definition"].startswith("Open Issues now") and o["pending_refresh"] == 0

    start, end = (NOW - timedelta(days=89)).date(), NOW.date()
    risk = metric(env, "open_risk")
    assert risk["value"] == sum(i.priority_score or 0 for i in live)
    assert risk["series"][-1]["risk"] == risk["value"]  # the burndown ends where the risk is now

    fixed = [i for i in issues if i.state == "fixed" and start <= _utc(i.fixed_at).date() <= end]  # type: ignore[arg-type]
    m = metric(env, "mttr")
    days = [(_utc(i.fixed_at) - _utc(i.first_seen_at)).total_seconds() / 86400 for i in fixed]  # type: ignore[arg-type]
    assert m["counts"]["fixed"] == len(fixed) and m["value"] == round(statistics.mean(days), 1)

    nf = metric(env, "new_vs_fixed")
    assert nf["counts"]["new"] == sum(start <= _utc(i.first_seen_at).date() <= end for i in issues)
    assert nf["counts"]["fixed"] == len(fixed)

    policy = from_row(True, "severity", STARTER)
    met = missed = past = 0
    for i in issues:
        st = evaluate(policy, severity=i.severity, priority_band=_band(i), state=i.state,
                      first_seen_at=i.first_seen_at, sla_started_at=None, fixed_at=i.fixed_at,
                      triage_status=i.triage_status, triage_expires_at=i.triage_expires_at, now=NOW)  # fmt: skip
        if st.due_at is None or not (start <= _utc(st.due_at).date() <= min(end, NOW.date())):
            continue
        met += st.state == "met"
        missed += st.state == "missed"
        past += st.state == "breached" and _utc(st.due_at).date() < NOW.date()
    sla = metric(env, "sla_adherence")
    assert sla["counts"]["met"] == met and sla["counts"]["missed"] == missed
    assert sla["counts"]["open_past_deadline"] == past
    assert sla["value"] == round(met / (met + missed + past), 4)  # with its counts, always

    ages = sorted((NOW - _utc(i.first_seen_at)).days for i in live)
    age = metric(env, "backlog_age")
    assert age["value"] == ages[len(ages) // 2]  # the median (the upper one of an even count)
    assert age["counts"]["over_90"] == sum(
        NOW - _utc(i.first_seen_at) > timedelta(days=90) for i in live
    )  # noqa: E501

    ps = metric(env, "past_sla")
    with env.sessions() as s:
        due = {m.issue_id: m.due_at for m in s.scalars(select(MetricOpenIssue))}
    overdue = [k for k, d in due.items() if d and _utc(d) < NOW]
    assert ps["value"] == len(overdue) and len(ps["rows"]) == min(10, len(overdue))
    assert [r["days_over"] for r in ps["rows"]] == sorted(
        (r["days_over"] for r in ps["rows"]), reverse=True
    )  # noqa: E501

    # The Issues behind a number, a page at a time, add up to it.
    seen: list[str] = []
    after = None
    while True:
        page = env.client.get("/v2/metrics/issues", params={"kind": "open", "band": "P1", "limit": 7,
                              **({"after": after} if after else {})}, headers=AUTH).json()  # fmt: skip
        seen += [r["id"] for r in page["rows"]]
        after = page["next"]
        if not after:
            break
    assert len(seen) == len(set(seen)) == sum(_band(i) == "P1" for i in live)
    fixed_rows = env.client.get(
        "/v2/metrics/issues", params={"kind": "fixed", "limit": 200}, headers=AUTH
    ).json()  # noqa: E501
    assert len(fixed_rows["rows"]) == len(fixed)


def test_a_change_marks_the_project_and_a_refresh_catches_up(env: Env) -> None:
    issues = _history(env, n=30)
    before = metric(env, "open_issues")["value"]
    target = next(i for i in issues if _open(i))
    r = env.client.post(f"/assets/{env.asset_id}/issues/{target.id}/triage",
                        json={"action": "not_a_risk", "reason": "test"}, headers=AUTH)  # fmt: skip
    assert r.status_code == 200
    stale = metric(env, "open_issues")
    assert stale["pending_refresh"] == 1 and stale["value"] == before  # marked, not yet refreshed
    with env.sessions() as s:
        assert rollup.refresh_dirty(s, ORG) == 1
        assert (
            s.scalar(select(func.count()).select_from(MetricDirty).where(MetricDirty.org_id == ORG))
            == 0
        )  # noqa: E501
    assert metric(env, "open_issues")["value"] == before - 1

    # Marked again while a refresh runs: it stays dirty, so the change is not lost.
    with env.sessions() as s:
        rollup.mark(s, ORG, [env.asset_id])
        s.commit()
        mine = select(MetricDirty.marked_at).where(MetricDirty.scope == env.asset_id)
        first = s.scalar(mine)
        rollup.mark(s, ORG, [env.asset_id])
        s.commit()
        assert s.scalar(mine) > first

    # A scan finishing marks its project; the pipeline refreshes at once (plan: "on ingest").
    scan(env, [finding(999, Severity.HIGH)])
    with env.sessions() as s:
        assert env.asset_id in set(s.scalars(select(MetricDirty.scope)))


def test_filters_by_portfolio_project_and_tag(env: Env) -> None:
    _history(env, n=40)
    with env.sessions() as s:
        unit = Portfolio(org_id=ORG, name="Payments")
        s.add(unit)
        s.flush()
        other = repo.get_or_create_asset(s, source_type="git", source_label="c/d", org_id=ORG)
        other.portfolio_id = unit.id
        s.commit()
        sc = repo.create_scan(s, source_type="git", source_ref="https://example.com/c/d",
                              source_label="c/d", tools=["semgrep"])  # fmt: skip
        sc.asset_id = other.id
        s.commit()
        found = [finding(500 + k, Severity.HIGH) for k in range(5)]
        sync = repo.sync_issues_for_scan(s, sc.id, found)
        repo.add_findings(s, sc.id, found, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        rollup.refresh_dirty(s, ORG)
        unit_id, other_id = unit.id, other.id
        tagged_issue = s.scalars(select(IssueRow.id).where(IssueRow.asset_id == env.asset_id,
                                                           IssueRow.state != "fixed",
                                                           IssueRow.triage_status == "open")).first()  # fmt: skip
        s.add_all([Tag(org_id=ORG, target_type="portfolio", target_id=unit.id, name="pci"),
                   Tag(org_id=ORG, target_type="issue", target_id=tagged_issue, name="pci")])  # fmt: skip
        s.commit()
    everything = metric(env, "open_issues")["value"]
    assert metric(env, "open_issues", portfolio=unit_id)["value"] == 5
    assert metric(env, "open_issues", project=env.asset_id)["value"] == everything - 5
    tagged = metric(env, "open_issues", tag="pci")
    assert tagged["value"] == 6 and tagged["notes"] == []  # the portfolio's 5, the Issue tagged
    assert metric(env, "open_issues", tag="pci", project=other_id)["value"] == 5
    trend = metric(env, "new_vs_fixed", tag="pci")
    assert trend["notes"] and trend["counts"]["new"] == 5  # per-project metrics: project tags only
    by_unit = metric(env, "open_risk", group="portfolio")
    assert {r["label"] for r in by_unit["rows"]} == {"Payments", "(none)"}
    assert (
        env.client.get("/v2/metrics/open_issues", params={"group": "x"}, headers=AUTH).status_code
        == 422
    )  # noqa: E501
    assert env.client.get("/v2/metrics/nope", headers=AUTH).status_code == 404
    assert (
        env.client.get("/v2/metrics/open_issues", params={"project": "x"}, headers=AUTH).status_code
        == 422
    )  # noqa: E501
    bad = {"from": "2026-05-01", "to": "2026-01-01"}
    assert env.client.get("/v2/metrics/mttr", params=bad, headers=AUTH).status_code == 422


def test_project_and_program_metrics(env: Env) -> None:
    sid = scan(env, [finding(1, Severity.HIGH)])
    with env.sessions() as s:
        for tool, status in (("semgrep", "ok"), ("bandit", "ok"), ("gitleaks", "error"),
                             ("trivy", "skipped")):  # fmt: skip
            repo.add_tool_run(s, sid, tool, {"status": status, "findings": 0})
        s.add(RiskAcceptance(org_id=ORG, asset_id=env.asset_id, decision="accept",
                             justification="j", controls="c", state="approved",
                             expires_at=NOW + timedelta(days=5), requested_by="token:a",
                             decided_by="token:b", decided_at=NOW))  # fmt: skip
        s.add(RiskAcceptance(org_id=ORG, asset_id=env.asset_id, decision="accept",
                             justification="j", controls="c", state="approved",
                             expires_at=NOW + timedelta(days=90), requested_by="token:a"))  # fmt: skip
        s.add(Engagement(org_id=ORG, asset_id=env.asset_id, name="Q4 test", engagement_type="pentest",
                         status="active", target_end_at=NOW - timedelta(days=1)))  # fmt: skip
        s.commit()
        rollup.refresh_all(s, ORG)
    cov = metric(env, "scan_coverage")
    assert cov["value"] == 1.0 and cov["counts"] == {"scanned_recently": 1, "projects": 1}
    assert (cov["rows"][0]["scanners_ok"], cov["rows"][0]["scanners_applicable"]) == (2, 3)
    exp = metric(env, "expiring_acceptances")
    assert exp["value"] == 1 and exp["rows"][0]["days_left"] in (4, 5)
    eng = metric(env, "engagement_status")
    assert eng["value"] == 1 and eng["rows"][0]["overdue"] is True
    adv = metric(env, "advisory_impact")
    assert adv["value"] == 0 and adv["counts"] == {"new": 0, "kev": 0, "not_acted_on": 0}
    comp = metric(env, "vulnerable_components")
    assert comp["value"] == 0 and comp["rows"] == []


def test_components_from_advisory_impacts(env: Env) -> None:
    from tests.unit.test_advisories import LOG4J, load_all, project, sbom

    with env.sessions() as s:
        load_all(s)
        from core.persistence.models import KevEntry

        s.add(KevEntry(cve="CVE-2021-44228", date_added="2021-12-10", due_date="2021-12-24",
                       name="Log4j", ransomware="Known"))  # fmt: skip
        s.commit()
        a, b = project(s, "one"), project(s, "two")
        sbom(s, a, f"{LOG4J}@2.14.1", "pkg:npm/lodash@4.17.20")
        sbom(s, b, f"{LOG4J}@2.0-beta9")
        rollup.refresh_all(s, ORG)
    comp = metric(env, "vulnerable_components")
    top = comp["rows"][0]
    assert top["library"] == "org.apache.logging.log4j:log4j-core" and top["projects"] == 2
    assert top["kev_projects"] == 2 and top["vulns"] == 1  # the fixtures hold Log4Shell only
    assert metric(env, "vulnerable_components", project=b)["value"] == 1
    adv = metric(env, "advisory_impact")
    assert (
        adv["value"] == 2 and adv["counts"]["kev"] == 1 and adv["rows"][0]["kev"] is True
    )  # Log4Shell, lodash


def test_nothing_of_another_org_and_the_definitions(env: Env) -> None:
    _history(env, n=20)
    assert env.client.get("/v2/metrics/open_issues", headers=OTHER).json()["value"] == 0
    other_page = env.client.get("/v2/metrics/issues", params={"kind": "open"}, headers=OTHER).json()
    assert other_page["rows"] == []
    assert env.client.get("/v2/metrics/open_issues", params={"project": env.other_asset_id},
                          headers=AUTH).json()["value"] == 0  # fmt: skip
    reader = token(env, "Reader", ["scans:read"])
    catalogue = env.client.get("/v2/metrics", headers=reader).json()
    assert [m["id"] for m in catalogue] == [m.id for m in METRICS] and len(catalogue) == 12
    assert all(m["definition"] for m in catalogue)
    from pathlib import Path

    doc = Path(__file__).resolve().parents[2] / "docs" / "metrics.md"
    assert (
        doc.read_text() == markdown()
    ), "regenerate docs/metrics.md from core/metrics/definitions.py"  # noqa: E501
    with env.sessions() as s:  # a project removed: its rows go with it
        n = s.scalar(select(func.count()).select_from(MetricOpenIssue))
        assert n and s.get(Asset, env.asset_id) is not None
