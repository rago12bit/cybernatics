"""The calendar (plan §49): engagements, SLA due dates and expiring risk acceptances, for a range,
as one list -- the same SLA dates the issues table shows, and nothing of another organization."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from core.engagements import service as engagements
from core.models import Severity
from core.persistence.models import IssueRow, RiskAcceptance, RiskAcceptanceIssue
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_sla import age, finding, scan
from tests.unit.test_sla import put as put_sla

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
TODAY = datetime.now(timezone.utc).date()


def get(env: Env, start: date, end: date, headers: Any = AUTH, **params: Any) -> Any:
    q = {"from": start.isoformat(), "to": end.isoformat(), **params}
    return env.client.get("/v2/calendar", params=q, headers=headers)


def seed(env: Env) -> dict[str, str]:
    # Starter SLA: CRITICAL 7 days, HIGH 30, LOW 180.
    scan(env, [finding(1, Severity.CRITICAL), finding(2, Severity.HIGH), finding(3, Severity.LOW)])
    assert put_sla(env).status_code == 200
    age(env, {"Problem 1": 2, "Problem 2": 40})  # critical due in 5 days; high breached 10 ago
    with env.sessions() as s:
        ids = {i.title: i.id for i in s.scalars(select(IssueRow))}
        e = engagements.create(
            s,
            org_id=DEFAULT_ORG_ID,
            asset_id=env.asset_id,
            actor="t",
            data={
                "name": "Q4 external pentest",
                "starts_at": (TODAY + timedelta(days=3)).isoformat(),
                "ends_at": (TODAY + timedelta(days=12)).isoformat(),
            },
        )
        ra = RiskAcceptance(
            org_id=DEFAULT_ORG_ID,
            asset_id=env.asset_id,
            decision="accept",
            justification="j",
            controls="c",
            expires_at=datetime.now(timezone.utc) + timedelta(days=20),
            state="approved",
            requested_by="token:x",
        )
        s.add(ra)
        s.flush()
        s.add(
            RiskAcceptanceIssue(
                acceptance_id=ra.id, issue_id=ids["Problem 3"], org_id=DEFAULT_ORG_ID
            )
        )
        s.commit()
        ids.update(engagement=e.id, acceptance=ra.id)
    return ids


def test_engagements_sla_dates_and_acceptances_in_one_list(env: Env) -> None:
    ids = seed(env)
    r = get(env, TODAY - timedelta(days=15), TODAY + timedelta(days=30))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"] == {"engagement": 1, "sla": 2, "acceptance": 1}
    by_kind = {e["kind"]: [] for e in body["entries"]}
    for e in body["entries"]:
        by_kind[e["kind"]].append(e)
    [eng] = by_kind["engagement"]
    assert (eng["title"], eng["start"], eng["end"]) == (
        "Q4 external pentest",
        str(TODAY + timedelta(days=3)),
        str(TODAY + timedelta(days=12)),
    )
    assert eng["link"] == f"/app/engagements/{ids['engagement']}"
    slas = {e["title"]: e for e in by_kind["sla"]}
    assert slas["Problem 1"]["start"] == str(TODAY + timedelta(days=5))
    assert slas["Problem 1"]["state"] == "on_track" and "SLA due" in slas["Problem 1"]["detail"]
    assert slas["Problem 2"]["start"] == str(TODAY - timedelta(days=10))
    assert slas["Problem 2"]["state"] == "breached"
    assert "Problem 3" not in slas  # due in 180 days: outside the range
    [acc] = by_kind["acceptance"]
    assert (acc["title"], acc["link"]) == (
        "Accept: 1 issue",
        f"/app/risk-acceptances/{ids['acceptance']}",
    )
    assert [e["start"] for e in body["entries"]] == sorted(e["start"] for e in body["entries"])
    # The same SLA date the issues table shows.
    table = env.client.get(f"/assets/{env.asset_id}/issues", headers=AUTH).json()["items"]
    shown = {i["title"]: i["issue"]["sla"] for i in table}
    for title in ("Problem 1", "Problem 2"):
        assert shown[title]["due_at"][:10] == slas[title]["start"], title


def test_filters_ranges_and_another_org(env: Env) -> None:
    seed(env)
    only = get(env, TODAY, TODAY + timedelta(days=30), kinds="sla").json()
    assert set(only["counts"]) == {"engagement", "sla", "acceptance"}
    assert {e["kind"] for e in only["entries"]} == {"sla"}
    assert (
        get(env, TODAY, TODAY + timedelta(days=30), project_id=env.asset_id).json()["counts"][
            "engagement"
        ]
        == 1
    )
    assert (
        get(env, TODAY, TODAY + timedelta(days=30), project_id=env.other_asset_id).status_code
        == 404
    )
    assert get(env, TODAY, TODAY - timedelta(days=1)).json()["detail"]["field"] == "to"
    assert get(env, TODAY, TODAY + timedelta(days=150)).status_code == 422
    assert get(env, TODAY, TODAY + timedelta(days=5), kinds="sla,birthdays").status_code == 422
    other = get(env, TODAY - timedelta(days=30), TODAY + timedelta(days=60), headers=OTHER).json()
    assert other["entries"] == []


def test_exempt_fixed_and_closed_things_leave_the_calendar(env: Env) -> None:
    ids = seed(env)
    with env.sessions() as s:
        s.get(IssueRow, ids["Problem 1"]).triage_status = "not_a_risk"  # type: ignore[union-attr]
        s.get(RiskAcceptance, ids["acceptance"]).state = "withdrawn"  # type: ignore[union-attr]
        s.commit()
    scan(env, [finding(1, Severity.CRITICAL), finding(3, Severity.LOW)])  # Problem 2 fixed
    body = get(env, TODAY - timedelta(days=15), TODAY + timedelta(days=30)).json()
    assert body["counts"] == {"engagement": 1, "sla": 0, "acceptance": 0}
