"""Role homes and the portfolio overview (plan §48.2, §55.6): the sentence names what needs
attention and why -- Issues past SLA, a new advisory, the project nobody scans -- projects sort by
need, "scanners N of M"; an engineer lands on their Issues, a tester on their engagements; only a
person picks a role; nothing of another organization."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select

from core.metrics import rollup
from core.models import Severity
from core.persistence import repo
from core.persistence.models import (
    AdvisoryImpact,
    AdvisoryState,
    Asset,
    Engagement,
    IssueRow,
    Library,
    Portfolio,
    Scan,
)
from core.sla import service as sla
from core.sla.policy import STARTER
from core.tenancy import DEFAULT_ORG_ID as ORG
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_risk_acceptance import token
from tests.unit.test_sla import finding

NOW = datetime.now(timezone.utc)


def _project(env: Env, label: str, unit: str | None, *, n: int = 3, late: int = 0,
             scanned_days_ago: int = 1, tools: tuple[str, ...] = ("ok", "ok", "skipped")) -> str:  # fmt: skip
    """A project with n HIGH Issues, `late` of them first seen long enough ago to be past SLA."""
    with env.sessions() as s:
        sc = repo.create_scan(s, source_type="git", source_ref=f"https://example.com/{label}",
                              source_label=label, tools=["semgrep"], org_id=ORG)  # fmt: skip
        found = [finding(i, Severity.HIGH) for i in range(n)]
        sync = repo.sync_issues_for_scan(s, sc.id, found)
        repo.add_findings(s, sc.id, found, sync.updates)
        for k, status in enumerate(tools):
            repo.add_tool_run(s, sc.id, f"tool{k}", {"status": status, "findings": 0})
        repo.finish_scan(s, sc.id, "completed")
        s.get(Scan, sc.id).finished_at = NOW - timedelta(days=scanned_days_ago)  # type: ignore[union-attr]
        asset = s.get(Asset, sc.asset_id)
        assert asset is not None
        asset.portfolio_id = unit
        sla.save(s, org_id=ORG, asset_id=asset.id, enabled=True, bands=STARTER, actor="t")
        issues = list(s.scalars(select(IssueRow).where(IssueRow.asset_id == asset.id)))
        for k, i in enumerate(issues):
            i.first_seen_at = NOW - timedelta(days=60 if k < late else 2)
            i.priority_band = "P1" if k == 0 else "P3"
        s.commit()
        return asset.id


def _unit(env: Env, name: str) -> str:
    with env.sessions() as s:
        p = Portfolio(org_id=ORG, name=name)
        s.add(p)
        s.commit()
        return p.id


def _advisory(env: Env, asset: str, key: str) -> None:
    with env.sessions() as s:
        lib = Library(org_id=ORG, ecosystem="npm", name=f"lib-{key}", key=f"npm:lib-{key}",
                      purl=f"pkg:npm/lib-{key}")  # fmt: skip
        s.add(lib)
        s.flush()
        s.add(AdvisoryImpact(org_id=ORG, vuln_key=key, advisory_ids=[], library_id=lib.id,
                             asset_id=asset, version="1.0", certain=True))  # fmt: skip
        s.add(AdvisoryState(org_id=ORG, vuln_key=key, state="new"))
        s.commit()


def _refresh(env: Env) -> None:
    with env.sessions() as s:
        rollup.refresh_all(s, ORG)


def test_the_overview_says_what_needs_attention_and_sorts_by_need(env: Env) -> None:
    pay = _unit(env, "Payments")
    gateway = _project(env, "partner-gateway", pay, late=2, tools=("ok", "error", "ok", "skipped"))
    api = _project(env, "payments-api", pay, late=2)
    reports = _project(env, "reporting-svc", pay, n=1, scanned_days_ago=19)
    _project(env, "ledger", pay, n=2)
    _advisory(env, gateway, "CVE-2026-0001")
    _refresh(env)

    o = env.client.get(f"/v2/portfolio-overviews/{pay}", headers=AUTH).json()
    assert o["verdict"] == (
        "3 projects need attention: 4 issues are past SLA, a new advisory affects "
        "partner-gateway and reporting-svc hasn't been scanned in 19 days. The other project is "
        "on track."
    )
    assert [p["label"] for p in o["projects"]] == [
        "partner-gateway", "payments-api", "reporting-svc", "ledger"
    ]  # fmt: skip
    first = o["projects"][0]
    assert (first["open_p1"], first["past_sla"], first["needs"]) == (
        1,
        2,
        ["past_sla", "new_advisory"],
    )
    assert (first["scanners_ok"], first["scanners_applicable"]) == (2, 3)  # skipped doesn't apply
    assert len(first["trend"]) == 8 and first["trend"][-1] == 3
    assert o["projects"][2]["days_since_scan"] == 19 and o["projects"][3]["needs"] == []
    assert api in {p["asset"] for p in o["projects"]} and reports

    listed = env.client.get("/v2/portfolio-overviews", headers=AUTH).json()
    assert listed[0] == {"id": pay, "name": "Payments", "verdict": o["verdict"],
                         "needs_attention": 3, "projects": 4}  # fmt: skip


def test_all_on_track_and_projects_without_a_portfolio(env: Env) -> None:
    unit = _unit(env, "Platform")
    _project(env, "auth", unit)
    _project(env, "infra", unit)
    _project(env, "intranet", None, scanned_days_ago=40)
    _refresh(env)
    o = env.client.get(f"/v2/portfolio-overviews/{unit}", headers=AUTH).json()
    assert o["verdict"] == (
        "All 2 projects are on track: nothing past SLA, no new advisories, and every one scanned "
        "in the last 14 days."
    )
    none = env.client.get("/v2/portfolio-overviews/none", headers=AUTH).json()
    assert none["name"] == "Projects without a portfolio"
    # The fixture's own project has never been scanned: the quiet failure, named first.
    assert none["verdict"] == (
        "2 projects need attention: a/b has never had a full scan and intranet hasn't been "
        "scanned in 40 days."
    )
    ids = [x["id"] for x in env.client.get("/v2/portfolio-overviews", headers=AUTH).json()]
    assert ids == ["none", unit]  # the one needing attention first
    other = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
    assert env.client.get(f"/v2/portfolio-overviews/{unit}", headers=other).status_code == 404
    theirs = env.client.get("/v2/portfolio-overviews", headers=other).json()
    assert [x["id"] for x in theirs] == ["none"]  # their own fixture project only
    assert "intranet" not in theirs[0]["verdict"] and theirs[0]["projects"] == 1


def _me(env: Env, who: dict[str, str]) -> dict[str, Any]:
    return env.client.get("/v2/me", headers=who).json()  # type: ignore[no-any-return]


def test_engineers_land_on_their_issues_and_testers_on_their_engagements(env: Env) -> None:
    arjun, meera, priya = token(env, "Arjun K."), token(env, "Meera S."), token(env, "Priya N.")
    a = _project(env, "payments-api", None, n=4, late=1)
    with env.sessions() as s:
        issues = sorted(s.scalars(select(IssueRow).where(IssueRow.asset_id == a)),
                        key=lambda i: i.first_seen_at)  # fmt: skip
        for i in issues[:3]:
            i.assignee = _me(env, arjun)["actor"]
        issues[3].assignee = _me(env, priya)["actor"]
        s.add(Engagement(org_id=ORG, asset_id=a, name="Q4 test", engagement_type="pentest",
                         status="active", lead="@priyan", testers=["Meera S."],
                         target_end_at=NOW - timedelta(days=1)))  # fmt: skip
        s.add(Engagement(org_id=ORG, asset_id=a, name="Q1 audit", engagement_type="audit",
                         status="completed", lead="Someone", testers=["meera s."]))  # fmt: skip
        s.commit()
    _refresh(env)

    mine = env.client.get("/v2/me/assigned", headers=arjun).json()
    assert mine["total"] == 3 and len(mine["rows"]) == 3
    assert mine["rows"][0]["days_left"] < 0  # the overdue one first
    assert [r["days_left"] for r in mine["rows"]] == sorted(r["days_left"] for r in mine["rows"])
    assert env.client.get("/v2/me/assigned", headers=priya).json()["total"] == 1

    tests = env.client.get("/v2/me/engagements", headers=meera).json()
    assert [(e["name"], e["as"], e["overdue"]) for e in tests] == [
        ("Q4 test", ["tester"], True), ("Q1 audit", ["tester"], False)
    ]  # fmt: skip
    assert [e["as"] for e in env.client.get("/v2/me/engagements", headers=priya).json()] == [
        ["lead"]
    ]
    assert env.client.get("/v2/me/engagements", headers=arjun).json() == []


def test_only_a_person_picks_a_role(env: Env) -> None:
    r = env.client.put("/v2/me/role", json={"role": "lead"}, headers=AUTH)
    assert r.status_code == 409 and "shared token is nobody" in r.json()["detail"]["message"]
    me = _me(env, AUTH)
    assert me["person"] is False and me["role"] is None
