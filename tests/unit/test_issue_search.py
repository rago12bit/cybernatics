"""Issues across the organization, by query (Week 73, plan §56): the query language reads exactly
the shared cases the web app's twin reads; every filter means what it says; pages by cursor never
repeat or skip a row; counts are exact up to the cap and an estimate past it; nothing of another
organization, whatever the query or the cursor says."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from core.models import Severity
from core.persistence import repo
from core.persistence.models import Asset, IssueRow, Portfolio, Tag
from core.search import issues as search
from core.search.language import QueryError, format_query, glob_match, parse
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

CASES = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "issue_query_cases.json").read_text()
)["cases"]
NOW = datetime.now(timezone.utc)


# --- the language ---------------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=[c["q"] or "(empty)" for c in CASES])
def test_shared_cases(case: dict[str, Any]) -> None:
    if "error" in case:
        with pytest.raises(QueryError) as caught:
            parse(case["q"])
        err = caught.value
        assert (err.start, err.end) == (case["error"]["start"], case["error"]["end"]), err.message
        assert case["error"]["contains"] in err.message
        return
    q = parse(case["q"])
    assert q.to_dict() == case["filters"]
    assert format_query(q) == case["query"]
    assert parse(format_query(q)).to_dict() == q.to_dict()  # writing back loses nothing


def test_globs_match_a_projects_full_label_or_its_last_part() -> None:
    assert glob_match("payments-*", "acme/payments-api")
    assert glob_match("acme/*", "acme/payments-api")
    assert glob_match("*API", "acme/payments-api")  # case-insensitive
    assert not glob_match("acme/pay", "acme/payments-api")
    assert not glob_match("other/*", "acme/payments-api")
    assert glob_match("a.b", "a.b") and not glob_match("a.b", "axb")  # only * is special


# --- the search -----------------------------------------------------------------------------------


def _project(env: Env, label: str, *, unit: str | None, org: str = ORG, n: int = 4) -> list[str]:
    with env.sessions() as s:
        sc = repo.create_scan(s, source_type="git", source_ref=f"https://example.com/{label}",
                              source_label=label, tools=["semgrep"], org_id=org)  # fmt: skip
        found = [finding(i, Severity.HIGH) for i in range(n)]
        sync = repo.sync_issues_for_scan(s, sc.id, found)
        repo.add_findings(s, sc.id, found, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        asset = s.get(Asset, sc.asset_id)
        assert asset is not None
        asset.portfolio_id = unit
        sla.save(s, org_id=org, asset_id=asset.id, enabled=True, bands=STARTER, actor="t")
        ids = [
            i.id
            for i in s.scalars(
                select(IssueRow).where(IssueRow.asset_id == asset.id).order_by(IssueRow.path)
            )
        ]
        s.commit()
        return ids


def _set(env: Env, issue_id: str, **values: Any) -> None:
    with env.sessions() as s:
        row = s.get(IssueRow, issue_id)
        assert row is not None
        for k, v in values.items():
            setattr(row, k, v)
        s.commit()


@pytest.fixture
def org(env: Env) -> dict[str, Any]:  # noqa: F811
    """Payments (two projects) and Platform (one), each Issue made different on purpose."""
    with env.sessions() as s:
        pay = Portfolio(org_id=ORG, name="Payments")
        plat = Portfolio(org_id=ORG, name="Platform")
        s.add_all([pay, plat])
        s.commit()
        units = {"pay": pay.id, "plat": plat.id}
    api = _project(env, "acme/payments-api", unit=units["pay"])
    ui = _project(env, "acme/payments-ui", unit=units["pay"])
    ledger = _project(env, "acme/ledger", unit=units["plat"])
    other = _project(env, "acme/payments-secret", unit=None, org=OTHER_ORG)
    alice = token(env, "Alice")
    with env.sessions() as s:
        actor = next(a for a in repo.list_api_tokens(s, ORG) if a.name == "Alice")
        alice_actor = f"token:{actor.display_prefix}"
    old = NOW - timedelta(days=90)
    # api: a breached P1 critical, an accepted one, a not-a-risk one, one fixed
    _set(env, api[0], severity="CRITICAL", priority_band="P1", priority_score=95,
         first_seen_at=old, title="SQL injection in checkout", assignee=alice_actor)  # fmt: skip
    _set(env, api[1], triage_status="accepted", triage_expires_at=NOW + timedelta(days=30),
         priority_band="P1", priority_score=90, first_seen_at=old)  # fmt: skip
    _set(env, api[2], triage_status="not_a_risk", priority_band="P2", priority_score=70)
    _set(env, api[3], state="fixed", fixed_at=NOW - timedelta(days=3), priority_score=60)
    # ui: an acceptance that ran out (back in the queue), a P1 not breached, a low, an info
    _set(env, ui[0], triage_status="accepted", triage_expires_at=NOW - timedelta(days=1),
         priority_band="P2", priority_score=80)  # fmt: skip
    _set(env, ui[1], priority_band="P1", priority_score=88, title="Open redirect after login")
    _set(env, ui[2], severity="LOW", priority_band="P4", priority_score=20)
    _set(env, ui[3], severity="INFO", priority_band=None, priority_score=None)
    # ledger: a manual P3 with a path, a P1 breached in Platform, a P3, retest requested
    _set(env, ledger[0], source="manual", path="src/ledger/post.py", priority_band="P3",
         priority_score=40)  # fmt: skip
    _set(env, ledger[1], priority_band="P1", priority_score=91, first_seen_at=old)
    _set(env, ledger[2], priority_band="P3", priority_score=40)
    _set(env, ledger[3], retest_status="requested", priority_band="P2", priority_score=65)
    for i in other:
        _set(env, i, priority_band="P1", priority_score=99, first_seen_at=old)
    with env.sessions() as s:
        s.add(Tag(org_id=ORG, target_type="portfolio", target_id=units["plat"], name="sox"))
        s.commit()
    return {"api": api, "ui": ui, "ledger": ledger, "other": other, "alice": alice,
            "units": units}  # fmt: skip


def _get(env: Env, q: str = "", headers: dict[str, str] | None = None, **params: Any) -> Any:
    r = env.client.get("/v2/issues", params={"q": q, **params}, headers=headers or AUTH)
    assert r.status_code == 200, r.text
    return r.json()


def _ids(page: dict[str, Any]) -> set[str]:
    return {r["id"] for r in page["rows"]}


def test_the_plans_example_query(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    page = _get(env, "priority:P1 sla:breached project:payments-* -status:accepted")
    # api[0] is P1 and breached; api[1] is accepted; ui[1] is P1 but recent; ledger is not payments
    assert _ids(page) == {org["api"][0]}
    assert page["query"] == "-status:accepted priority:P1 sla:breached project:payments-*"
    row = page["rows"][0]
    assert row["project"] == "acme/payments-api" and row["sla"]["state"] == "breached"
    assert row["assignee_name"] == "Alice" and row["band"] == "P1" and row["severity"] == "critical"


def test_status_defaults_to_the_active_queue(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    a, u, led = org["api"], org["ui"], org["ledger"]
    active = _ids(_get(env))
    assert active == {a[0], *u, *led}  # not accepted, not not-a-risk, not fixed
    assert u[0] in active  # its acceptance ran out: back in the queue
    assert _ids(_get(env, "status:fixed")) == {a[3]}
    assert _ids(_get(env, "status:accepted,not_a_risk")) == {a[1], a[2]}
    assert _ids(_get(env, "status:open,fixed project:acme/payments-api")) == {a[0], a[3]}


def test_each_filter(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    a, u, led = org["api"], org["ui"], org["ledger"]
    assert _ids(_get(env, "severity:critical")) == {a[0]}
    assert _ids(_get(env, "-severity:high,critical")) == {u[2], u[3]}
    assert _ids(_get(env, "priority:none")) == {u[3]}
    assert _ids(_get(env, "portfolio:Platform")) == set(led)
    assert _ids(_get(env, "-portfolio:Payments")) == set(led)
    assert _ids(_get(env, "path:src/ledger/*")) == {led[0]}
    assert _ids(_get(env, "source:manual")) == {led[0]}
    assert _ids(_get(env, "retest:requested")) == {led[3]}
    assert _ids(_get(env, "tag:sox")) == set(led)  # set on the business unit, inherited
    assert _ids(_get(env, "-tag:sox project:acme/ledger")) == set()
    assert _ids(_get(env, '"sql injection"')) == {a[0]}
    assert _ids(_get(env, "redirect LOGIN")) == {u[1]}
    assert _ids(_get(env, "first_seen:>30d")) == {a[0], led[1]}
    assert _ids(_get(env, "first_seen:<30d project:acme/ledger")) == {led[0], led[2], led[3]}
    assert _ids(_get(env, "status:fixed fixed:<7d")) == {a[3]}
    assert _ids(_get(env, "status:fixed fixed:>7d")) == set()
    assert _ids(_get(env, "category:sca")) == set()
    assert _ids(_get(env, "sla:breached")) == {a[0], led[1]}
    assert _ids(_get(env, "-sla:breached portfolio:Platform")) == {led[0], led[2], led[3]}


def test_assignee_me_by_name_and_none(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    assert _ids(_get(env, "assignee:me", headers=org["alice"])) == {org["api"][0]}
    assert _ids(_get(env, "assignee:me")) == set()  # the shared token is nobody
    assert _ids(_get(env, "assignee:alice")) == {org["api"][0]}
    assert _ids(_get(env, "assignee:Nobody-Known")) == set()
    assert org["api"][0] not in _ids(_get(env, "assignee:none"))


def test_pages_by_cursor_cover_everything_once_in_order(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    for sort in search.SORTS:
        seen: list[dict[str, Any]] = []
        after = None
        while True:
            params: dict[str, Any] = {
                "sort": sort,
                "limit": 2,
                "q": "status:open,accepted,not_a_risk,fixed",
            }  # noqa: E501
            if after:
                params["after"] = after
            page = _get(env, **params)
            seen += page["rows"]
            after = page["next"]
            if not after:
                break
        ids = [r["id"] for r in seen]
        assert len(ids) == len(set(ids)) == 12, sort  # every Issue of the org, each once
        if sort == "priority":
            scores = [r["score"] if r["score"] is not None else -1 for r in seen]
            assert scores == sorted(scores, reverse=True)
        if sort in ("newest", "oldest"):
            dates = [r["first_seen_at"] for r in seen]
            assert dates == sorted(dates, reverse=sort == "newest")
        if sort == "severity":
            rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            ranks = [rank[r["severity"]] for r in seen]
            assert ranks == sorted(ranks, reverse=True)


def test_a_row_that_changes_between_pages_is_not_shown_twice(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    first = _get(env, limit=3)
    shown = [r["id"] for r in first["rows"]]
    _set(env, shown[0], priority_score=10)  # it would now sort later; the cursor is past it
    rest: list[str] = []
    after = first["next"]
    while after:
        page = _get(env, limit=3, after=after)
        rest += [r["id"] for r in page["rows"]]
        after = page["next"]
    # It is shown again at its new place (it did move), but nothing else repeats or vanishes.
    others = [i for i in rest if i != shown[0]]
    assert len(others) == len(set(others))
    assert set(shown) | set(rest) == _ids(_get(env, limit=200))


def test_counts_are_exact_while_quick_then_a_true_lower_bound(
    env: Env, org: dict[str, Any], monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    assert _get(env)["count"] == {"value": 9, "exact": True}
    assert _get(env, count=False)["count"] is None
    monkeypatch.setattr(search, "COUNT_CAP", 5)
    assert _get(env)["count"] == {"value": 9, "exact": True}  # past the cap, but quick: exact
    monkeypatch.setattr(search, "bounded", lambda s, stmt, ms: None)  # the full count ran out
    assert _get(env)["count"] == {"value": 5, "exact": False, "at_least": True}


def test_bad_queries_and_cursors_say_what_is_wrong(
    env: Env, org: dict[str, Any]
) -> None:  # noqa: F811,E501
    r = env.client.get("/v2/issues", params={"q": "severity:huge"}, headers=AUTH)
    assert r.status_code == 422
    assert r.json()["detail"] == {"message": "“huge” is not a severity. Choose from: critical, "
                                  "high, medium, low, info.", "start": 9, "end": 13}  # fmt: skip
    r = env.client.get("/v2/issues", params={"after": "garbage!"}, headers=AUTH)
    assert r.status_code == 422 and "not valid" in r.json()["detail"]["message"]
    nxt = _get(env, limit=1)["next"]
    r = env.client.get("/v2/issues", params={"after": nxt, "sort": "newest"}, headers=AUTH)
    assert r.status_code == 422 and "another order" in r.json()["detail"]["message"]
    r = env.client.get("/v2/issues", params={"sort": "random"}, headers=AUTH)
    assert r.status_code == 422
    parsed = env.client.get("/v2/issues/parse", params={"q": "sev:HIGH  x"}, headers=AUTH).json()
    assert parsed == {"filters": {"severity": {"include": ["high"]}, "text": ["x"]},
                      "query": "severity:high x"}  # fmt: skip


def test_nothing_of_another_organization(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    everything = "status:open,accepted,not_a_risk,fixed"
    for q in ("", "project:*", "project:acme/payments-secret", everything, "priority:P1"):
        assert not _ids(_get(env, q, limit=200)) & set(org["other"]), q
    # A cursor naming another org's Issue only says where to start; it reveals nothing.
    with env.sessions() as s:
        foreign = s.get(IssueRow, org["other"][0])
        assert foreign is not None
        cursor = search._encode("priority", 99, foreign.id)
    page = _get(env, after=cursor, q=everything, limit=200)
    assert not _ids(page) & set(org["other"])
    projects = env.client.get("/v2/issues/suggest", params={"key": "project"}, headers=AUTH)
    assert "acme/payments-secret" not in projects.json()["values"]


def test_suggestions(env: Env, org: dict[str, Any]) -> None:  # noqa: F811
    def values(key: str, prefix: str = "") -> list[str]:
        r = env.client.get("/v2/issues/suggest", params={"key": key, "prefix": prefix},
                           headers=AUTH)  # fmt: skip
        assert r.status_code == 200
        return list(r.json()["values"])

    assert values("project", "pay") == ["acme/payments-api", "acme/payments-ui"]
    assert values("portfolio") == ["Payments", "Platform", "none"]
    assert values("severity", "i") == ["info"]  # a fixed list matches from the start
    assert values("assignee")[:2] == ["me", "none"] and "alice" in values("assignee")
    assert values("tag") == ["sox"]
    assert set(values("source")) == {"scanner", "manual"}
    assert values("nonsense") == []
