"""The priority engine v3 (Week 63, plan §44.3): weights per factor and the project's business
context, a preview of the top 50 before saving, recomputation in the background under a lock, every
rank explained with its weights -- and, with no saved policy, exactly the v2 score."""

from __future__ import annotations

import itertools
import math
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import func, select

from core.models import Category, Evidence, Finding, Location, Package, Scoring, Severity, Taxonomy
from core.persistence import repo
from core.persistence.models import AuditEntry, FindingRow, IssueRow, OutboxEvent, PriorityPolicy
from core.priority import engine, service
from core.priority.engine import (
    STARTER,
    V2_WEIGHTS,
    Context,
    PolicyError,
    Signals,
    band_of,
    non_production,
    parse_context,
    parse_weights,
)
from core.reachability.index import Reachability
from core.risk.feeds import Feeds
from core.risk.score import score_finding
from core.sla import service as sla_service
from core.sla.policy import STARTER_BY_PRIORITY, Policy, evaluate, parse_bands
from core.tenancy import DEFAULT_ORG_ID
from core.triage_assistant.contract import TriageVerdict
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    Env,
    env,  # noqa: F401  (the fixture)
)

# --- the engine -----------------------------------------------------------------------------------


def _finding(
    i: int,
    *,
    severity: Severity = Severity.HIGH,
    category: Category = Category.SAST,
    cvss: float | None = None,
    cves: tuple[str, ...] = (),
    confidence: float = 0.5,
    agreement: int = 1,
    path: str | None = None,
    title: str | None = None,
) -> Finding:
    path = path or f"app/m{i}.py"
    return Finding(
        id=f"p:{i}", title=title or f"Problem {i}", description="d",
        location=Location(path, i + 1, i + 1, f"line {i}", Location.hash_snippet(f"line {i}")),
        taxonomy=Taxonomy(category, cwe=("CWE-89",), cve=cves),
        scoring=Scoring(normalized_severity=severity, cvss_v3_1=cvss, confidence=confidence),
        evidence=Evidence(reported_by=["semgrep"], agreement_count=agreement,
                          rule_ids={"semgrep": [f"rule-{i}"]}),
        fingerprint=f"prio-{i}",
        package=Package("lib", "1.0", "pypi") if category is Category.SCA else None,
    )  # fmt: skip


def _cases() -> list[tuple[Finding, Feeds, Reachability | None, TriageVerdict | None]]:
    """A broad grid of what v2 scores: every severity, CVSS or not, KEV, EPSS from tiny to certain,
    no exploit data, no CVE id, code findings by confidence, reachability, and every verdict."""
    feeds = Feeds(
        epss={"CVE-1": 0.0004, "CVE-2": 0.03, "CVE-3": 0.2, "CVE-4": 0.9, "CVE-K": 0.01},
        kev={"CVE-K"}, epss_loaded=True, kev_loaded=True,
    )  # fmt: skip
    reaches = [
        None,
        Reachability(True, "Imported by app/x.py"),
        Reachability(False, "Not imported"),
    ]
    verdicts: list[TriageVerdict | None] = [None] + [
        TriageVerdict(v, c, "r", ())
        for v in ("likely_real", "likely_false_positive", "unsure")
        for c in ("high", "medium", "low")
    ]
    out = []
    i = 0
    for sev, cvss in itertools.product(list(Severity), (None, 9.8, 5.3, 0.0)):
        for cves in ((), ("CVE-1",), ("CVE-3",), ("CVE-4",), ("CVE-K",), ("CVE-UNKNOWN",)):
            for reach, verdict in itertools.product(reaches, verdicts[::3]):
                i += 1
                cat = Category.SCA if cves or i % 2 else Category.SAST
                f = _finding(i, severity=sev, category=cat, cvss=cvss, cves=cves,
                             confidence=(i % 10) / 10, agreement=1 + i % 3)  # fmt: skip
                out.append((f, feeds, reach, verdict))
    return out


def test_v2_weights_reproduce_the_v2_score_exactly() -> None:
    cases = _cases()
    assert len(cases) > 1000
    for f, feeds, reach, verdict in cases:
        v2 = score_finding(f, feeds, reach, verdict)
        sig = Signals.from_finding(
            v2.to_dict(),
            verdict=verdict.verdict if verdict else None,
            verdict_confidence=verdict.confidence if verdict else None,
        )
        got = engine.score(sig, V2_WEIGHTS)
        assert got.score == v2.scoring.risk_score, (f.title, f.to_dict()["scoring"], reach)


def _sig(**over: Any) -> Signals:
    return Signals(**{"severity": "HIGH", "confidence": 0.8, "agreement": 2, **over})


def _w(**over: float) -> dict[str, float]:
    return {**STARTER, **over}


def test_a_weight_is_an_exponent_on_the_factor() -> None:
    unreached = _sig(reachable=False)
    base = engine.score(_sig(), STARTER).score
    assert engine.score(unreached, _w(reachability=0)).score == base  # ignored
    one = engine.score(unreached, _w(reachability=1))
    two = engine.score(unreached, _w(reachability=2))
    assert one.score == round(75 * 0.9 * 0.85)  # High 0.75, confidence 0.8 -> 0.9; rounded once
    assert two.score == round(75 * 0.9 * 0.85**2)
    assert next(c for c in two.factors if c.factor == "reachability").weight == 2


def test_severity_weight_zero_ranks_every_severity_alike() -> None:
    flat = _w(severity=0)
    scores = {s: engine.score(_sig(severity=s), flat).score for s in ("CRITICAL", "LOW", "INFO")}
    assert len(set(scores.values())) == 1
    steep = _w(severity=2)
    assert (
        engine.score(_sig(severity="LOW"), steep).score
        < engine.score(_sig(severity="LOW"), STARTER).score
    )


def test_kev_is_a_floor_scaled_by_its_weight_and_zero_ignores_it() -> None:
    kev = _sig(severity="LOW", kev=True, has_cve=True, dependency=True, epss=0.0001)
    assert engine.score(kev, STARTER).score == 90
    assert engine.score(kev, _w(kev=0.5)).score == 45
    assert engine.score(kev, _w(kev=2)).score == 100  # capped
    ignored = engine.score(kev, _w(kev=0))
    assert ignored.score < 45 and [c.factor for c in ignored.factors][1] == "epss"
    unreached = engine.score(_sig(severity="LOW", kev=True, has_cve=True, reachable=False), STARTER)
    assert unreached.score == 80
    assert "at least 90" in engine.score(kev, STARTER).factors[1].text


def test_new_factors_boost_or_damp_and_say_so() -> None:
    plain = engine.score(_sig(), STARTER).score
    taint = engine.score(_sig(taint=True), STARTER)
    runtime = engine.score(_sig(runtime=True), STARTER)
    test_code = engine.score(_sig(path="tests/test_app.py"), STARTER)
    raw = 75 * 0.9  # High, confidence 0.8; the score is rounded once, at the end
    assert plain == round(raw)
    assert taint.score == round(raw * 1.1) and runtime.score == round(raw * 1.25)
    assert test_code.score == round(raw * 0.6)
    assert any(c.text == "In test code" for c in test_code.factors)
    # v2's weights leave all three out
    for s in (_sig(taint=True), _sig(runtime=True), _sig(path="tests/test_app.py")):
        assert engine.score(s, V2_WEIGHTS).score == engine.score(_sig(), V2_WEIGHTS).score


def test_business_context_only_lowers_and_unset_is_the_worst_case() -> None:
    sig = _sig()
    plain = engine.score(sig, STARTER).score
    worst = Context(internet_facing=True, data_sensitivity="restricted", criticality="critical")
    calm = Context(internet_facing=False, data_sensitivity="public", criticality="low")
    assert engine.score(sig, STARTER, worst).score == plain  # describing the worst changes nothing
    assert engine.score(sig, STARTER, worst).factors == engine.score(sig, STARTER).factors
    down = engine.score(sig, STARTER, calm)
    assert down.score == round(75 * 0.9 * 0.8 * 0.65 * 0.65)
    texts = [c.text for c in down.factors]
    assert "Internal only" in texts and "Handles public data" in texts
    assert "Low business criticality" in texts
    # a heavier weight calms harder; zero ignores it
    assert engine.score(sig, _w(criticality=2), Context(criticality="low")).score == round(
        75 * 0.9 * 0.65**2
    )
    assert engine.score(sig, _w(criticality=0), Context(criticality="low")).score == plain
    # no context can push an issue up, so none can inflate a project into P1
    for ctx in (worst, calm, Context(data_sensitivity="internal")):
        for s in (_sig(severity="LOW"), _sig(severity="CRITICAL", kev=True, has_cve=True)):
            assert engine.score(s, STARTER, ctx).score <= engine.score(s, STARTER).score


def test_every_factor_that_applied_is_listed_with_its_weight() -> None:
    sig = _sig(reachable=True, reach_reason="Reachable", taint=True, verdict="likely_real",
               verdict_confidence="high")  # fmt: skip
    p = engine.score(sig, _w(taint=1.5), Context(criticality="high"))  # high: x0.9
    got = {c["factor"]: c for c in p.to_dict()["factors"]}
    assert set(got) == {
        "severity",
        "agreement",
        "reachability",
        "taint",
        "criticality",
        "assistant",
    }
    assert got["taint"]["weight"] == 1.5 and got["taint"]["label"] == "Taint path confirmed"
    assert math.isclose(got["taint"]["effect"], round(1.1**1.5, 3))
    assert p.band == band_of(p.score)


def test_bands() -> None:
    assert [band_of(x) for x in (100, 80, 79, 60, 59, 30, 29, 0, None)] == [
        "P1", "P1", "P2", "P2", "P3", "P3", "P4", "P4", None,
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("raw", "field"),
    [
        ({"severity": 3.5}, "weights.severity"),
        ({"severity": -1}, "weights.severity"),
        ({"severity": True}, "weights.severity"),
        ({"severity": "2"}, "weights.severity"),
        ({"severity": float("nan")}, "weights.severity"),
        ({"loudness": 1}, "weights"),
        ([], "weights"),
    ],
)
def test_weights_are_validated_with_the_field_named(raw: Any, field: str) -> None:
    with pytest.raises(PolicyError) as caught:
        parse_weights(raw)
    assert caught.value.field == field


def test_missing_weights_take_the_starter_and_values_round() -> None:
    got = parse_weights({"epss": 1.234})
    assert got == {**STARTER, "epss": 1.23}


@pytest.mark.parametrize(
    ("raw", "field"),
    [
        ({"internet_facing": "yes"}, "context.internet_facing"),
        ({"data_sensitivity": "secret"}, "context.data_sensitivity"),
        ({"criticality": "extreme"}, "context.criticality"),
        ({"owner": "x"}, "context"),
        ("high", "context"),
    ],
)
def test_context_is_validated(raw: Any, field: str) -> None:
    with pytest.raises(PolicyError) as caught:
        parse_context(raw)
    assert caught.value.field == field


def test_context_empty_values_mean_not_set() -> None:
    assert parse_context(None) == Context()
    assert parse_context({"data_sensitivity": "", "criticality": None}) == Context()


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("tests/test_x.py", "test"), ("src/__tests__/a.js", "test"), ("app/x_test.py", "test"),
        ("web/a.spec.ts", "test"), ("docs/example.py", "other"), ("vendor/lib/a.go", "other"),
        ("./examples/a.py", "other"), ("app/latest.py", None), ("app/contest/x.py", None),
        ("requirements.txt", None),
    ],
)  # fmt: skip
def test_non_production_paths(path: str, kind: str | None) -> None:
    assert non_production(path) == kind


# --- a project with Issues ------------------------------------------------------------------------


def scan(env: Env, findings: list[Finding]) -> str:
    """Store a scan the way the pipeline does: v2 risk scores first, then Issues and occurrences."""
    scored = [score_finding(f, Feeds()) for f in findings]
    with env.sessions() as s:
        sc = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/a/b", source_label="a/b",
            tools=["semgrep"],
        )  # fmt: skip
        sc.asset_id = env.asset_id
        s.commit()
        sync = repo.sync_issues_for_scan(s, sc.id, scored)
        repo.add_findings(s, sc.id, scored, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        return sc.id


def mixed() -> list[Finding]:
    return [
        _finding(1, severity=Severity.CRITICAL, confidence=0.9, title="Critical in app"),
        _finding(2, severity=Severity.HIGH, confidence=0.5, title="High in app"),
        _finding(3, severity=Severity.CRITICAL, confidence=0.9, path="tests/test_db.py",
                 title="Critical in tests"),
        _finding(4, severity=Severity.MEDIUM, confidence=0.6, title="Medium in app"),
        _finding(5, severity=Severity.LOW, confidence=0.3, title="Low in app"),
    ]  # fmt: skip


def issues(env: Env, **params: Any) -> list[dict[str, Any]]:
    r = env.client.get(f"/assets/{env.asset_id}/issues", params=params, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()["items"]  # type: ignore[no-any-return]


def put(env: Env, weights: Any = None, context: Any = None, **kw: Any) -> Any:
    body = {"weights": STARTER if weights is None else weights, "context": context, **kw}
    return env.client.put(f"/v2/projects/{env.asset_id}/priority", json=body, headers=AUTH)


def issue_rows(env: Env) -> dict[str, IssueRow]:
    with env.sessions() as s:
        rows = s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id))
        return {i.title: i for i in rows}


def test_with_no_policy_priority_is_the_v2_score(env: Env) -> None:
    scan(env, mixed())
    got = issues(env)
    for item in got:
        p = item["issue"]["priority"]
        assert p["version"] == 0
        assert p["score"] == item["scoring"]["risk_score"]
        assert p["band"] == band_of(p["score"])
        assert [f["text"] for f in p["factors"]] == item["scoring"]["risk_factors"]
    assert [i["title"] for i in got][0] in ("Critical in app", "Critical in tests")
    r = env.client.get(f"/v2/projects/{env.asset_id}/priority", headers=AUTH).json()
    assert (r["version"], r["weights"], r["locked"], r["recompute"]) == (0, V2_WEIGHTS, False, None)
    assert [f["key"] for f in r["factors"]] == list(engine.FACTOR_KEYS)


def test_saving_recomputes_every_issue_in_the_background_and_logs_it(env: Env) -> None:
    scan(env, mixed())
    r = put(env, context={"criticality": "high", "internet_facing": True}, note="payments")
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["version"] == 1
    # the background job ran after the response (TestClient runs it before returning)
    after = env.client.get(f"/v2/projects/{env.asset_id}/priority", headers=AUTH).json()
    rc = after["recompute"]
    assert (rc["status"], rc["total"], rc["processed"]) == ("done", 5, 5)
    assert after["locked"] is False and after["history"][0]["note"] == "payments"
    rows = issue_rows(env)
    assert {i.priority_version for i in rows.values()} == {1}
    tests_issue = rows["Critical in tests"]
    assert any(
        f["factor"] == "path" and f["weight"] == 1 for f in tests_issue.priority_factors or []
    )
    assert rows["Critical in app"].priority_score > rows["Critical in tests"].priority_score  # type: ignore[operator]
    with env.sessions() as s:
        audit = s.scalars(
            select(AuditEntry).where(AuditEntry.action == "priority.policy.changed")
        ).all()
        assert len(audit) == 1 and audit[0].target == f"asset:{env.asset_id}"
        events = [
            e.event_type
            for e in s.scalars(select(OutboxEvent).where(OutboxEvent.event_type.like("priority.%")))
        ]
        assert events == ["priority.policy_changed", "priority.recomputed"]
    # the issues table now ranks by it, and test code no longer sits at the top
    order = [i["title"] for i in issues(env)]
    assert order[0] == "Critical in app" and order.index("Critical in tests") > 0


def test_the_business_context_moves_bands_and_the_band_filter_follows(env: Env) -> None:
    scan(env, mixed())
    before = {i["title"] for i in issues(env, priority="P1")}
    assert before
    put(env, context={"criticality": "low", "internet_facing": False, "data_sensitivity": "public"})
    after = {i["title"] for i in issues(env, priority="P1")}
    assert after < before
    p4 = issues(env, priority=["p4"])
    assert p4 and all(i["issue"]["priority"]["band"] == "P4" for i in p4)
    assert env.client.get(f"/assets/{env.asset_id}/issues", params={"priority": "P9"},
                          headers=AUTH).status_code == 422  # fmt: skip


def test_saving_is_refused_while_a_recomputation_runs(env: Env) -> None:
    scan(env, mixed())
    now = datetime.now(timezone.utc)
    with env.sessions() as s:
        s.add(PriorityPolicy(org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, version=1,
                             weights=STARTER, context={}, status="running", heartbeat_at=now))  # fmt: skip
        s.commit()
    r = put(env)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "PRIORITY_RECOMPUTING"
    assert env.client.get(f"/v2/projects/{env.asset_id}/priority", headers=AUTH).json()["locked"]
    with env.sessions() as s:
        assert s.scalar(select(func.count()).select_from(PriorityPolicy)) == 1


def test_a_stale_lock_is_taken_over_and_the_old_job_stops(env: Env) -> None:
    scan(env, mixed())
    old = datetime.now(timezone.utc) - timedelta(minutes=11)
    with env.sessions() as s:
        stale = PriorityPolicy(org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, version=1,
                               weights=STARTER, context={}, status="running", heartbeat_at=old)  # fmt: skip
        s.add(stale)
        s.commit()
        stale_id = stale.id
    assert put(env).status_code == 202
    with env.sessions() as s:
        abandoned = s.get(PriorityPolicy, stale_id)
        assert abandoned is not None and abandoned.status == "failed"
        assert "abandoned" in (abandoned.error or "")
        # a late redelivery of the abandoned job does nothing
        assert service.recompute(s, stale_id).status == "failed"  # type: ignore[union-attr]


def test_two_saves_cannot_both_land(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    with env.sessions() as s:
        service.save(s, org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, weights=STARTER,
                     context=None, actor="a")  # fmt: skip
        first = service.current(s, env.asset_id)
        assert first is not None
        first.status = "done"
        s.commit()
        # the second save read the state before the first landed: same version number
        monkeypatch.setattr(service, "current", lambda *_: None)
        with pytest.raises(service.PolicyLocked):
            service.save(s, org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, weights=STARTER,
                         context=None, actor="b")  # fmt: skip


def test_a_superseded_or_finished_job_does_nothing(env: Env) -> None:
    scan(env, mixed())
    with env.sessions() as s:
        a = PriorityPolicy(org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, version=1,
                           weights=STARTER, context={}, status="pending")  # fmt: skip
        b = PriorityPolicy(org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, version=2,
                           weights=STARTER, context={}, status="pending")  # fmt: skip
        s.add_all([a, b])
        s.commit()
        assert service.recompute(s, a.id).status == "superseded"  # type: ignore[union-attr]
        assert service.recompute(s, b.id).status == "done"  # type: ignore[union-attr]
        n = b.processed
        assert service.recompute(s, b.id).processed == n  # type: ignore[union-attr]
        assert service.recompute(s, "missing") is None


def test_recomputation_works_in_batches_and_records_progress(env: Env) -> None:
    scan(env, [_finding(i, severity=Severity.MEDIUM) for i in range(7)])
    with env.sessions() as s:
        row = service.save(s, org_id=DEFAULT_ORG_ID, asset_id=env.asset_id,
                           weights=_w(severity=2), context=None, actor="a")  # fmt: skip
        done = service.recompute(s, row.id, batch=3)
        assert done is not None
        assert (done.status, done.total, done.processed) == ("done", 7, 7)
        assert done.changed == 7  # Medium, squared impact: P3 -> P4
        assert done.started_at is not None and done.finished_at is not None


def test_a_job_that_was_taken_over_mid_run_stops(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    scan(env, [_finding(i) for i in range(6)])
    with env.sessions() as s:
        row = service.save(s, org_id=DEFAULT_ORG_ID, asset_id=env.asset_id, weights=STARTER,
                           context=None, actor="a")  # fmt: skip
        real = service.latest_occurrences
        calls = {"n": 0}

        def taken_over(sess: Any, ids: Any) -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                with env.sessions() as other:
                    other.get(PriorityPolicy, row.id).status = "failed"  # type: ignore[union-attr]
                    other.commit()
            return real(sess, ids)

        monkeypatch.setattr(service, "latest_occurrences", taken_over)
        got = service.recompute(s, row.id, batch=2)
        assert got is not None and got.status == "failed" and got.processed == 2


def test_a_failing_recomputation_is_recorded(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    scan(env, mixed())

    def boom(*_: Any) -> Any:
        raise RuntimeError("disk full")

    monkeypatch.setattr(service, "latest_occurrences", boom)
    assert put(env).status_code == 202
    r = env.client.get(f"/v2/projects/{env.asset_id}/priority", headers=AUTH).json()
    assert r["recompute"]["status"] == "failed" and "disk full" in r["recompute"]["error"]
    assert r["locked"] is False  # a failed job does not hold the lock
    monkeypatch.undo()
    assert put(env).status_code == 202


def test_a_worker_gets_the_job_when_there_is_one(env: Env) -> None:
    queued: list[tuple[str, str]] = []
    env.client.app.state.bulwark.enqueue_priority = lambda pid, org: queued.append((pid, org))  # type: ignore[attr-defined]
    scan(env, mixed())
    r = put(env)
    assert r.status_code == 202 and r.json()["locked"] is True
    assert len(queued) == 1 and queued[0][1] == DEFAULT_ORG_ID
    assert put(env).status_code == 409


def test_new_scans_are_ranked_under_the_saved_policy(env: Env) -> None:
    put(env, context={"internet_facing": False})
    scan(env, mixed())  # internal only: x0.8 on every new issue
    rows = issue_rows(env)
    assert {i.priority_version for i in rows.values()} == {1}
    assert all(
        any(f.get("factor") == "internet_facing" for f in i.priority_factors or [])
        for i in rows.values()
    )


def test_runtime_confirmation_and_an_assistant_verdict_rescore_the_issue(env: Env) -> None:
    scan(env, mixed())
    put(env)
    with env.sessions() as s:
        issue = s.scalars(select(IssueRow).where(IssueRow.title == "High in app")).one()
        before, issue_id = issue.priority_score, issue.id
    with env.sessions() as s:
        repo.mark_issue_confirmed_at_runtime(s, issue_id, scan_id="dast-1")
        confirmed = s.get(IssueRow, issue_id)
        assert confirmed is not None and confirmed.priority_score == round(before * 1.25)  # type: ignore[operator]
        repo.set_assistant_verdict(s, issue_id, verdict="likely_false_positive", confidence="high",
                                   rationale="r", lines=[], model="m")  # fmt: skip
        doubted = s.get(IssueRow, issue_id)
        assert doubted is not None
        assert doubted.priority_score == round(round(before * 1.25) * 0.6)  # type: ignore[operator]
        assert {f["factor"] for f in doubted.priority_factors or []} >= {"runtime", "assistant"}


def test_the_preview_shows_the_reordering_and_saves_nothing(env: Env) -> None:
    scan(env, mixed())
    before_rows = {k: (v.priority_score, v.priority_version) for k, v in issue_rows(env).items()}
    r = env.client.post(
        f"/v2/projects/{env.asset_id}/priority/preview",
        json={"weights": _w(path=3, severity=0), "context": None}, headers=AUTH,
    )  # fmt: skip
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["open_issues"] == 5 and p["current_version"] == 0
    top = {x["title"]: x for x in p["top"]}
    assert top["Critical in tests"]["after"]["rank"] == 5
    assert top["Critical in tests"]["before"]["rank"] < 5
    assert p["moved"] >= 2 and p["dropped"] == []
    assert sum(p["bands_before"].values()) == sum(p["bands_after"].values()) == 5
    # nothing saved
    assert {
        k: (v.priority_score, v.priority_version) for k, v in issue_rows(env).items()
    } == before_rows
    with env.sessions() as s:
        assert s.scalar(select(func.count()).select_from(PriorityPolicy)) == 0


def test_the_preview_lists_what_drops_out_of_the_top(env: Env) -> None:
    scan(env, mixed())
    with env.sessions() as s:
        p = service.preview(s, env.asset_id, _w(path=3), None, top=2)
    assert [x["after"]["rank"] for x in p["top"]] == [1, 2]
    assert len(p["dropped"]) == 1 and p["dropped"][0]["title"] == "Critical in tests"
    assert p["dropped"][0]["after"]["rank"] > 2


def test_the_preview_leaves_out_triaged_and_fixed_issues(env: Env) -> None:
    scan(env, mixed())
    with env.sessions() as s:
        rows = {i.title: i for i in s.scalars(select(IssueRow))}
        rows["Low in app"].triage_status = "not_a_risk"
        rows["Medium in app"].state = "fixed"
        s.commit()
        p = service.preview(s, env.asset_id, STARTER, None)
    assert p["open_issues"] == 3


def test_errors_name_the_field_and_another_org_sees_nothing(env: Env) -> None:
    bad = put(env, weights={"severity": 9})
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "weights.severity"
    bad = env.client.post(f"/v2/projects/{env.asset_id}/priority/preview",
                          json={"weights": STARTER, "context": {"criticality": "x"}}, headers=AUTH)  # fmt: skip
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "context.criticality"
    other = {**AUTH, "X-Bulwark-Org": OTHER_ORG}
    url = f"/v2/projects/{env.asset_id}/priority"
    assert env.client.get(url, headers=other).status_code == 404
    assert env.client.put(url, json={"weights": STARTER}, headers=other).status_code == 404
    assert (
        env.client.post(f"{url}/preview", json={"weights": STARTER}, headers=other).status_code
        == 404
    )
    assert env.client.get("/v2/projects/not-a-uuid/priority", headers=AUTH).status_code == 404


def test_a_promoted_hypothesis_gets_a_risk_score_and_a_priority(env: Env) -> None:
    from core.persistence.models import HypothesisRow

    scan(env, mixed())
    with env.sessions() as s:
        h = HypothesisRow(
            asset_id=env.asset_id, model="m", route_method="GET", route_path="/admin", file="app/admin.py", line=3,
            snippet="def admin(): ...", evidence="no check", suggested_check="require_admin",
            confidence="high", status="open",
        )  # fmt: skip
        s.add(h)
        s.commit()
        issue = repo.promote_hypothesis(s, h.id, actor="a")
        assert issue.priority_score is not None and issue.priority_version == 0
        stored = s.scalar(
            select(func.max(FindingRow.risk_score)).where(FindingRow.issue_id == issue.id)
        )
        assert stored == issue.priority_score


# --- SLA by priority band -------------------------------------------------------------------------

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
BY_PRIORITY = Policy(True, "priority", parse_bands(STARTER_BY_PRIORITY, "priority"))


def test_an_sla_by_priority_band_keys_on_the_band() -> None:
    args: dict[str, Any] = {
        "severity": "LOW", "state": "open", "first_seen_at": NOW - timedelta(days=8),
        "sla_started_at": None, "fixed_at": None, "triage_status": "open",
        "triage_expires_at": None, "now": NOW,
    }  # fmt: skip
    assert evaluate(BY_PRIORITY, priority_band="P1", **args).state == "breached"  # 7 days
    assert evaluate(BY_PRIORITY, priority_band="P2", **args).state == "on_track"
    assert evaluate(BY_PRIORITY, priority_band=None, **args).state == "none"


def test_priority_bands_are_validated() -> None:
    with pytest.raises(Exception) as caught:
        parse_bands({"HIGH": {"days": 3}}, "priority")
    assert "unknown priority band" in str(caught.value)
    assert set(parse_bands({"p1": {"days": 3, "warn": 1}}, "priority")) == {"P1", "P2", "P3", "P4"}


def test_the_sla_api_saves_a_priority_basis_and_filters_by_it(env: Env) -> None:
    scan(env, mixed())
    with env.sessions() as s:
        for issue in s.scalars(select(IssueRow)):
            issue.first_seen_at = datetime.now(timezone.utc) - timedelta(days=10)
        s.commit()
    r = env.client.put(
        f"/v2/projects/{env.asset_id}/sla",
        json={"enabled": True, "basis": "priority", "bands": STARTER_BY_PRIORITY}, headers=AUTH,
    )  # fmt: skip
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["basis"] == "priority" and set(body["bands"]) == {"P1", "P2", "P3", "P4"}
    assert body["history"][0]["basis"] == "priority" and "P1" in body["starter_by_priority"]
    p1 = {i["title"] for i in issues(env, priority="P1")}
    breached = {i["title"] for i in issues(env, sla="breached")}
    assert breached == p1 and p1  # P1 has 7 days; 10 days old: breached. P2 and lower: 30+.
    with env.sessions() as s:
        policy = sla_service.policy_for(s, env.asset_id)
        for issue in s.scalars(select(IssueRow)):
            want = sla_service.status_of(policy, issue).state
            got = s.scalar(
                select(func.count())
                .select_from(IssueRow)
                .where(
                    IssueRow.id == issue.id,
                    sla_service.clause(policy, [want], datetime.now(timezone.utc)),
                )
            )
            assert got == 1, (issue.title, issue.priority_band, want)
    bad = env.client.put(f"/v2/projects/{env.asset_id}/sla",
                         json={"enabled": True, "basis": "risk", "bands": {}}, headers=AUTH)  # fmt: skip
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "basis"
