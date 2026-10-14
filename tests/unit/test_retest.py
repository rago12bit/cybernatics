"""Retests (Week 64, plan §43.3): a developer marks an Issue ready, a tester confirms it fixed or
reproduces it; for a scanner's Issue the next scan or upload decides; a targeted retest re-runs only
the one rule against the one file -- or the one DAST template against the one URL."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from core.models import Severity
from core.persistence import repo
from core.persistence.models import AuditEntry, IssueRow, OutboxEvent, RetestRun, Scan
from core.retest import service, targeted
from core.scan import ToolOutcome
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_api import AUTH
from tests.unit.test_api_ingest import (
    OTHER_ORG,
    SARIF,
    Env,
    env,  # noqa: F401  (the fixture)
)
from tests.unit.test_engagements import create, manual
from tests.unit.test_sla import finding, scan

OTHER = {**AUTH, "X-Bulwark-Org": OTHER_ORG}


def issues_by_title(env: Env) -> dict[str, IssueRow]:
    with env.sessions() as s:
        return {
            i.title: i for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id))
        }


def step(env: Env, issue_id: str, action: str, note: str | None = None, headers: Any = AUTH) -> Any:
    return env.client.post(f"/v2/issues/{issue_id}/retest", json={"action": action, "note": note},
                           headers=headers)  # fmt: skip


def history(env: Env, issue_id: str) -> list[str]:
    r = env.client.get(f"/assets/{env.asset_id}/issues/{issue_id}/history", headers=AUTH)
    return [e["label"] for e in r.json()]


def active_titles(env: Env) -> set[str]:
    r = env.client.get(f"/assets/{env.asset_id}/issues", headers=AUTH).json()
    return {i["title"] for i in r["items"]}


# --- people decide ----------------------------------------------------------------------------------


def test_ready_for_retest_then_confirmed_fixed(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.LOW)])
    issue = issues_by_title(env)["Problem 1"]
    r = step(env, issue.id, "request", "Fixed in #412")
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["note"], body["requested_by"]) == ("requested", "Fixed in #412",
                                                                     "shared-token")  # fmt: skip
    listed = env.client.get(f"/assets/{env.asset_id}/issues", headers=AUTH).json()["items"]
    assert {i["title"]: i["issue"]["retest_status"] for i in listed}["Problem 1"] == "requested"
    done = step(env, issue.id, "confirm_fixed", "Could not reproduce on build 2.3.1").json()
    assert (done["status"], done["state"]) == ("passed", "fixed")
    assert "Problem 1" not in active_titles(env)
    labels = history(env, issue.id)
    assert labels.index("Marked ready for retest") < labels.index("Retest passed: confirmed fixed")
    with env.sessions() as s:
        events = [e.event_type for e in s.scalars(select(OutboxEvent).where(
            OutboxEvent.event_type.like("issue.retest%")))]  # fmt: skip
        assert events == ["issue.retest_requested", "issue.retest_passed"]


def test_reproducing_needs_a_note_and_keeps_it_open(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    issue = issues_by_title(env)["Problem 1"]
    step(env, issue.id, "request")
    bad = step(env, issue.id, "reproduced", "  ")
    assert bad.status_code == 422 and bad.json()["detail"]["field"] == "note"
    r = step(env, issue.id, "reproduced", "Still returns another user's order").json()
    assert (r["status"], r["state"], r["note"]) == ("failed", "new",
                                                    "Still returns another user's order")  # fmt: skip
    assert "Problem 1" in active_titles(env)
    assert step(env, issue.id, "request").json()["status"] == "requested"  # ask again after a fix
    assert step(env, issue.id, "cancel").json()["status"] is None


@pytest.mark.parametrize(
    ("first", "then"),
    [(None, "confirm_fixed"), (None, "reproduced"), (None, "cancel"), ("request", "request")],
)
def test_steps_out_of_order_are_refused(env: Env, first: str | None, then: str) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    issue = issues_by_title(env)["Problem 1"]
    if first:
        step(env, issue.id, first)
    r = step(env, issue.id, then, "note")
    assert r.status_code == 409 and r.json()["detail"]["field"] == "action"


def test_a_fixed_issue_cannot_be_marked_and_another_org_sees_nothing(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH)])
    scan(env, [finding(2, Severity.HIGH)])  # Problem 1 fixed by the scan
    issue = issues_by_title(env)["Problem 1"]
    assert step(env, issue.id, "request").status_code == 409
    assert env.client.get(f"/v2/issues/{issue.id}/retest", headers=OTHER).status_code == 404
    assert step(env, issue.id, "request", headers=OTHER).status_code == 404
    assert step(env, "not-an-id", "request").status_code == 404


def test_a_confirmed_fix_reopens_when_a_scan_reports_it_again(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    issue = issues_by_title(env)["Problem 1"]
    step(env, issue.id, "request")
    step(env, issue.id, "confirm_fixed")
    scan(env, [finding(1, Severity.HIGH)])
    assert issues_by_title(env)["Problem 1"].state == "reintroduced"
    assert "Problem 1" in active_titles(env)


# --- the next scan or upload is the retest ----------------------------------------------------------


def test_the_next_scan_decides_a_requested_retest(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH), finding(3, Severity.LOW)])
    by = issues_by_title(env)
    for t in ("Problem 1", "Problem 2"):
        step(env, by[t].id, "request")
    scan(env, [finding(1, Severity.HIGH), finding(3, Severity.LOW)])  # 2 is gone, 1 is not
    after = issues_by_title(env)
    assert (after["Problem 1"].retest_status, after["Problem 1"].state) == ("failed", "open")
    assert after["Problem 3"].state == "open"
    assert (after["Problem 2"].retest_status, after["Problem 2"].state) == ("passed", "fixed")
    assert after["Problem 3"].retest_status is None  # nobody asked
    assert after["Problem 1"].retest_note.startswith("Still reported by the scan of")  # type: ignore[union-attr]
    labels = history(env, by["Problem 2"].id)
    assert any(x.startswith("Retest passed: No longer reported by the scan of") for x in labels)


def test_an_upload_decides_it_and_undoing_the_upload_undoes_that(env: Env) -> None:
    eid = create(env, status="in_progress")["id"]
    first = env.import_and_get(SARIF, engagement=eid, test="Burp Suite")
    assert first["counts"]["new"] == 3
    with env.sessions() as s:
        issue = s.scalars(select(IssueRow).where(IssueRow.asset_id == env.asset_id)).first()
        assert issue is not None
        issue_id = issue.id
    step(env, issue_id, "request")
    empty = (
        b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}]}'
    )
    second = env.import_and_get(empty, engagement=eid, test="Burp Suite", parser="sarif")
    assert second["counts"]["closed"] == 3, second
    with env.sessions() as s:
        row = s.get(IssueRow, issue_id)
        assert row is not None and (row.retest_status, row.state) == ("passed", "fixed")
        assert row.retest_note == "No longer reported by the upload into Burp Suite."
    undo = env.client.post(f"/v2/imports/{second['id']}/revert", headers=AUTH)
    assert undo.status_code == 200, undo.text
    with env.sessions() as s:
        row = s.get(IssueRow, issue_id)
        assert row is not None and (row.retest_status, row.state) == ("requested", "new")


def test_a_manual_finding_is_never_decided_by_a_scan(env: Env) -> None:
    eid = create(env, status="in_progress")["id"]
    m = manual(env, eid)
    issue_id = m["manual"]["issue_id"]
    step(env, issue_id, "request")
    scan(env, [finding(9, Severity.LOW)])  # a native scan never saw it: says nothing about it
    with env.sessions() as s:
        row = s.get(IssueRow, issue_id)
        assert row is not None and row.retest_status == "requested"
    offer = env.client.get(f"/v2/issues/{issue_id}/retest", headers=AUTH).json()["targeted"]
    assert offer["available"] is False and "tester retests it" in offer["reason"]


# --- targeted retests -------------------------------------------------------------------------------


def checkout(files: dict[str, str]) -> Any:
    @contextmanager
    def materialize(source: str) -> Iterator[Path]:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            for rel, text in files.items():
                p = Path(tmp) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            yield Path(tmp)

    return materialize


class FakeSemgrep:
    """Fires rule-1 on any file containing 'bad' -- in the directory it is handed."""

    def __init__(self, status: str = "ok") -> None:
        self.status = status
        self.seen: list[list[str]] = []

    def __call__(self, tool: str, target: Path, ctx: Any) -> ToolOutcome:
        files = sorted(str(p.relative_to(target)) for p in target.rglob("*") if p.is_file())
        self.seen.append(files)
        if self.status != "ok":
            return ToolOutcome(tool, self.status, error="container exited 2")
        hits = []
        for rel in files:
            if "bad" in (target / rel).read_text():
                f = finding(1, Severity.HIGH)
                hits.append(replace(f, location=replace(f.location, path=rel)))
        return ToolOutcome(tool, "ok", findings=hits)


def _issue(env: Env, title: str = "Problem 1") -> IssueRow:
    return issues_by_title(env)[title]


def test_a_targeted_retest_offers_the_one_rule_and_file(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    with env.sessions() as s:
        o = targeted.offer(s, _issue(env))
    assert o.target is not None
    assert (o.target.kind, o.target.tool, o.target.rule, o.target.location) == (
        "rule", "semgrep", "rule-1", "app/m1.py")  # fmt: skip
    assert o.target.source_ref == "https://example.com/a/b"


@pytest.mark.parametrize(
    ("files", "status", "result", "retest", "state"),
    [
        ({"app/m1.py": "x = bad()", "app/other.py": "bad too"}, "ok", "still_present", "failed", "new"),
        ({"app/m1.py": "x = good()", "app/other.py": "bad"}, "ok", "gone", "passed", "fixed"),
        ({"app/other.py": "bad"}, "ok", "gone", "passed", "fixed"),  # the file was deleted
        ({"app/m1.py": "x = bad()"}, "error", None, "requested", "new"),  # the check failed
    ],
)  # fmt: skip
def test_a_targeted_retest_runs_only_that_rule_on_that_file(
    env: Env, files: dict[str, str], status: str, result: str | None, retest: str, state: str
) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    issue = _issue(env)
    tool = FakeSemgrep(status)
    with env.sessions() as s:
        run = targeted.start(s, s.get(IssueRow, issue.id), actor="tester")  # type: ignore[arg-type]
        done = targeted.run(s, run.id, materialize=checkout(files), executor=tool)
        assert done is not None and done.result == result
        assert done.status == ("failed" if status != "ok" else "done")
        row = s.get(IssueRow, issue.id)
        assert row is not None and (row.retest_status, row.state) == (retest, state)
    if "app/m1.py" in files:
        assert tool.seen == [["app/m1.py"]]  # only that file, at its own path
    else:
        assert tool.seen == []  # nothing to run: the file is gone
    with env.sessions() as s:
        actions = [a.action for a in s.scalars(select(AuditEntry))]
        assert "issue.retest.targeted" in actions and "issue.retest.requested" in actions


def test_a_targeted_retest_never_leaves_its_checkout(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    with env.sessions() as s:
        issue = s.get(IssueRow, _issue(env).id)
        run = targeted.start(s, issue, actor="t")  # type: ignore[arg-type]
        run.location = "../../etc/passwd"
        s.commit()
        done = targeted.run(
            s, run.id, materialize=checkout({"a.py": "bad"}), executor=FakeSemgrep()
        )
        assert done is not None and done.status == "failed" and "outside" in (done.detail or "")


def test_one_targeted_retest_at_a_time_and_redelivery_is_harmless(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    with env.sessions() as s:
        issue = s.get(IssueRow, _issue(env).id)
        run = targeted.start(s, issue, actor="t")  # type: ignore[arg-type]
        with pytest.raises(service.RetestError):
            targeted.start(s, issue, actor="t")  # type: ignore[arg-type]
        targeted.run(s, run.id, materialize=checkout({"app/m1.py": "bad"}), executor=FakeSemgrep())
        again = targeted.run(s, run.id, materialize=checkout({}), executor=FakeSemgrep())
        assert again is not None and again.result == "still_present"


def test_the_api_runs_a_targeted_retest_in_the_background(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    issue = _issue(env)
    monkeypatch.setattr(targeted, "_default_materialize", checkout({"app/m1.py": "fine now"}))
    monkeypatch.setattr(targeted, "_default_executor", FakeSemgrep())
    r = env.client.post(f"/v2/issues/{issue.id}/retest/run", headers=AUTH)
    assert r.status_code == 202, r.text
    after = env.client.get(f"/v2/issues/{issue.id}/retest", headers=AUTH).json()
    assert after["status"] == "passed" and after["state"] == "fixed"
    assert after["runs"][0]["result"] == "gone"
    assert after["runs"][0]["detail"] == "semgrep rule rule-1 no longer fires on app/m1.py."
    assert after["targeted"]["available"] is False  # it is fixed now
    queued: list[tuple[str, str]] = []
    env.client.app.state.bulwark.enqueue_retest = lambda rid, org: queued.append((rid, org))  # type: ignore[attr-defined]
    scan(env, [finding(2, Severity.HIGH)])
    other = _issue(env, "Problem 2")
    assert env.client.post(f"/v2/issues/{other.id}/retest/run", headers=AUTH).status_code == 202
    assert len(queued) == 1 and queued[0][1] == DEFAULT_ORG_ID


def test_a_dast_issue_retests_its_one_template_against_its_url(env: Env) -> None:
    from core.models import Category, Evidence, Finding, Location, Scoring, Taxonomy

    with env.sessions() as s:
        web, _ = repo.register_web_asset(s, domain="shop.example", method="dns_txt")
        sc = repo.create_scan(s, source_type="web", source_ref="https://shop.example",
                              source_label="shop.example", tools=["nuclei"])  # fmt: skip
        sc.asset_id, sc.dast_mode = web.id, "active"
        s.commit()
        f = Finding(
            id="nuclei:x", title="Exposed .git", description="d",
            location=Location("", 0, 0, route="/.git/config", host="shop.example"),
            taxonomy=Taxonomy(Category.DAST), scoring=Scoring(normalized_severity=Severity.HIGH),
            evidence=Evidence(reported_by=["nuclei"], rule_ids={"nuclei": ["git-config"]}),
            fingerprint="dast-1",
        )  # fmt: skip
        sync = repo.sync_issues_for_scan(s, sc.id, [f])
        repo.add_findings(s, sc.id, [f], sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        issue = s.scalars(select(IssueRow).where(IssueRow.asset_id == web.id)).one()
        o = targeted.offer(s, issue)
        assert o.target is not None

        assert (o.target.kind, o.target.rule, o.target.location) == (
            "dast", "git-config", "https://shop.example/.git/config")  # fmt: skip
        class Check:
            def __init__(self, ok: bool) -> None:
                self.ok, self.error = ok, None if ok else "TXT record not found"

        # ownership no longer verifies: nothing is sent to the target
        calls: list[str] = []

        def runner(url: str, t: Any) -> list[Any]:
            calls.append(url)
            return []

        run = targeted.start(s, issue, actor="t")
        done = targeted.run(s, run.id, dast=runner, verify=lambda *a, **k: Check(False))
        assert done is not None and done.status == "failed"
        assert done.detail == "Ownership verification failed: TXT record not found" and calls == []

        run2 = targeted.start(s, issue, actor="t")
        done2 = targeted.run(s, run2.id, dast=runner, verify=lambda *a, **k: Check(True))
        assert done2 is not None and done2.result == "gone"
        assert calls == ["https://shop.example/.git/config"]
        assert s.get(IssueRow, issue.id).retest_status == "passed"  # type: ignore[union-attr]


def test_a_retest_run_is_not_a_scan(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH)])
    before = issues_by_title(env)
    with env.sessions() as s:
        n = len(s.scalars(select(Scan)).all())
        run = targeted.start(s, s.get(IssueRow, before["Problem 1"].id), actor="t")  # type: ignore[arg-type]
        targeted.run(s, run.id, materialize=checkout({"app/m1.py": "bad"}), executor=FakeSemgrep())
        assert len(s.scalars(select(Scan)).all()) == n
        assert s.scalars(select(RetestRun)).one().result == "still_present"


def test_a_confirmed_fix_leaves_the_project_overview_queue(env: Env) -> None:
    scan(env, [finding(1, Severity.HIGH), finding(2, Severity.HIGH)])
    issue = issues_by_title(env)["Problem 1"]
    before = env.client.get(f"/assets/{env.asset_id}/overview", headers=AUTH).json()
    assert {f["title"] for f in before["fix_first"]} == {"Problem 1", "Problem 2"}
    step(env, issue.id, "request")
    step(env, issue.id, "confirm_fixed")
    after = env.client.get(f"/assets/{env.asset_id}/overview", headers=AUTH).json()
    assert [f["title"] for f in after["fix_first"]] == ["Problem 2"]
    assert after["more_at_lower_risk"] == 0


def test_a_dast_retest_whose_scanner_fails_does_not_read_as_fixed(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Until 2026-10-14 `run_nuclei` ignored Nuclei's exit code: a template renamed in a template
    update ("no templates provided for scan", exit 1), a missing image or a crash returned no
    findings, and this retest decided the Issue was fixed. Now the run fails and the Issue stays."""
    import subprocess
    import sys

    from core.dast.adapters import nuclei
    from core.models import Category, Evidence, Finding, Location, Scoring, Taxonomy

    with env.sessions() as s:
        web, _ = repo.register_web_asset(s, domain="shop.example", method="dns_txt")
        sc = repo.create_scan(s, source_type="web", source_ref="https://shop.example",
                              source_label="shop.example", tools=["nuclei"])  # fmt: skip
        sc.asset_id, sc.dast_mode = web.id, "active"
        s.commit()
        f = Finding(
            id="nuclei:x", title="Exposed .git", description="d",
            location=Location("", 0, 0, route="/.git/config", host="shop.example"),
            taxonomy=Taxonomy(Category.DAST), scoring=Scoring(normalized_severity=Severity.HIGH),
            evidence=Evidence(reported_by=["nuclei"], rule_ids={"nuclei": ["git-config"]}),
            fingerprint="dast-1",
        )  # fmt: skip
        sync = repo.sync_issues_for_scan(s, sc.id, [f])
        repo.add_findings(s, sc.id, [f], sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        issue = s.scalars(select(IssueRow).where(IssueRow.asset_id == web.id)).one()

        failing = ("import sys; sys.stderr.write('[FTL] Could not run nuclei: no templates "
                   "provided for scan'); sys.exit(1)")  # fmt: skip
        real_popen = subprocess.Popen
        monkeypatch.setattr(nuclei.subprocess, "Popen",
                            lambda argv, **kw: real_popen([sys.executable, "-c", failing], **kw))  # fmt: skip

        class Verified:
            ok, error = True, None

        run = targeted.start(s, issue, actor="t")
        done = targeted.run(s, run.id, verify=lambda *a, **k: Verified(),
                            dast=lambda url, t: nuclei.run_nuclei(url, template_ids=(t.rule,)))  # fmt: skip
        assert done is not None and (done.status, done.result) == ("failed", None)
        assert "no templates provided for scan" in (done.detail or "")
        assert s.get(IssueRow, issue.id).retest_status != "passed"  # type: ignore[union-attr]
