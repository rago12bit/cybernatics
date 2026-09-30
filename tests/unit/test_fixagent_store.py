"""Persistence for one verified-fix run (plan §21.2) -- against real SQLite, via the `sessions`
fixture every other persistence test in this suite already shares (tests/conftest.py)."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.fixagent import store
from core.persistence import repo
from core.persistence.models import Asset, IssueRow


def _issue(s: Session) -> str:
    asset = Asset(org_id="org-a", source_type="git", key="k", label="L")
    s.add(asset)
    s.commit()
    issue = IssueRow(
        asset_id=asset.id, fingerprint="fp1", state="open", category="sast", severity="HIGH",
        path="a.py", title="t", triage_status="open",
    )  # fmt: skip
    s.add(issue)
    s.commit()
    return issue.id


def test_create_and_get_run_round_trips(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        issue_id = _issue(s)
        run = store.create_run(s, "org-a", issue_id, "wf-1")
        assert run.status == "running" and run.attempts == 0 and run.verification_record == []
        fetched = store.get_run(s, run.id, org_id="org-a")
        assert fetched is not None and fetched.workflow_id == "wf-1"


def test_get_run_is_org_scoped(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        issue_id = _issue(s)
        run = store.create_run(s, "org-a", issue_id, "wf-2")
        assert store.get_run(s, run.id, org_id="org-b") is None
        assert store.get_run(s, run.id, org_id="org-a") is not None


def test_get_run_by_workflow_id_needs_no_org(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        issue_id = _issue(s)
        store.create_run(s, "org-a", issue_id, "wf-3")
        found = store.get_run_by_workflow_id(s, "wf-3")
        assert found is not None and found.issue_id == issue_id
        assert store.get_run_by_workflow_id(s, "wf-nonexistent") is None


def test_latest_run_for_issue_picks_the_most_recent(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        issue_id = _issue(s)
        first = store.create_run(s, "org-a", issue_id, "wf-old")
        second = store.create_run(s, "org-a", issue_id, "wf-new")
        latest = store.latest_run_for_issue(s, issue_id, org_id="org-a")
        assert latest is not None and latest.id == second.id
        assert first.id != second.id


def test_count_running_for_org_excludes_terminal_statuses(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        issue_id = _issue(s)
        r1 = store.create_run(s, "org-a", issue_id, "wf-a")
        r2 = store.create_run(s, "org-a", issue_id, "wf-b")
        store.create_run(s, "org-a", issue_id, "wf-c")
        assert store.count_running_for_org(s, "org-a") == 3
        store.update_run(s, r1, status="opened_pr")
        store.update_run(s, r2, status="failed")
        assert store.count_running_for_org(s, "org-a") == 1


def test_update_run_persists_every_field_and_bumps_updated_at(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        issue_id = _issue(s)
        run = store.create_run(s, "org-a", issue_id, "wf-d")
        before = run.updated_at
        store.update_run(
            s, run, status="awaiting_approval",
            latest_patch={"explanation": "x", "patch": "p", "confidence": "high"},
        )  # fmt: skip
        assert run.status == "awaiting_approval" and run.latest_patch["confidence"] == "high"
        assert run.updated_at >= before


def test_baseline_fingerprints_for_reads_only_that_path_in_that_scan(
    sessions: sessionmaker[Session],
) -> None:
    from core.models import Category, Finding, Location, Taxonomy

    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref="u", source_label="u", tools=["bandit"]
        ).id
        f1 = Finding("f1", "t1", "d", Location("a.py", 1, 1, "x"), Taxonomy(Category.SAST))
        f1.fingerprint = "fp-a"
        f2 = Finding("f2", "t2", "d", Location("b.py", 1, 1, "x"), Taxonomy(Category.SAST))
        f2.fingerprint = "fp-b"
        repo.add_findings(s, sid, [f1, f2])
        baseline = store.baseline_fingerprints_for(s, sid, "a.py")
        assert baseline == ["fp-a"]
