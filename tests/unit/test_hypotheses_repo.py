"""core.persistence.repo's Hypotheses-lane functions (plan §21.4): create/list/get/dismiss/promote."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID


def _seed_asset_with_a_completed_scan(sessions: sessionmaker[Session]) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git", source_label="acme/x",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        repo.finish_scan(s, scan.id, "completed")
        asset_id = scan.asset_id
    assert asset_id is not None
    return asset_id


def _create(sessions: sessionmaker[Session], asset_id: str) -> str:
    with sessions() as s:
        row = repo.create_hypothesis(
            s, asset_id, method="DELETE", path="/users/<id>", file="app.py", line=20,
            evidence="No auth decorator, unlike the sibling route.",
            suggested_check="Call it without a session and see if it still works.",
            confidence="medium", snippet="def delete_user(id): ...", model="fake-model-1",
        )  # fmt: skip
        return row.id


def test_create_and_list_round_trip(sessions: sessionmaker[Session]) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    hyp_id = _create(sessions, asset_id)
    with sessions() as s:
        items = repo.list_hypotheses(s, asset_id)
        assert len(items) == 1 and items[0].id == hyp_id and items[0].status == "open"
        assert repo.get_hypothesis(s, hyp_id) is not None


def test_list_filters_by_status(sessions: sessionmaker[Session]) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    hyp_id = _create(sessions, asset_id)
    with sessions() as s:
        repo.dismiss_hypothesis(s, hyp_id, actor="tester")
    with sessions() as s:
        assert len(repo.list_hypotheses(s, asset_id, status="open")) == 0
        assert len(repo.list_hypotheses(s, asset_id, status="dismissed")) == 1


def test_dismiss_is_final_not_reversible_via_dismiss_again(sessions: sessionmaker[Session]) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    hyp_id = _create(sessions, asset_id)
    with sessions() as s:
        repo.dismiss_hypothesis(s, hyp_id, actor="tester")
    with sessions() as s, pytest.raises(ValueError, match="already dismissed"):
        repo.dismiss_hypothesis(s, hyp_id, actor="tester")


def test_promote_creates_a_real_issue_with_llm_confirmed_source(
    sessions: sessionmaker[Session],
) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    hyp_id = _create(sessions, asset_id)
    with sessions() as s:
        issue = repo.promote_hypothesis(s, hyp_id, actor="tester")
        issue_id = issue.id
        assert issue.source == "llm-confirmed"
        assert issue.triage_status == "open"
        assert "Missing authorization check" in issue.title

    with sessions() as s:
        hyp = repo.get_hypothesis(s, hyp_id)
        assert hyp is not None and hyp.status == "promoted" and hyp.promoted_issue_id == issue_id
        # A real occurrence exists, so the promoted issue is visible through the normal issues path.
        scan = repo.latest_scan_for_asset(s, asset_id)
        assert scan is not None
        finding_doc = repo.get_issue_finding(s, issue_id, scan.id)
        assert finding_doc is not None
        assert finding_doc["scoring"]["risk_score"] is not None
        assert finding_doc["taxonomy"]["cwe"] == ["CWE-862"]


def test_promote_is_not_reversible_via_promote_again(sessions: sessionmaker[Session]) -> None:
    asset_id = _seed_asset_with_a_completed_scan(sessions)
    hyp_id = _create(sessions, asset_id)
    with sessions() as s:
        repo.promote_hypothesis(s, hyp_id, actor="tester")
    with sessions() as s, pytest.raises(ValueError, match="already promoted"):
        repo.promote_hypothesis(s, hyp_id, actor="tester")


def test_promote_does_not_touch_other_open_issues(sessions: sessionmaker[Session]) -> None:
    """The whole reason promotion is NOT core.issues.sync: reconciling a full scan's findings
    against history would read every other open issue as newly-fixed. Prove it doesn't."""
    from core.models import Category, Finding, Location, Taxonomy

    asset_id = _seed_asset_with_a_completed_scan(sessions)
    with sessions() as s:
        scan = repo.latest_scan_for_asset(s, asset_id)
        assert scan is not None
        f = Finding("f1", "t", "d", Location("a.py", 1, 1), Taxonomy(Category.SAST))
        result = repo.sync_issues_for_scan(s, scan.id, [f])
        repo.add_findings(s, scan.id, [f], issue_updates=result.updates)
        other_issue_id = next(u.issue_id for u in result.updates if u.finding_id == "f1")

    hyp_id = _create(sessions, asset_id)
    with sessions() as s:
        repo.promote_hypothesis(s, hyp_id, actor="tester")
    with sessions() as s:
        other = repo.get_issue(s, other_issue_id)
        assert other is not None and other.state != "fixed"
