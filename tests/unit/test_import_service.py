"""The ingest service (Week 54 task 4, ADR-0040): preview, apply, idempotency, revert, events, and
how an import and a native scan treat each other's Issues. SQLite; the Postgres/RLS behaviour is
covered by tests/integration/test_ingest_rls_docker.py and the live run noted in the week's doc."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.imports.service import (
    ImportRequestError,
    apply_import,
    preview_import,
    revert_latest_import,
)
from core.persistence import repo
from core.persistence.models import FindingRow, ImportRecord, IssueRow, Organization, Scan
from core.tenancy import DEFAULT_ORG_ID
from tests.unit.test_reimport import file_of

ORG = DEFAULT_ORG_ID


def digest(n: int) -> str:
    return f"{n:064x}"


def setup(s: Session, *tests: str) -> tuple[str, dict[str, str]]:
    """An org, an asset, one import-type engagement and the named Tests in it."""
    s.add(Organization(id=ORG, name="default"))
    s.commit()
    asset = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=ORG)
    eng = repo.create_engagement(
        s, org_id=ORG, asset_id=asset.id, name="Q3", engagement_type="import"
    )
    ids = {
        name: repo.get_or_create_engagement_test(s, org_id=ORG, engagement_id=eng.id, name=name).id
        for name in tests
    }
    return asset.id, ids


def do_import(s: Session, test_id: str, defects: set[int], n: int, **kw):
    return apply_import(
        s,
        org_id=ORG,
        test_id=test_id,
        findings=file_of(*sorted(defects)),
        parser="sarif",
        file_digest=digest(n),
        file_name=f"report-{n}.sarif",
        **kw,
    )


def issue_states(s: Session, asset_id: str) -> list[str]:
    return sorted(i.state for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id)))


def test_the_first_import_creates_issues_findings_a_record_and_events(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Nessus")
        result = do_import(s, t["Nessus"], {1, 2, 3}, 1)

        assert result.created
        rec = result.record
        assert (rec.new_count, rec.unchanged_count, rec.closed_count) == (3, 0, 0)
        assert rec.status == "applied" and rec.scan_id is not None
        scan = s.get(Scan, rec.scan_id)
        assert scan is not None and scan.source_type == "import" and scan.status == "completed"
        assert scan.tools == ["sarif"] and scan.asset_id == asset_id
        assert s.scalar(select(func.count()).select_from(FindingRow)) == 3
        assert issue_states(s, asset_id) == ["new", "new", "new"]
        kinds = sorted(e.event_type for e in repo.pending_outbox_events(s, ORG))
        assert kinds == ["issue.created"] * 3 + ["scan.completed"]


def test_the_same_file_twice_is_a_no_op_returning_the_original(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, t = setup(s, "Nessus")
        first = do_import(s, t["Nessus"], {1, 2}, 1)
        events_before = len(repo.pending_outbox_events(s, ORG))
        again = do_import(s, t["Nessus"], {1, 2}, 1)
        assert not again.created and again.record.id == first.record.id
        assert s.scalar(select(func.count()).select_from(ImportRecord)) == 1
        assert s.scalar(select(func.count()).select_from(Scan)) == 1
        assert len(repo.pending_outbox_events(s, ORG)) == events_before  # nothing announced twice


def test_dropping_a_defect_closes_its_issue_and_announces_it(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Nessus")
        do_import(s, t["Nessus"], {1, 2, 3}, 1)
        second = do_import(s, t["Nessus"], {1, 2}, 2)
        assert (second.record.unchanged_count, second.record.closed_count) == (2, 1)
        assert issue_states(s, asset_id) == ["fixed", "open", "open"]
        closed = [e for e in repo.pending_outbox_events(s, ORG) if e.event_type == "issue.closed"]
        assert len(closed) == 1 and closed[0].payload["source"] == "import"


def test_a_returning_defect_is_reopened(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Nessus")
        do_import(s, t["Nessus"], {1, 2}, 1)
        do_import(s, t["Nessus"], {1}, 2)
        third = do_import(s, t["Nessus"], {1, 2}, 3)
        assert third.record.reopened_count == 1 and third.record.new_count == 0
        assert issue_states(s, asset_id) == ["open", "reintroduced"]
        assert any(e.event_type == "issue.reopened" for e in repo.pending_outbox_events(s, ORG))


def test_preview_changes_nothing_and_matches_what_the_import_then_records(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Nessus")
        steps = [{1, 2, 3}, {2, 3, 4}, {1, 4}, {1, 2, 3, 4}]
        for n, defects in enumerate(steps, start=1):
            before = (
                s.scalar(select(func.count()).select_from(Scan)),
                s.scalar(select(func.count()).select_from(IssueRow)),
                len(repo.pending_outbox_events(s, ORG)),
                issue_states(s, asset_id),
            )
            preview = preview_import(
                s, org_id=ORG, test_id=t["Nessus"], findings=file_of(*sorted(defects))
            )
            after_preview = (
                s.scalar(select(func.count()).select_from(Scan)),
                s.scalar(select(func.count()).select_from(IssueRow)),
                len(repo.pending_outbox_events(s, ORG)),
                issue_states(s, asset_id),
            )
            assert after_preview == before, "a preview must write nothing"

            rec = do_import(s, t["Nessus"], defects, n).record
            applied = {
                "new": rec.new_count, "unchanged": rec.unchanged_count,
                "reopened": rec.reopened_count, "closed": rec.closed_count,
                "detached": rec.detached_count, "held": rec.held_count,
            }  # fmt: skip
            assert preview.counts == applied  # the screen's numbers are the import's numbers


def test_revert_restores_the_issues_and_removes_the_snapshot(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Nessus")
        first = do_import(s, t["Nessus"], {1, 2, 3}, 1)
        do_import(s, t["Nessus"], {1, 4}, 2)  # closes 2 and 3, creates 4, keeps 1
        assert issue_states(s, asset_id) == ["fixed", "fixed", "new", "open"]  # sorted

        out = revert_latest_import(s, org_id=ORG, test_id=t["Nessus"])
        assert (out.restored, out.deleted, out.skipped) == (3, 1, 0)
        assert out.record.status == "reverted" and out.record.scan_id is None
        # Back to exactly the state after the first import: 2 and 3 live again, 4 gone, 1 as before.
        assert issue_states(s, asset_id) == ["new", "new", "new"]
        latest = repo.latest_applied_import(s, t["Nessus"], ORG)
        assert latest is not None and latest.id == first.record.id  # the Test's snapshot is back
        assert s.scalar(select(func.count()).select_from(Scan)) == 1
        assert s.scalar(select(func.count()).select_from(FindingRow)) == 3
        assert any(e.event_type == "import.reverted" for e in repo.pending_outbox_events(s, ORG))


def test_after_a_revert_the_next_import_compares_against_the_restored_snapshot(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, t = setup(s, "Nessus")
        do_import(s, t["Nessus"], {1, 2}, 1)
        do_import(s, t["Nessus"], {1}, 2)  # closes 2
        revert_latest_import(s, org_id=ORG, test_id=t["Nessus"])
        # "Last quarter's file by mistake" is gone; the real next report is judged against report 1.
        nxt = do_import(s, t["Nessus"], {1, 2}, 3)
        assert (nxt.record.new_count, nxt.record.unchanged_count) == (0, 2)
        assert nxt.record.closed_count == 0 and nxt.record.reopened_count == 0


def test_revert_leaves_alone_an_issue_something_else_changed_since(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Nessus")
        do_import(s, t["Nessus"], {1}, 1)
        do_import(s, t["Nessus"], {1, 2}, 2)  # creates issue 2
        created = s.scalars(select(IssueRow).where(IssueRow.state == "new")).one()
        created.state = "fixed"  # e.g. a later scan or a person changed it
        s.commit()
        out = revert_latest_import(s, org_id=ORG, test_id=t["Nessus"])
        assert out.skipped >= 1
        assert s.get(IssueRow, created.id) is not None  # not deleted: it is no longer the import's
        assert s.get(IssueRow, created.id).state == "fixed"  # type: ignore[union-attr]


def test_only_the_latest_import_can_be_reverted_and_an_empty_test_has_none(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, t = setup(s, "Nessus")
        with pytest.raises(ImportRequestError, match="no applied import"):
            revert_latest_import(s, org_id=ORG, test_id=t["Nessus"])
        do_import(s, t["Nessus"], {1}, 1)
        revert_latest_import(s, org_id=ORG, test_id=t["Nessus"])
        with pytest.raises(ImportRequestError, match="no applied import"):
            revert_latest_import(s, org_id=ORG, test_id=t["Nessus"])  # already reverted


def test_unknown_tests_other_orgs_tests_and_bad_scopes_are_refused(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _, t = setup(s, "Nessus")
        with pytest.raises(ImportRequestError, match="not found"):
            preview_import(s, org_id=ORG, test_id="nope", findings=[])
        with pytest.raises(ImportRequestError, match="not found"):
            preview_import(s, org_id="someone-else", test_id=t["Nessus"], findings=[])
        with pytest.raises(ImportRequestError, match="scope"):
            do_import(s, t["Nessus"], {1}, 1, scope="galaxy")
        # A refused import leaves nothing behind.
        assert s.scalar(select(func.count()).select_from(Scan)) == 0
        assert s.scalar(select(func.count()).select_from(IssueRow)) == 0


def test_close_missing_off_adds_without_closing(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Nessus")
        do_import(s, t["Nessus"], {1, 2, 3}, 1)
        second = do_import(s, t["Nessus"], {1}, 2, close_missing=False)
        assert second.record.closed_count == 0
        assert "fixed" not in issue_states(s, asset_id)


def test_one_tests_import_does_not_close_another_tests_issues(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Burp", "Nessus")
        do_import(s, t["Burp"], {10, 11}, 1)
        second = do_import(s, t["Nessus"], {1, 2}, 2)
        assert second.record.closed_count == 0
        assert "fixed" not in issue_states(s, asset_id)


def test_an_issue_another_test_still_reports_is_detached_not_closed(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Burp", "Nessus")
        do_import(s, t["Burp"], {1, 2}, 1)
        do_import(s, t["Nessus"], {1, 2}, 2)
        third = do_import(s, t["Nessus"], {1}, 3)  # Nessus drops 2; Burp still reports it
        assert (third.record.closed_count, third.record.detached_count) == (0, 1)
        assert "fixed" not in issue_states(s, asset_id)


def test_engagement_scope_reconciles_across_every_test_in_it(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Burp", "Nessus")
        do_import(s, t["Burp"], {10, 11}, 1)
        do_import(s, t["Nessus"], {1}, 2)
        # An engagement-wide import that reports only defect 1 closes what *either* Test reported
        # last time and this file no longer lists -- but only because Burp is inside the scope.
        wide = do_import(s, t["Nessus"], {1}, 3, scope="engagement")
        assert wide.record.closed_count == 2
        assert issue_states(s, asset_id).count("fixed") == 2


def _ci_scan(s: Session, defects: set[int]) -> str:
    """A completed native scan of the same asset whose findings were synced the way the worker does."""
    scan = repo.create_scan(
        s, source_type="git", source_ref="https://x", source_label="a/b", tools=["bandit"],
        org_id=ORG,
    )  # fmt: skip
    findings = file_of(*sorted(defects))
    result = repo.sync_issues_for_scan(s, scan.id, findings)
    repo.add_findings(s, scan.id, findings, result.updates)
    repo.finish_scan(s, scan.id, "completed")
    return scan.id


def test_a_native_scan_does_not_close_an_issue_an_import_still_reports(
    sessions: sessionmaker[Session],
) -> None:
    """A pen tester's file lists defect 2; the next CI scan no longer sees it. The scan has not
    shown it fixed, so it must stay open."""
    with sessions() as s:
        asset_id, t = setup(s, "Pentest")
        do_import(s, t["Pentest"], {1, 2}, 1)
        _ci_scan(s, {1})
        states = {
            i.title: i.state
            for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id))
        }
        assert states["defect 2"] != "fixed"


def test_a_native_scan_still_closes_what_nothing_else_reports(
    sessions: sessionmaker[Session],
) -> None:
    """The unchanged v2 behaviour: with no import involved, a scan that stops seeing an issue fixes it."""
    with sessions() as s:
        asset_id, _ = setup(s)
        _ci_scan(s, {1, 2})
        _ci_scan(s, {1})
        states = {
            i.title: i.state
            for i in s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id))
        }
        assert states["defect 2"] == "fixed" and states["defect 1"] == "open"


def test_an_import_does_not_close_an_issue_the_native_scan_still_reports(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Pentest")
        _ci_scan(s, {1, 2})
        do_import(s, t["Pentest"], {1, 2}, 1)
        third = do_import(s, t["Pentest"], {1}, 2)  # the file drops 2; CI still reports it
        assert (third.record.closed_count, third.record.detached_count) == (0, 1)
        assert "fixed" not in issue_states(s, asset_id)


def test_imports_are_never_the_latest_or_previous_scan_of_an_asset(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "Pentest")
        ci = _ci_scan(s, {1})
        do_import(s, t["Pentest"], {1, 2}, 1)  # newer than the CI scan
        latest = repo.latest_scan_for_asset(s, asset_id, org_id=ORG)
        assert latest is not None and latest.id == ci
        assert repo.previous_scan_for_asset(s, asset_id, latest, org_id=ORG) is None
