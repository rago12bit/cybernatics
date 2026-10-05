"""Previewing and applying a deduplication change against a database (Week 58, ADR-0042): the
preview writes nothing, the apply does exactly what the preview said, and nothing is lost on the way
-- occurrences, tickets, fix runs, and the triage decisions that must not hide an open Issue."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from core.correlation import correlate
from core.dedup.service import DedupError, StalePlan, apply_change, preview_change
from core.dedup.settings import current_settings, history
from core.imports.service import apply_import
from core.models import Finding
from core.persistence.models import (
    AuditEntry,
    ExternalIssueLinkRow,
    FindingRow,
    IssueRow,
    OutboxEvent,
    VerifiedFixRun,
)
from tests.unit.test_dedup_strategies import code
from tests.unit.test_import_service import ORG, digest, setup

SRC = "semgrep"


def load(*findings: Finding) -> list[Finding]:
    return correlate(list(findings))[0]


def do_import(s: Session, test_id: str, findings: list[Finding], n: int):
    return apply_import(
        s, org_id=ORG, test_id=test_id, findings=findings, parser=SRC,
        file_digest=digest(n), file_name=f"r{n}.sarif",
    )  # fmt: skip


def three_lines(s: Session, test_id: str) -> None:
    """One rule, one file, three structurally different lines: three Issues under the default."""
    do_import(
        s, test_id,
        load(code(line=10, snippet="a(x)"), code(line=20, snippet="b(x, y)"),
             code(line=30, snippet="c(x, y, z)")),
        1,
    )  # fmt: skip


def issues(s: Session, asset_id: str) -> list[IssueRow]:
    return list(s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id)))


def apply_it(s: Session, asset_id: str, strategy: str = "tool_id", **kw):
    p = preview_change(
        s, org_id=ORG, asset_id=asset_id, source=SRC, strategy=strategy, fields=kw.get("fields", ())
    )
    return apply_change(
        s, org_id=ORG, asset_id=asset_id, source=SRC, strategy=strategy,
        fields=kw.get("fields", ()), expected_digest=p.plan.digest, created_by="ana", note=kw.get("note"),
    )  # fmt: skip


def test_the_preview_says_what_would_happen_and_writes_nothing(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        before = ([(i.id, i.fingerprint) for i in issues(s, asset_id)],
                  s.scalar(select(func.count()).select_from(OutboxEvent)))  # fmt: skip
        p = preview_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="tool_id")
        d = p.to_dict()
        assert d["issues_before"] == 3 and d["issues_after"] == 1 and d["issues_merged_away"] == 2
        assert d["merge_groups"] == 1 and d["issues_split"] == 0
        assert (
            d["summary"]
            == "Switching semgrep to tool_id would merge 3 issues into 1 and split none"
        )
        assert d["from"] == {"strategy": "fingerprint_v2", "version": 0} and d["to"]["version"] == 1
        assert d["changes_anything"] and d["examples"][0]["kind"] == "merge"
        assert d["examples"][0]["issue_count"] == 3 and d["examples"][0]["titles"] == [
            "SQL injection"
        ]
        s.rollback()
        after = ([(i.id, i.fingerprint) for i in issues(s, asset_id)],
                 s.scalar(select(func.count()).select_from(OutboxEvent)))  # fmt: skip
        assert before == after and history(s, asset_id) == []


def test_applying_merges_exactly_as_previewed_and_keeps_every_occurrence(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        oldest = min(issues(s, asset_id), key=lambda i: (i.first_seen_at, i.id)).id
        rows_before = s.scalar(select(func.count()).select_from(FindingRow))
        done = apply_it(s, asset_id, note="one issue per rule per file")

        (only,) = issues(s, asset_id)
        assert only.id == oldest and only.fingerprint.startswith("dd1:tool_id:")
        assert only.fallback_fingerprint is None
        assert s.scalar(select(func.count()).select_from(FindingRow)) == rows_before == 3
        assert {r.issue_id for r in s.scalars(select(FindingRow))} == {oldest}
        assert done.effect["merged_away"] == 2 and done.version == 1
        (row,) = history(s, asset_id)
        assert (row.source, row.strategy, row.version, row.created_by) == (SRC, "tool_id", 1, "ana")
        assert row.effect["merged_away"] == 2 and row.note == "one issue per rule per file"
        assert current_settings(s, asset_id)[SRC].strategy == "tool_id"
        event = s.scalars(
            select(OutboxEvent).where(OutboxEvent.event_type == "dedup.changed")
        ).one()
        assert event.payload["merged_away"] == 2 and event.payload["version"] == 1
        audit = s.scalars(select(AuditEntry).where(AuditEntry.action == "dedup.changed")).one()
        assert audit.actor == "ana" and audit.target == f"asset:{asset_id}:{SRC}"


def test_after_the_change_an_import_matches_by_the_new_key(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        apply_it(s, asset_id)
        again = do_import(s, t["SAST"], load(code(line=55, snippet="moved(a, b, c, d)")), 2)
    assert (again.record.new_count, again.record.unchanged_count, again.record.closed_count) == (
        0,
        1,
        0,
    )


def test_applying_the_same_strategy_again_changes_nothing(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        apply_it(s, asset_id)
        p = preview_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="tool_id")
        assert not p.to_dict()["changes_anything"] and p.plan.merged_away == 0


def test_going_back_splits_what_was_merged(sessions: sessionmaker[Session]) -> None:
    """The inverse change: tool_id -> fingerprint_v2 gives back one Issue per distinct fingerprint
    (the merge itself cannot be undone, but its effect can: occurrences are never lost)."""
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        apply_it(s, asset_id)
        back = preview_change(
            s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="fingerprint_v2"
        )
        d = back.to_dict()
        assert d["issues_split"] == 1 and d["new_issues_from_split"] == 2 and d["issues_after"] == 3
        apply_it(s, asset_id, "fingerprint_v2")
        assert len(issues(s, asset_id)) == 3
        assert {len({r.issue_id for r in s.scalars(select(FindingRow))})} == {3}
        assert all(not i.fingerprint.startswith("dd1:") for i in issues(s, asset_id))


def test_a_stale_preview_is_refused_and_changes_nothing(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        p = preview_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="tool_id")
        do_import(
            s, t["SAST"], load(code(line=60, snippet="new(a, b, c, d, e)")), 2
        )  # moves the project
        with pytest.raises(StalePlan):
            apply_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="tool_id",
                         expected_digest=p.plan.digest)  # fmt: skip
        assert all(not i.fingerprint.startswith("dd1:") for i in issues(s, asset_id))
        assert history(s, asset_id) == []


def test_a_merge_never_hides_an_open_issue_behind_a_triage_decision(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        a, b, c = sorted(issues(s, asset_id), key=lambda i: (i.first_seen_at, i.id))
        a.first_seen_at = datetime(2020, 1, 1, tzinfo=timezone.utc)  # the survivor
        a.triage_status, a.triage_reason = "not_a_risk", "test code"
        s.commit()
        p = preview_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="tool_id")
        assert p.to_dict()["triage_conflicts"] == 1
        done = apply_it(s, asset_id)
        (merged,) = issues(s, asset_id)
    assert done.effect["triage_reset"] == 1
    assert (
        merged.triage_status == "open" and merged.triage_reason is None
    )  # open Issues stay visible


def test_members_that_agree_about_triage_keep_it(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        for i in issues(s, asset_id):
            i.triage_status, i.triage_reason = "not_a_risk", "known"
        s.commit()
        apply_it(s, asset_id)
        (merged,) = issues(s, asset_id)
    assert merged.triage_status == "not_a_risk" and merged.triage_reason == "known"


def test_a_merge_keeps_the_oldest_first_seen_and_a_live_state(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        a, b, c = sorted(issues(s, asset_id), key=lambda i: (i.first_seen_at, i.id))
        a.state, a.fixed_at = "fixed", datetime.now(timezone.utc)  # the survivor looks fixed ...
        a.first_seen_at = b.first_seen_at - timedelta(days=9)
        s.commit()
        apply_it(s, asset_id)  # ... but b and c are still present, so the merged Issue is
        (merged,) = issues(s, asset_id)
    assert merged.state in ("new", "open") and merged.fixed_at is None
    assert merged.first_seen_at == a.first_seen_at


def test_tickets_and_fix_runs_of_a_merged_away_issue_move_to_the_survivor(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        three_lines(s, t["SAST"])
        a, b, c = sorted(issues(s, asset_id), key=lambda i: (i.first_seen_at, i.id))
        a.first_seen_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
        for issue, provider, ext in (
            (a, "github", "o/r#1"),
            (b, "github", "o/r#2"),
            (c, "jira", "P-3"),
        ):
            s.add(ExternalIssueLinkRow(issue_id=issue.id, org_id=ORG, provider=provider,
                                       external_id=ext, external_url="https://x"))  # fmt: skip
        s.add(VerifiedFixRun(org_id=ORG, issue_id=c.id, workflow_id="wf-1"))
        s.commit()
        apply_it(s, asset_id)
        (merged,) = issues(s, asset_id)
        links = {(r.provider, r.external_id) for r in s.scalars(select(ExternalIssueLinkRow))}
        assert links == {
            ("github", "o/r#1"),
            ("jira", "P-3"),
        }  # b's duplicate ticket on github goes
        assert all(r.issue_id == merged.id for r in s.scalars(select(ExternalIssueLinkRow)))
        assert s.scalars(select(VerifiedFixRun)).one().issue_id == merged.id


def test_multi_source_issues_are_left_alone_and_counted(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, t = setup(s, "SAST")
        both = code(line=10)
        both.evidence.reported_by = [SRC, "bandit"]  # two tools agreed on this one
        do_import(s, t["SAST"], load(both, code(line=40, snippet="b(x, y)")), 1)
        p = preview_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="tool_id")
    assert p.plan.skipped_multi_source == 1 and p.plan.issues_before == 1


def test_a_bad_strategy_is_refused_before_anything_is_read(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        asset_id, _ = setup(s, "SAST")
        with pytest.raises(ValueError):
            preview_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="hash_fields")
        with pytest.raises(DedupError):
            apply_change(s, org_id=ORG, asset_id=asset_id, source=SRC, strategy="tool_id",
                         expected_digest="nope")  # fmt: skip
