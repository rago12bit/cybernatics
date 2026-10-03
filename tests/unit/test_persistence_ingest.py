"""core.persistence.repo's persistent-Test, ImportRecord and outbox functions (Week 54 task 2,
ADR-0040). SQLite, so these cover application-level behaviour and org filtering; the real
Row-Level Security proof is tests/integration/test_ingest_rls_docker.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import Organization
from core.tenancy import DEFAULT_ORG_ID

OTHER_ORG = "other-org"


def _seed(s: Session) -> str:
    """One org, one asset, one non-CI engagement; returns the engagement id."""
    s.add(Organization(id=DEFAULT_ORG_ID, name="default"))
    s.add(Organization(id=OTHER_ORG, name="other"))
    s.commit()
    asset = repo.get_or_create_asset(
        s, source_type="git", source_label="a/b", org_id=DEFAULT_ORG_ID
    )
    return repo.create_engagement(
        s, org_id=DEFAULT_ORG_ID, asset_id=asset.id, name="Q3 pentest", engagement_type="import"
    ).id


def test_a_test_is_created_once_and_reused(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        eng = _seed(s)
        first = repo.get_or_create_engagement_test(
            s, org_id=DEFAULT_ORG_ID, engagement_id=eng, name="Nessus", parser="nessus"
        )
        second = repo.get_or_create_engagement_test(
            s, org_id=DEFAULT_ORG_ID, engagement_id=eng, name="Nessus"
        )
        assert first.id == second.id
        assert first.parser == "nessus"
        assert [t.name for t in repo.list_engagement_tests(s, eng, DEFAULT_ORG_ID)] == ["Nessus"]


def test_two_differently_named_tests_coexist_in_one_engagement(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        eng = _seed(s)
        for name in ("ZAP", "Burp"):
            repo.get_or_create_engagement_test(
                s, org_id=DEFAULT_ORG_ID, engagement_id=eng, name=name
            )
        names = [t.name for t in repo.list_engagement_tests(s, eng, DEFAULT_ORG_ID)]
        assert names == ["Burp", "ZAP"]  # sorted by name


def test_a_test_cannot_be_created_under_another_orgs_engagement(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        eng = _seed(s)
        with pytest.raises(ValueError, match="not found"):
            repo.get_or_create_engagement_test(s, org_id=OTHER_ORG, engagement_id=eng, name="x")
        with pytest.raises(ValueError, match="not found"):
            repo.get_or_create_engagement_test(
                s, org_id=DEFAULT_ORG_ID, engagement_id="no-such-engagement", name="x"
            )


def test_another_orgs_test_is_invisible_at_the_repo_layer(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        eng = _seed(s)
        test = repo.get_or_create_engagement_test(
            s, org_id=DEFAULT_ORG_ID, engagement_id=eng, name="Nessus"
        )
        assert repo.get_engagement_test(s, test.id, OTHER_ORG) is None
        assert repo.list_engagement_tests(s, eng, OTHER_ORG) == []
        assert repo.get_engagement_test(s, test.id, DEFAULT_ORG_ID) is not None


def _record(s: Session, test_id: str, digest: str, *, at: datetime, status: str = "applied"):
    rec = repo.add_import_record(
        s, org_id=DEFAULT_ORG_ID, test_id=test_id, scan_id=None, parser="sarif", file_digest=digest
    )
    rec.created_at, rec.status = at, status
    s.commit()
    return rec


def test_latest_applied_import_is_the_newest_applied_one(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        eng = _seed(s)
        test = repo.get_or_create_engagement_test(
            s, org_id=DEFAULT_ORG_ID, engagement_id=eng, name="SARIF"
        )
        t0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
        assert repo.latest_applied_import(s, test.id, DEFAULT_ORG_ID) is None
        _record(s, test.id, "a" * 64, at=t0)
        newest = _record(s, test.id, "b" * 64, at=t0 + timedelta(hours=1))
        # A reverted import is history, not the Test's current snapshot.
        _record(s, test.id, "c" * 64, at=t0 + timedelta(hours=2), status="reverted")
        latest = repo.latest_applied_import(s, test.id, DEFAULT_ORG_ID)
        assert latest is not None and latest.id == newest.id
        history = repo.list_import_records(s, test.id, DEFAULT_ORG_ID)
        assert [r.file_digest[0] for r in history] == ["c", "b", "a"]  # newest first


def test_import_records_are_org_scoped(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        eng = _seed(s)
        test = repo.get_or_create_engagement_test(
            s, org_id=DEFAULT_ORG_ID, engagement_id=eng, name="SARIF"
        )
        rec = _record(s, test.id, "a" * 64, at=datetime(2026, 10, 1, tzinfo=timezone.utc))
        assert repo.get_import_record(s, rec.id, OTHER_ORG) is None
        assert repo.list_import_records(s, test.id, OTHER_ORG) == []
        assert repo.latest_applied_import(s, test.id, OTHER_ORG) is None
        assert repo.get_import_record(s, rec.id, DEFAULT_ORG_ID) is not None


def test_new_import_record_defaults(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        eng = _seed(s)
        test = repo.get_or_create_engagement_test(
            s, org_id=DEFAULT_ORG_ID, engagement_id=eng, name="SARIF"
        )
        rec = repo.add_import_record(
            s, org_id=DEFAULT_ORG_ID, test_id=test.id, scan_id=None, parser="sarif",
            file_digest="d" * 64,
        )  # fmt: skip
        s.commit()
        assert (rec.status, rec.scope, rec.close_missing) == ("applied", "test", True)
        assert (rec.new_count, rec.unchanged_count, rec.reopened_count) == (0, 0, 0)
        assert (rec.closed_count, rec.detached_count) == (0, 0)
        assert rec.warnings == [] and rec.changes == []


def test_an_outbox_event_commits_or_rolls_back_with_its_transaction(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _seed(s)
        repo.add_outbox_event(
            s, org_id=DEFAULT_ORG_ID, event_type="issue.created", payload={"n": 1}
        )
        s.rollback()  # the change that caused it failed: so must the announcement
        assert repo.pending_outbox_events(s, DEFAULT_ORG_ID) == []

        repo.add_outbox_event(
            s, org_id=DEFAULT_ORG_ID, event_type="issue.created", payload={"n": 2}
        )
        s.commit()
        pending = repo.pending_outbox_events(s, DEFAULT_ORG_ID)
        assert [(e.event_type, e.payload) for e in pending] == [("issue.created", {"n": 2})]


def test_dispatched_outbox_events_leave_the_pending_list_in_order(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        _seed(s)
        for n in range(3):
            repo.add_outbox_event(s, org_id=DEFAULT_ORG_ID, event_type="e", payload={"n": n})
        s.commit()
        pending = repo.pending_outbox_events(s, DEFAULT_ORG_ID)
        assert [e.payload["n"] for e in pending] == [0, 1, 2]  # stable creation order
        repo.mark_outbox_dispatched(s, DEFAULT_ORG_ID, [pending[0].id, pending[1].id])
        assert [e.payload["n"] for e in repo.pending_outbox_events(s, DEFAULT_ORG_ID)] == [2]


def test_outbox_events_are_org_scoped(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        _seed(s)
        repo.add_outbox_event(s, org_id=DEFAULT_ORG_ID, event_type="e", payload={})
        s.commit()
        assert repo.pending_outbox_events(s, OTHER_ORG) == []
        ev = repo.pending_outbox_events(s, DEFAULT_ORG_ID)[0]
        repo.mark_outbox_dispatched(s, OTHER_ORG, [ev.id])  # another org cannot dispatch it
        assert len(repo.pending_outbox_events(s, DEFAULT_ORG_ID)) == 1
