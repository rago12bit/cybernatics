"""The ingest service against REAL Postgres, as the non-superuser `bulwark_worker` role with real
Row-Level Security (Week 54 task 4, ADR-0040): the whole apply / reimport / revert flow under RLS,
another org being unable to touch a Test, and two simultaneous uploads of one file.

Needs `BULWARK_RLS_TEST_DATABASE_URL` pointed at a Postgres migrated to head.
"""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.imports.service import (
    ImportRequestError,
    apply_import,
    preview_import,
    revert_latest_import,
)
from core.persistence import repo
from core.persistence.models import FindingRow, ImportRecord, IssueRow, Scan
from core.tenancy import set_session_org
from tests.unit.test_reimport import file_of


def _url() -> str | None:
    return os.environ.get("BULWARK_RLS_TEST_DATABASE_URL")


def _ready() -> bool:
    if not _url():
        return False
    try:
        create_engine(_url()).connect().close()  # type: ignore[arg-type]
        return True
    except Exception:  # noqa: BLE001 - any connection failure means "not ready"
        return False


pytestmark = pytest.mark.skipif(not _ready(), reason="BULWARK_RLS_TEST_DATABASE_URL not reachable")


@pytest.fixture
def sessions() -> Iterator[sessionmaker[Session]]:
    engine = create_engine(_url())  # type: ignore[arg-type]
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def two_orgs(sessions: sessionmaker[Session]) -> Iterator[tuple[str, str]]:
    a, b = f"imp-a-{uuid.uuid4().hex[:8]}", f"imp-b-{uuid.uuid4().hex[:8]}"
    with sessions() as s:
        s.execute(
            text("INSERT INTO organizations (id, name, created_at) VALUES (:id, :n, now())"),
            [{"id": a, "n": "A"}, {"id": b, "n": "B"}],
        )
        s.commit()
    yield a, b
    with sessions() as s:
        for org in (a, b):
            set_session_org(s, org)
            for table in ("outbox_events", "import_records", "engagement_tests"):
                s.execute(text(f"DELETE FROM {table} WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM findings WHERE scan_id IN "
                           "(SELECT id FROM scans WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM issues WHERE asset_id IN "
                           "(SELECT id FROM assets WHERE org_id = :o)"), {"o": org})  # fmt: skip
            s.execute(text("DELETE FROM scans WHERE org_id = :o"), {"o": org})
            s.execute(text("DELETE FROM assets WHERE org_id = :o"), {"o": org})
        s.execute(text("DELETE FROM organizations WHERE id IN (:a, :b)"), {"a": a, "b": b})
        s.commit()


def _test_for(sessions: sessionmaker[Session], org: str) -> str:
    with sessions() as s:
        set_session_org(s, org)
        asset = repo.get_or_create_asset(s, source_type="git", source_label="a/b", org_id=org)
        eng = repo.get_or_create_import_engagement(s, asset_id=asset.id, org_id=org)
        return repo.get_or_create_engagement_test(
            s, org_id=org, engagement_id=eng.id, name="Nessus"
        ).id


def _import(s: Session, org: str, test_id: str, defects: set[int], n: int):
    return apply_import(
        s,
        org_id=org,
        test_id=test_id,
        findings=file_of(*sorted(defects)),
        parser="sarif",
        file_digest=f"{n:064x}",
        file_name=f"r{n}.sarif",
    )


def test_apply_reimport_and_revert_work_under_row_level_security(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org, _ = two_orgs
    test_id = _test_for(sessions, org)
    with sessions() as s:
        set_session_org(s, org)
        first = _import(s, org, test_id, {1, 2, 3}, 1)
        assert first.created and first.record.new_count == 3
        preview = preview_import(
            s, org_id=org, test_id=test_id, findings=file_of(1, 2, 4)
        )  # nothing written
        second = _import(s, org, test_id, {1, 2, 4}, 2)
        assert preview.counts == {
            "new": second.record.new_count, "unchanged": second.record.unchanged_count,
            "reopened": second.record.reopened_count, "closed": second.record.closed_count,
            "detached": second.record.detached_count, "held": second.record.held_count,
        }  # fmt: skip
        assert (second.record.new_count, second.record.closed_count) == (1, 1)
        kinds = {e.event_type for e in repo.pending_outbox_events(s, org)}
        assert {"issue.created", "issue.closed", "scan.completed"} <= kinds

        out = revert_latest_import(s, org_id=org, test_id=test_id)
        assert out.record.status == "reverted" and out.skipped == 0
        states = sorted(i.state for i in s.scalars(select(IssueRow)))
        assert states == ["new", "new", "new"]  # exactly as after the first import
        assert s.scalar(select(func.count()).select_from(Scan)) == 1
        assert s.scalar(select(func.count()).select_from(FindingRow)) == 3


def test_zap_places_are_held_then_closed_under_row_level_security(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    """The held-Issue lookup reads stored findings' JSON (JSONB here) with a grouped subquery; the
    same sequence as the SQLite test, on Postgres as the worker role."""
    from core.imports.parsers import get_parser, run_parser_on_bytes
    from core.imports.prepare import prepare
    from tests.unit.test_dast_sampled_places import zap_json

    org, _ = two_orgs
    test_id = _test_for(sessions, org)

    def zap(s: Session, alerts: dict[str, list[str]], n: int) -> ImportRecord:
        found = prepare(run_parser_on_bytes(get_parser("zap"), zap_json(alerts)).findings)
        return apply_import(s, org_id=org, test_id=test_id, findings=found, parser="zap",
                            file_digest=f"{n:064x}", file_name=f"z{n}.json").record  # fmt: skip

    with sessions() as s:
        set_session_org(s, org)
        zap(s, {"10038": ["/a0", "/a1"], "10020": ["/x"]}, 1)
        two = zap(s, {"10038": ["/b0"], "10020": ["/x"]}, 2)
        assert (two.closed_count, two.held_count, len(two.held_issue_ids)) == (0, 2, 2)
        three = zap(s, {"10020": ["/x"]}, 3)
        assert (three.closed_count, three.held_count) == (3, 0)


def test_another_org_cannot_preview_apply_or_revert_a_test_it_does_not_own(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org_a, org_b = two_orgs
    test_id = _test_for(sessions, org_a)
    with sessions() as s:
        set_session_org(s, org_a)
        _import(s, org_a, test_id, {1, 2}, 1)
    with sessions() as s:
        set_session_org(s, org_b)
        with pytest.raises(ImportRequestError, match="not found"):
            preview_import(s, org_id=org_b, test_id=test_id, findings=file_of(1))
        with pytest.raises(ImportRequestError, match="not found"):
            _import(s, org_b, test_id, {9}, 2)
        with pytest.raises(ImportRequestError, match="not found"):
            revert_latest_import(s, org_id=org_b, test_id=test_id)
    with sessions() as s:  # org A's data is exactly as it was
        set_session_org(s, org_a)
        assert s.scalar(select(func.count()).select_from(ImportRecord)) == 1
        assert sorted(i.state for i in s.scalars(select(IssueRow))) == ["new", "new"]


def test_two_simultaneous_uploads_of_one_file_apply_exactly_once(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]
) -> None:
    org, _ = two_orgs
    test_id = _test_for(sessions, org)
    barrier = threading.Barrier(2)
    results: list[bool] = []
    errors: list[BaseException] = []

    def upload() -> None:
        try:
            with sessions() as s:
                set_session_org(s, org)
                barrier.wait(timeout=10)
                results.append(_import(s, org, test_id, {1, 2, 3}, 7).created)
        except BaseException as exc:  # noqa: BLE001 - surfaced by the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=upload) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, errors
    assert sorted(results) == [False, True]  # one applied it, the other was a no-op
    with sessions() as s:
        set_session_org(s, org)
        assert s.scalar(select(func.count()).select_from(ImportRecord)) == 1
        assert s.scalar(select(func.count()).select_from(IssueRow)) == 3  # not 6
