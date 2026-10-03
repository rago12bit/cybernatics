from __future__ import annotations

import os
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core import maintenance
from core.events import MemoryPublisher
from core.persistence import repo
from core.persistence.models import Organization, Scan
from core.tenancy import DEFAULT_ORG_ID

NOW = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


def _scan(
    s: Session, status: str, created: datetime, started: datetime | None = None, **kw: str
) -> str:
    """reap_stale_scans discovers which orgs to check via the organizations table itself (its own
    docstring explains why: that's the one table with no RLS, so it's safe to query before
    app.current_org is set for any particular org) -- so, like core.retention's equivalent fixture,
    this seeds a real Organization row even under SQLite's otherwise-unenforced FKs."""
    if s.get(Organization, DEFAULT_ORG_ID) is None:
        s.add(Organization(id=DEFAULT_ORG_ID, name=DEFAULT_ORG_ID))
        s.commit()
    scan = repo.create_scan(
        s,
        source_type=kw.get("stype", "git"),
        source_ref=kw.get("ref", "u"),
        source_label="l",
        tools=["bandit"],
    )
    scan.status, scan.created_at, scan.started_at = status, created, started
    s.commit()
    return scan.id


def test_reaper_fails_only_stuck_scans(sessions: sessionmaker[Session], tmp_path: Path) -> None:
    upload = tmp_path / "up.zip"
    upload.write_bytes(b"PK")
    with sessions() as s:
        old_queued = _scan(s, "queued", NOW - timedelta(hours=2), stype="archive", ref=str(upload))
        old_running = _scan(s, "running", NOW - timedelta(hours=3), NOW - timedelta(hours=2))
        fresh_running = _scan(s, "running", NOW - timedelta(hours=3), NOW - timedelta(minutes=5))
        fresh_queued = _scan(s, "queued", NOW - timedelta(minutes=1))
        done = _scan(s, "completed", NOW - timedelta(days=1), NOW - timedelta(days=1))
    bus = MemoryPublisher()
    reaped = maintenance.reap_stale_scans(sessions, timedelta(minutes=30), bus, NOW)
    assert sorted(reaped) == sorted([old_queued, old_running])
    with sessions() as s:
        statuses = {x.id: (x.status, x.error) for x in s.query(Scan).all()}
    assert statuses[old_queued][0] == statuses[old_running][0] == "failed"
    assert "did not finish" in (statuses[old_running][1] or "")
    assert statuses[fresh_running][0] == "running" and statuses[fresh_queued][0] == "queued"
    assert statuses[done][0] == "completed"  # finished scans are never touched
    assert not upload.exists()  # orphaned upload removed with its scan
    assert {sid for sid, _ in bus.events} == {old_queued, old_running}  # watchers are told
    assert all(e["type"] == "scan.finished" and e["status"] == "failed" for _, e in bus.events)


def test_reaper_is_idempotent(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        _scan(s, "running", NOW - timedelta(hours=3), NOW - timedelta(hours=2))
    assert len(maintenance.reap_stale_scans(sessions, timedelta(minutes=30), None, NOW)) == 1
    assert maintenance.reap_stale_scans(sessions, timedelta(minutes=30), None, NOW) == []


def test_docker_timestamp_parsing() -> None:
    t = maintenance._parse_docker_time("2026-09-24T17:09:51.123456789Z\n")
    assert t == datetime(2026, 9, 24, 17, 9, 51, 123456, tzinfo=timezone.utc)
    assert maintenance._parse_docker_time("2026-09-24T17:09:51Z") is not None
    assert maintenance._parse_docker_time("garbage") is None


def test_container_janitor_kills_only_old_labelled_containers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []
    created = {"old1": "2026-09-25T09:00:00Z", "young": "2026-09-25T11:50:00Z", "weird": "???"}

    def fake_docker(*args: str) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "ps":
            assert "label=bulwark.managed=1" in args  # never touches containers we did not start
            return subprocess.CompletedProcess(args, 0, "old1\nyoung\nweird\n", "")
        if args[0] == "inspect":
            return subprocess.CompletedProcess(args, 0, created[args[-1]], "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(maintenance, "_docker", fake_docker)
    assert maintenance.cleanup_containers(3600, NOW) == ["old1"]
    assert [c for c in calls if c[0] == "kill"] == [("kill", "old1")]


def test_container_janitor_survives_docker_being_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: str) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("docker")

    monkeypatch.setattr(maintenance, "_docker", boom)
    assert maintenance.cleanup_containers() == []


def test_scratch_cleanup_removes_only_old_entries(tmp_path: Path) -> None:
    old_dir, new_dir, old_file = tmp_path / "old", tmp_path / "new", tmp_path / "old.zip"
    for d in (old_dir, new_dir):
        d.mkdir()
        (d / "f").write_text("x")
    old_file.write_text("x")
    past = time.time() - 10_000
    for p in (old_dir, old_file):
        os.utime(p, (past, past))
    removed = maintenance.cleanup_scratch(tmp_path, 7200)
    assert sorted(removed) == ["old", "old.zip"] and new_dir.exists()
    assert maintenance.cleanup_scratch(tmp_path / "missing") == []


def test_maintenance_task_is_scheduled_and_runs(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    from core import tasks
    from core.persistence import db

    sched = tasks.celery_app.conf.beat_schedule["housekeeping"]
    assert sched["task"] == "bulwark.maintenance" and sched["schedule"] == 300.0
    monkeypatch.setattr(db, "_factory", sessions)
    monkeypatch.setattr(
        maintenance, "_docker", lambda *a: subprocess.CompletedProcess(a, 0, "", "")
    )
    monkeypatch.setattr("core.events.RedisPublisher", lambda url: MemoryPublisher())
    with sessions() as s:
        _scan(
            s,
            "running",
            datetime.now(timezone.utc) - timedelta(hours=3),
            datetime.now(timezone.utc) - timedelta(hours=2),
        )
    out = tasks.maintenance_task()
    assert out["scans_reaped"] == 1 and out["containers_killed"] == 0


# --- expire_stale_imports (Week 54 task 8, ADR-0040) -----------------------------------------------


def _import(s: Session, tmp_path: Path, status: str, created: datetime, name: str):
    if s.get(Organization, DEFAULT_ORG_ID) is None:
        s.add(Organization(id=DEFAULT_ORG_ID, name=DEFAULT_ORG_ID))
        s.commit()
    asset = repo.get_or_create_asset(
        s, source_type="git", source_label="a/b", org_id=DEFAULT_ORG_ID
    )
    eng = repo.get_or_create_import_engagement(s, asset_id=asset.id, org_id=DEFAULT_ORG_ID)
    test = repo.get_or_create_engagement_test(
        s, org_id=DEFAULT_ORG_ID, engagement_id=eng.id, name="T"
    )
    upload = tmp_path / name
    upload.write_text("{}")
    rec = repo.add_import_record(
        s, org_id=DEFAULT_ORG_ID, test_id=test.id, scan_id=None, parser="sarif",
        file_digest=name.ljust(64, "0"), status=status, upload_path=str(upload),
    )  # fmt: skip
    rec.created_at = created
    s.commit()
    return rec.id, upload


def test_an_abandoned_preview_is_cancelled_and_its_file_deleted(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    with sessions() as s:
        old, old_file = _import(s, tmp_path, "previewed", NOW - timedelta(hours=30), "old")
        fresh, fresh_file = _import(s, tmp_path, "previewed", NOW - timedelta(hours=1), "fresh")
    expired = maintenance.expire_stale_imports(sessions, timedelta(hours=24), NOW)
    assert expired == [old]
    assert not old_file.exists() and fresh_file.exists()  # a live preview keeps its file
    with sessions() as s:
        rec = repo.get_import_record(s, old, DEFAULT_ORG_ID)
        assert rec is not None and rec.status == "cancelled" and "expired" in (rec.error or "")
        assert rec.upload_path is None
        kept = repo.get_import_record(s, fresh, DEFAULT_ORG_ID)
        assert kept is not None and kept.status == "previewed" and kept.upload_path is not None


def test_an_import_a_worker_never_finished_is_failed_not_left_in_progress(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    with sessions() as s:
        stuck, f1 = _import(s, tmp_path, "processing", NOW - timedelta(hours=30), "a")
        queued, f2 = _import(s, tmp_path, "queued", NOW - timedelta(hours=30), "b")
        recent, f3 = _import(s, tmp_path, "processing", NOW - timedelta(minutes=5), "c")
    expired = maintenance.expire_stale_imports(sessions, timedelta(hours=24), NOW)
    assert sorted(expired) == sorted([stuck, queued])
    assert not f1.exists() and not f2.exists() and f3.exists()
    with sessions() as s:
        rec = repo.get_import_record(s, stuck, DEFAULT_ORG_ID)
        assert rec is not None and rec.status == "failed" and "did not finish" in (rec.error or "")
        still = repo.get_import_record(s, recent, DEFAULT_ORG_ID)
        assert still is not None and still.status == "processing"


def test_finished_imports_are_never_touched_by_the_expiry(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    with sessions() as s:
        applied, _ = _import(s, tmp_path, "applied", NOW - timedelta(days=90), "done")
        failed, _ = _import(s, tmp_path, "failed", NOW - timedelta(days=90), "bad")
    assert maintenance.expire_stale_imports(sessions, timedelta(hours=24), NOW) == []
    with sessions() as s:
        assert repo.get_import_record(s, applied, DEFAULT_ORG_ID).status == "applied"  # type: ignore[union-attr]
        assert repo.get_import_record(s, failed, DEFAULT_ORG_ID).status == "failed"  # type: ignore[union-attr]


def test_ingest_uploads_live_outside_the_generic_two_hour_scratch_cleanup() -> None:
    """A previewed upload waits for a person for hours; the scratch cleanup deletes uploads after
    two. They must not share a directory (this is the bug that made `ingest_dir` a separate setting).
    """
    from core.config import Settings

    s = Settings.from_env()
    assert s.ingest_dir != s.upload_dir and s.upload_dir not in s.ingest_dir.parents
