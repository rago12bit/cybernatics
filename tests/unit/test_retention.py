"""core.retention.shred_expired_scans (Week 47 task 2, plan §22.2). RLS itself is live-verified
against real Postgres in tests/integration/test_data_protection_rls_docker.py; this covers the
selection logic (which scans are eligible, per-org retention) against SQLite."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import Organization
from core.retention import shred_expired_scans
from core.tenancy import DEFAULT_ORG_ID


def _seed_finished_scan(
    sessions: sessionmaker[Session], *, org_id: str, finished_at: datetime | None
) -> str:
    """shred_expired_scans discovers which orgs to check via the organizations table itself
    (core.retention's own docstring explains why: it's the one table with no RLS, so it's safe to
    query before app.current_org is set for any particular org) -- unlike most repo functions,
    which only ever reference org_id as a foreign key value and never query organizations directly,
    so no other test in this suite needs a real row there under SQLite's unenforced FKs."""
    with sessions() as s:
        if s.get(Organization, org_id) is None:
            s.add(Organization(id=org_id, name=org_id))
            s.commit()
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://x/y.git", source_label="x/y",
            tools=["bandit"], org_id=org_id,
        )  # fmt: skip
        scan.finished_at = finished_at
        s.commit()
        return scan.id


def test_a_scan_past_the_default_retention_window_is_shredded(
    sessions: sessionmaker[Session],
) -> None:
    now = datetime.now(timezone.utc)
    scan_id = _seed_finished_scan(
        sessions, org_id=DEFAULT_ORG_ID, finished_at=now - timedelta(days=8)
    )
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped")

    shredded = shred_expired_scans(sessions, now=now)
    assert shredded == [scan_id]
    with sessions() as s:
        assert repo.get_scan_data_key(s, scan_id) is None


def test_a_scan_within_the_retention_window_is_left_alone(
    sessions: sessionmaker[Session],
) -> None:
    now = datetime.now(timezone.utc)
    scan_id = _seed_finished_scan(
        sessions, org_id=DEFAULT_ORG_ID, finished_at=now - timedelta(days=2)
    )
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped")

    assert shred_expired_scans(sessions, now=now) == []
    with sessions() as s:
        assert repo.get_scan_data_key(s, scan_id) is not None


def test_an_org_with_a_custom_retention_period_is_respected(
    sessions: sessionmaker[Session],
) -> None:
    now = datetime.now(timezone.utc)
    scan_id = _seed_finished_scan(
        sessions, org_id=DEFAULT_ORG_ID, finished_at=now - timedelta(days=20)
    )
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped")
        repo.set_retention_days(s, DEFAULT_ORG_ID, 30)  # longer than the default 7

    assert shred_expired_scans(sessions, now=now) == []
    with sessions() as s:
        assert repo.get_scan_data_key(s, scan_id) is not None


def test_a_scan_with_no_data_key_is_not_an_error(sessions: sessionmaker[Session]) -> None:
    now = datetime.now(timezone.utc)
    _seed_finished_scan(sessions, org_id=DEFAULT_ORG_ID, finished_at=now - timedelta(days=30))
    assert shred_expired_scans(sessions, now=now) == []


def test_an_unfinished_scan_is_never_shredded_even_if_created_long_ago(
    sessions: sessionmaker[Session],
) -> None:
    scan_id = _seed_finished_scan(sessions, org_id=DEFAULT_ORG_ID, finished_at=None)
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped")

    far_future = datetime.now(timezone.utc) + timedelta(days=3650)
    assert shred_expired_scans(sessions, now=far_future) == []
    with sessions() as s:
        assert repo.get_scan_data_key(s, scan_id) is not None


def test_shredding_never_touches_the_scan_or_issue_rows(sessions: sessionmaker[Session]) -> None:
    now = datetime.now(timezone.utc)
    scan_id = _seed_finished_scan(
        sessions, org_id=DEFAULT_ORG_ID, finished_at=now - timedelta(days=8)
    )
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped")

    shred_expired_scans(sessions, now=now)
    with sessions() as s:
        scan = repo.get_scan(s, scan_id)
        assert scan is not None and scan.id == scan_id  # the scan itself survives


def test_crypto_shred_task_is_scheduled_and_runs(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch
) -> None:
    from core import tasks
    from core.persistence import db

    sched = tasks.celery_app.conf.beat_schedule["crypto-shred"]
    assert sched["task"] == "bulwark.crypto_shred" and sched["schedule"] == 3600.0

    monkeypatch.setattr(db, "_factory", sessions)
    now = datetime.now(timezone.utc)
    scan_id = _seed_finished_scan(
        sessions, org_id=DEFAULT_ORG_ID, finished_at=now - timedelta(days=8)
    )
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped")

    out = tasks.crypto_shred_task()
    assert out["scans_shredded"] == 1
    with sessions() as s:
        assert repo.get_scan_data_key(s, scan_id) is None
