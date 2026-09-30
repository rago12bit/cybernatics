"""core.persistence.repo's scan_data_keys functions (Week 47 task 1/2, plan §22.2). RLS itself is
live-verified against real Postgres in tests/integration/test_data_protection_rls_docker.py; this
covers the SQLite-backed application logic every unit test runs against."""

from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.tenancy import DEFAULT_ORG_ID


def _seed_scan(sessions: sessionmaker[Session]) -> str:
    with sessions() as s:
        scan = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/x.git",
            source_label="acme/x", tools=["bandit"], org_id=DEFAULT_ORG_ID,
        )  # fmt: skip
        return scan.id


def test_get_scan_data_key_is_none_before_one_is_saved(sessions: sessionmaker[Session]) -> None:
    scan_id = _seed_scan(sessions)
    with sessions() as s:
        assert repo.get_scan_data_key(s, scan_id) is None


def test_save_then_get_roundtrips_the_wrapped_key(sessions: sessionmaker[Session]) -> None:
    scan_id = _seed_scan(sessions)
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped-bytes")
    with sessions() as s:
        row = repo.get_scan_data_key(s, scan_id)
        assert row is not None
        assert row.wrapped_dek == b"wrapped-bytes"
        assert row.org_id == DEFAULT_ORG_ID


def test_delete_scan_data_key_removes_it_and_reports_it_existed(
    sessions: sessionmaker[Session],
) -> None:
    scan_id = _seed_scan(sessions)
    with sessions() as s:
        repo.save_scan_data_key(s, scan_id, DEFAULT_ORG_ID, b"wrapped-bytes")
    with sessions() as s:
        assert repo.delete_scan_data_key(s, scan_id) is True
    with sessions() as s:
        assert repo.get_scan_data_key(s, scan_id) is None


def test_delete_scan_data_key_on_a_scan_with_none_reports_false(
    sessions: sessionmaker[Session],
) -> None:
    scan_id = _seed_scan(sessions)
    with sessions() as s:
        assert repo.delete_scan_data_key(s, scan_id) is False


# The migration declares the scan_id FK ON DELETE CASCADE (a scan's key can never outlive the scan
# itself even if crypto-shredding is never explicitly called for it) -- not tested here because
# SQLite does not enforce foreign-key constraints by default, unlike real Postgres. Verified live
# against real Postgres instead: see
# tests/integration/test_data_protection_rls_docker.py.
