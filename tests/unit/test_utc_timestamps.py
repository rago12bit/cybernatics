"""Timestamps come back from SQLite as they do from Postgres: timezone-aware UTC (core/persistence/
utc_type.py). Before, SQLite returned them naive, the API sent them without an offset, and a browser
east of UTC showed a run from seconds ago as "6 hours ago"."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import DateTime, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, sessionmaker

from core.persistence import repo
from core.persistence.models import Base, Scan
from core.persistence.utc_type import UtcDateTime
from tests.unit.test_api_ingest import (
    SARIF,
    Env,
    env,  # noqa: F401  (the fixture)
)

IST = timezone(timedelta(hours=5, minutes=30))


def _scan(s: Session) -> Scan:
    return repo.create_scan(
        s, source_type="git", source_ref="https://example.com/a/tz", source_label="a/tz", tools=[]
    )


def test_a_timestamp_read_back_from_sqlite_is_aware_utc(sessions: sessionmaker[Session]) -> None:
    with sessions() as s:
        scan_id = _scan(s).id
    with sessions() as s:
        created = s.get(Scan, scan_id).created_at  # type: ignore[union-attr]
    assert created.tzinfo is not None and created.utcoffset() == timedelta(0)
    assert abs(datetime.now(timezone.utc) - created) < timedelta(minutes=1)


def test_a_non_utc_value_is_stored_as_the_same_instant(sessions: sessionmaker[Session]) -> None:
    noon_ist = datetime(2026, 10, 5, 12, 0, tzinfo=IST)
    with sessions() as s:
        scan = _scan(s)
        scan.started_at = noon_ist
        s.commit()
        scan_id = scan.id
    with sessions() as s:
        started = s.get(Scan, scan_id).started_at  # type: ignore[union-attr]
        assert started == noon_ist and started.hour == 6 and started.minute == 30
        # Compared by instant in a query too, whatever zone the parameter is in.
        found = s.scalars(select(Scan.id).where(Scan.started_at < noon_ist + timedelta(seconds=1)))
        assert list(found) == [scan_id]
        assert not list(s.scalars(select(Scan.id).where(Scan.started_at > noon_ist)))


def test_the_api_sends_an_offset(env: Env) -> None:  # noqa: F811
    created = env.import_and_get(SARIF)["created_at"]
    assert created.endswith(("Z", "+00:00")), created


def test_every_timestamp_column_is_utc_and_postgres_ddl_is_unchanged() -> None:
    columns = [c for t in Base.metadata.tables.values() for c in t.columns]
    assert not [c for c in columns if isinstance(c.type, DateTime)], "use UtcDateTime"
    assert sum(isinstance(c.type, UtcDateTime) for c in columns) > 50
    ddl = UtcDateTime().compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]
    assert ddl == "TIMESTAMP WITH TIME ZONE"
