"""A timestamp column that is always UTC and always timezone-aware, on every database.

PostgreSQL's `timestamptz` keeps the zone, so `DateTime(timezone=True)` already behaves there.
SQLite has no timestamp type: SQLAlchemy writes the wall-clock digits as text and drops the zone,
and reads them back naive. A naive value then reaches the API as `2026-10-05T09:25:47` with no
offset, and a browser reads it as *local* time -- a run from seconds ago showed as "6 hours ago" in
IST (found on the Connectors screen against the SQLite-backed scratch server). It also stored an
aware non-UTC value as its local digits, a silent shift.

So: on the way in, a value is converted to UTC (a naive one is taken to be UTC already, as
everything in this codebase means); on the way out, a naive value is marked UTC, and an aware one
(PostgreSQL returns the session's zone) is converted to UTC. On PostgreSQL the DDL is the same
`TIMESTAMP WITH TIME ZONE` as before, so no migration.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime
from sqlalchemy.engine import Dialect
from sqlalchemy.types import TypeDecorator


class UtcDateTime(TypeDecorator[datetime]):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Dialect) -> Any:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value
