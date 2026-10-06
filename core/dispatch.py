"""The outbox dispatcher (plan §41.1): hands each batch of new events to every subscriber, then
marks the batch dispatched.

Events were written in the same transaction as the change that caused them, so nothing is lost
between "saved" and "announced". Delivery to subscribers is at least once: a crash after a
subscriber acted and before the batch is marked means the batch comes round again, which is why
the rules engine never acts twice on one subject for one cause.

One dispatcher per organization at a time: a Postgres advisory lock, held on a connection of its
own (a session's connection can change at each commit, and the lock must not). SQLite (tests and a
single-process install) has one writer anyway and takes no lock.

A subscriber that raises is logged and the batch is still marked dispatched, so one poison event
cannot stall every later one; the rules engine records its own failures as runs.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from core.persistence import repo
from core.rules.engine import Event, on_events

log = logging.getLogger(__name__)
BATCH = 500

Subscriber = Callable[[Session, str, Sequence[Event]], Any]
SUBSCRIBERS: list[Subscriber] = [on_events]


def _lock_key(org_id: str) -> int:
    return int(hashlib.sha256(f"bulwark-outbox:{org_id}".encode()).hexdigest()[:15], 16)


@contextmanager
def _org_lock(s: Session, org_id: str) -> Iterator[bool]:
    bind = s.get_bind()
    if bind.dialect.name != "postgresql":
        yield True
        return
    key = _lock_key(org_id)
    with bind.connect() as conn:  # type: ignore[union-attr]
        got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar())
        try:
            yield got
        finally:
            if got:
                conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})


def dispatch(
    s: Session, org_id: str, *, limit: int = BATCH, subscribers: Sequence[Subscriber] | None = None
) -> int:
    """One batch. Returns how many events it dispatched (0 if another dispatcher holds the lock)."""
    with _org_lock(s, org_id) as got:
        if not got:
            return 0
        events = [Event.of(e) for e in repo.pending_outbox_events(s, org_id, limit=limit)]
        if not events:
            return 0
        for sub in subscribers if subscribers is not None else SUBSCRIBERS:
            try:
                sub(s, org_id, events)
            except Exception:  # noqa: BLE001 - see the module docstring
                s.rollback()
                log.exception("outbox subscriber %s failed", getattr(sub, "__name__", sub))
        repo.mark_outbox_dispatched(s, org_id, [e.id for e in events])
        return len(events)


def drain(s: Session, org_id: str, *, rounds: int = 20) -> int:
    """Dispatch until the outbox is empty, or `rounds` batches (events rules cause come next)."""
    total = 0
    for _ in range(rounds):
        n = dispatch(s, org_id)
        total += n
        if n == 0:
            break
    return total
