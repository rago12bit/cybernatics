"""Crypto-shredding sweep: destroys expired scans' data keys per their organization's retention
policy (Week 47 task 2, plan §22.2, ADR-0032). Run periodically by Celery beat
(core.tasks.crypto_shred_task), the same pattern core.maintenance's housekeeping already uses.

Only the data key is destroyed here, never the underlying ciphertext object or the scan/issue rows
themselves -- "deletion by crypto-shredding" (plan §22.2) means the encrypted artifact becomes
permanently unreadable, not that it stops existing in storage or in any backup this code has no way
to reach anyway. Issues and findings are explicitly kept (plan §22.2: "keep issues") -- this sweep
never touches Scan, IssueRow, or FindingRow at all, only ScanDataKeyRow.

Iterates one organization at a time with `core.tenancy.set_session_org` set explicitly for each,
rather than one query across every org's rows: `scans` and `scan_data_keys` both carry `FORCE ROW
LEVEL SECURITY` policies keyed on `app.current_org` (migrations 0005/0018), and the worker's
`bulwark_app` connection is `NOBYPASSRLS` by design (ADR-0013) -- a single unscoped query would see
zero rows under RLS, not every org's, since an unset `app.current_org` matches nothing rather than
everything.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from core.persistence import repo
from core.persistence.db import SessionFactory
from core.persistence.models import Organization, Scan, ScanDataKeyRow
from core.tenancy import set_session_org

log = logging.getLogger(__name__)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # SQLite drops tzinfo


def shred_expired_scans(sessions: SessionFactory, now: datetime | None = None) -> list[str]:
    """Shreds every scan whose organization's retention window has passed and which still has a
    data key to destroy. Returns the shredded scan ids. Each organization's own
    core.persistence.repo.get_retention_days is checked individually -- there is no single global
    cutoff.

    The time comparison happens in Python against `_aware`-normalized values, not in the SQL WHERE
    clause -- the same fix core.maintenance.reap_stale_scans already needed: SQLite (used by every
    unit test) stores timestamps as naive text, so comparing a stored value against an
    aware `cutoff` inside SQLite's own string comparison silently matches nothing.
    """
    now = now or datetime.now(timezone.utc)
    shredded: list[str] = []
    with sessions() as s:  # organizations carries no RLS (ADR-0013) -- safe unscoped
        org_ids = list(s.scalars(select(Organization.id)))

    for org_id in org_ids:
        with sessions() as s:
            set_session_org(s, org_id)
            cutoff = now - timedelta(days=repo.get_retention_days(s, org_id))
            rows = s.execute(
                select(ScanDataKeyRow.scan_id, Scan.finished_at)
                .join(Scan, Scan.id == ScanDataKeyRow.scan_id)
                .where(ScanDataKeyRow.org_id == org_id, Scan.finished_at.is_not(None))
            ).all()
            for scan_id, finished_at in rows:
                if finished_at is None:  # SQL already filters this; narrows the type for mypy
                    continue
                if _aware(finished_at) >= cutoff:
                    continue
                if repo.delete_scan_data_key(s, scan_id):
                    shredded.append(scan_id)
                    log.info(
                        "crypto-shredded scan %s (org %s, retention window passed)",
                        scan_id,
                        org_id,
                    )
    return shredded
