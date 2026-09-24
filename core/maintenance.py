"""Housekeeping that keeps a long-running deployment healthy.

  * reap_stale_scans   scans stuck in queued/running (worker died, queue lost) -> failed
  * cleanup_containers scanner containers that outlived their wall-clock timeout -> killed
  * cleanup_scratch    leftover temp workspaces / uploads from crashed jobs -> removed
Run periodically by Celery beat (core.tasks.maintenance_task).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import Scan

log = logging.getLogger(__name__)

STALE_MESSAGE = "the scan did not finish in time (the worker may have stopped); please retry"


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # SQLite drops tzinfo


def reap_stale_scans(
    s: Session, max_age: timedelta, bus: Any = None, now: datetime | None = None
) -> list[str]:
    """Fail scans that have been queued/running longer than max_age. Returns the reaped ids."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - max_age
    candidates = s.scalars(
        select(Scan).where(or_(Scan.status == "queued", Scan.status == "running"))
    )
    reaped: list[str] = []
    for scan in candidates:
        started = _aware(scan.started_at or scan.created_at)
        if started > cutoff:
            continue
        repo.finish_scan(s, scan.id, "failed", STALE_MESSAGE)
        if scan.source_type == "archive":
            Path(scan.source_ref).unlink(missing_ok=True)
        if bus is not None:
            bus.publish(
                scan.id,
                {
                    "type": "scan.finished",
                    "scan_id": scan.id,
                    "status": "failed",
                    "error": STALE_MESSAGE,
                },
            )
        log.warning(
            "reaped stale scan %s (status was stuck since %s)", scan.id, started.isoformat()
        )
        reaped.append(scan.id)
    return reaped


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=30, check=False
    )


def _parse_docker_time(raw: str) -> datetime | None:
    """`2026-09-24T17:09:51.123456789Z` -> datetime (Python parses at most microseconds)."""
    try:
        head, _, frac = raw.strip().rstrip("Z").partition(".")
        frac = (frac + "000000")[:6]
        return datetime.fromisoformat(f"{head}.{frac}").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def cleanup_containers(max_age_seconds: int = 3600, now: datetime | None = None) -> list[str]:
    """Kill Bulwark scanner containers older than max_age. Tool timeouts are <= 15 min, so anything
    older than an hour is an orphan (e.g. its worker was hard-killed mid-scan)."""
    now = now or datetime.now(timezone.utc)
    try:
        ps = _docker("ps", "-q", "--filter", "label=bulwark.managed=1")
    except (OSError, subprocess.TimeoutExpired):
        return []  # docker unreachable: nothing to clean, and not fatal
    killed: list[str] = []
    for cid in ps.stdout.split():
        info = _docker("inspect", "--format", "{{.Created}}", cid)
        created = _parse_docker_time(info.stdout)
        if created is None or (now - created).total_seconds() < max_age_seconds:
            continue
        _docker("kill", cid)
        log.warning("killed orphaned scanner container %s", cid)
        killed.append(cid)
    return killed


def cleanup_scratch(root: Path, max_age_seconds: int = 7200, now: float | None = None) -> list[str]:
    """Remove workspace/upload leftovers older than max_age from crashed jobs."""
    now = now or time.time()
    removed: list[str] = []
    if not root.is_dir():
        return removed
    for entry in root.iterdir():
        try:
            if now - entry.stat().st_mtime < max_age_seconds:
                continue
            shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
            removed.append(entry.name)
        except OSError:
            log.exception("could not remove stale scratch entry %s", entry)
    return removed
