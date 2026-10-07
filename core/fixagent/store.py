"""Persistence for one verified-fix run (plan §21.2, ADR-0027). Kept alongside the rest of
`core.fixagent`, not in `core/persistence/repo.py` -- the same modularity `core/llm/budget.py` and
`core/llm/cache.py` already use for their own feature-specific tables (`LlmUsage`,
`RemediationCache`) rather than growing the general-purpose repo module.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence.models import FindingRow, VerifiedFixRun

TERMINAL = frozenset({"approved", "rejected", "opened_pr", "verified", "failed", "inconclusive"})


def create_run(
    s: Session,
    org_id: str,
    issue_id: str | None,
    workflow_id: str,
    *,
    pr_fix_request_id: str | None = None,
    finding_id: str | None = None,
) -> VerifiedFixRun:
    """For an Issue, or (`/fix`, Week 76) for one finding of a pull request request."""
    row = VerifiedFixRun(
        org_id=org_id, issue_id=issue_id, workflow_id=workflow_id, verification_record=[],
        pr_fix_request_id=pr_fix_request_id, finding_id=finding_id,
    )  # fmt: skip
    s.add(row)
    s.commit()
    return row


def get_run(s: Session, run_id: str, *, org_id: str | None = None) -> VerifiedFixRun | None:
    row = s.get(VerifiedFixRun, run_id)
    if row is None or (org_id is not None and row.org_id != org_id):
        return None
    return row


def get_run_by_workflow_id(s: Session, workflow_id: str) -> VerifiedFixRun | None:
    """No `org_id` filter: called only from inside a workflow activity, which already knows the
    exact workflow id it is (there is no cross-tenant question to ask), the same "trusted internal
    read" shape `core.persistence.repo.get_scan`'s `org_id=None` mode documents."""
    return s.scalar(select(VerifiedFixRun).where(VerifiedFixRun.workflow_id == workflow_id))


def latest_run_for_issue(
    s: Session, issue_id: str, *, org_id: str | None = None
) -> VerifiedFixRun | None:
    q = select(VerifiedFixRun).where(VerifiedFixRun.issue_id == issue_id)
    if org_id is not None:
        q = q.where(VerifiedFixRun.org_id == org_id)
    q = q.order_by(VerifiedFixRun.created_at.desc()).limit(1)
    return s.scalar(q)


def count_running_for_org(s: Session, org_id: str) -> int:
    """ADR-0015's concurrency cap: how many of this org's runs are still active (not yet at a
    terminal status) right now."""
    q = select(VerifiedFixRun).where(
        VerifiedFixRun.org_id == org_id, VerifiedFixRun.status.not_in(TERMINAL)
    )
    return len(list(s.scalars(q)))


def baseline_fingerprints_for(s: Session, scan_id: str, path: str) -> list[str]:
    """Every finding already on `path` in `scan_id`, before any fix attempt -- the "was this
    already there" set `core.fixagent.verify.rerun_scanners` needs to tell a real regression from a
    pre-existing, unrelated issue on the same file (its own docstring has the full reasoning)."""
    q = select(FindingRow.fingerprint).where(
        FindingRow.scan_id == scan_id, FindingRow.path == path, FindingRow.fingerprint != ""
    )
    return list(s.scalars(q))


def update_run(s: Session, run: VerifiedFixRun, **fields: Any) -> None:
    for k, v in fields.items():
        setattr(run, k, v)
    run.updated_at = datetime.now(timezone.utc)
    s.commit()
