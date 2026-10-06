"""The ingest service (plan §42.1, ADR-0040): preview an import, apply it, revert the latest one.

`preview_import` and `apply_import` share `_decide`, so the counts the import screen shows before
anything is saved are the counts the import then records -- one computation, not two kept in
agreement by hand. Applying is one transaction: the Scan that owns the findings, the findings, the
Issue changes, the ImportRecord and the outbox events all commit together or not at all.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from core import inventory
from core.dedup.settings import rekey_for_asset
from core.imports.reimport import ReimportPlan, plan_reimport
from core.models.finding import Finding
from core.persistence import repo
from core.persistence.models import (
    Engagement,
    EngagementTest,
    FindingRow,
    ImportRecord,
    IssueRow,
    Scan,
)

SCOPES = ("test", "engagement")
_COUNT_FIELDS = (
    "new_count",
    "unchanged_count",
    "reopened_count",
    "closed_count",
    "detached_count",
)


class ImportRequestError(ValueError):
    """The request cannot be honoured (unknown Test, bad scope, nothing to revert)."""


@dataclass(frozen=True)
class ImportPreview:
    """What an import would do, without doing it (the import screen, plan §55.1)."""

    plan: ReimportPlan
    close_missing: bool
    scope: str

    @property
    def counts(self) -> dict[str, int]:
        return self.plan.counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "counts": self.counts,
            "reopened_issue_ids": list(self.plan.reopened_issue_ids),
            "closed_issue_ids": list(self.plan.closed_issue_ids),
            "detached_issue_ids": list(self.plan.detached_issue_ids),
            "close_missing": self.close_missing,
            "scope": self.scope,
        }


@dataclass(frozen=True)
class ImportResult:
    record: ImportRecord
    created: bool  # False: the same file was already the Test's latest import (idempotent no-op)
    # Libraries whose current use an imported SBOM changed: what the caller matches against
    # advisories once this has committed (`core.advisories.impact.match_after_record`).
    inventory_changed: frozenset[str] = frozenset()
    asset_id: str | None = None  # the project whose inventory changed


@dataclass(frozen=True)
class RevertResult:
    record: ImportRecord
    restored: int  # Issues put back as they were before the import
    deleted: int  # Issues the import created that nothing else references
    skipped: int  # Issues something else changed since, left alone rather than clobbered
    inventory_changed: frozenset[str] = frozenset()
    asset_id: str | None = None  # the project whose inventory changed


def _load(s: Session, org_id: str, test_id: str) -> tuple[EngagementTest, Engagement]:
    test = repo.get_engagement_test(s, test_id, org_id)
    if test is None:
        raise ImportRequestError(f"test {test_id} not found")
    engagement = repo.get_engagement(s, test.engagement_id, org_id)
    if engagement is None:  # a Test cascades from its engagement, so this is corruption, not input
        raise ImportRequestError(f"engagement {test.engagement_id} not found")
    return test, engagement


def _snapshot_issue_ids(s: Session, org_id: str, test_ids: list[str]) -> set[str]:
    scan_ids = []
    for test_id in test_ids:
        latest = repo.latest_applied_import(s, test_id, org_id)
        if latest is not None and latest.scan_id is not None:
            scan_ids.append(latest.scan_id)
    return repo.issue_ids_in_scans(s, scan_ids)


def _decide(
    s: Session,
    *,
    org_id: str,
    test: EngagementTest,
    engagement: Engagement,
    findings: list[Finding],
    close_missing: bool,
    scope: str,
) -> tuple[ReimportPlan, list[IssueRow]]:
    if scope not in SCOPES:
        raise ImportRequestError(f"scope must be one of {SCOPES}, got {scope!r}")
    existing_rows, existing = repo._existing_issues(s, engagement.asset_id)
    if scope == "test":
        scope_tests = [test.id]
    else:
        scope_tests = [t.id for t in repo.list_engagement_tests(s, engagement.id, org_id)]
    previous = _snapshot_issue_ids(s, org_id, scope_tests)
    other_scans = repo.import_snapshot_scan_ids(
        s, org_id, engagement.asset_id, exclude_test_ids=frozenset(scope_tests)
    )
    native = repo.latest_native_snapshot_scan_id(s, org_id, engagement.asset_id)
    if native is not None:
        other_scans.append(native)
    plan = plan_reimport(
        findings,
        existing,
        previous_issue_ids=previous,
        other_live_issue_ids=repo.issue_ids_in_scans(s, other_scans),
        close_missing=close_missing,
        new_issue_id=repo._new_issue_id,
    )
    return plan, existing_rows


def preview_import(
    s: Session,
    *,
    org_id: str,
    test_id: str,
    findings: list[Finding],
    close_missing: bool = True,
    scope: str = "test",
) -> ImportPreview:
    """Nothing is written. (A session that autoflushes is not touched either: this only reads.)"""
    test, engagement = _load(s, org_id, test_id)
    rekey_for_asset(s, engagement.asset_id, findings)
    plan, _ = _decide(
        s,
        org_id=org_id,
        test=test,
        engagement=engagement,
        findings=findings,
        close_missing=close_missing,
        scope=scope,
    )
    return ImportPreview(plan, close_missing, scope)


def apply_import(
    s: Session,
    *,
    org_id: str,
    test_id: str,
    findings: list[Finding],
    parser: str,
    file_digest: str,
    file_name: str | None = None,
    size_bytes: int = 0,
    close_missing: bool = True,
    scope: str = "test",
    created_by: str | None = None,
    warnings: list[str] | None = None,
    record: ImportRecord | None = None,
    components: Sequence[Mapping[str, Any]] = (),
) -> ImportResult:
    """Apply an import. The same file (same digest) as the Test's latest import is a no-op that
    returns that import's original result -- "idempotent" (plan §42.1) -- decided under a lock on
    the Test, so two simultaneous uploads of one file cannot both be applied.

    `record` is a queued ImportRecord (the API creates one before a worker parses the upload); it is
    completed in place instead of a new one being added. If it turns out to repeat the Test's latest
    import, it is marked `duplicate` and carries that import's counts."""
    try:
        _load(s, org_id, test_id)  # reject an unknown Test before taking any lock
        # Serialize imports into one Test: the snapshot we compare against must not move under us.
        # (Ignored by SQLite, which has no row locks and a single writer anyway.)
        locked = s.scalars(
            select(EngagementTest).where(EngagementTest.id == test_id).with_for_update()
        ).one()
        test, engagement = _load(s, org_id, test_id)
        latest = repo.latest_applied_import(s, test.id, org_id)
        if latest is not None and latest.file_digest == file_digest:
            if record is not None:
                record.status, record.upload_path, record.error = "duplicate", None, None
                for field in _COUNT_FIELDS:
                    setattr(record, field, getattr(latest, field))
                s.commit()
                return ImportResult(record, created=False)
            s.rollback()  # release the lock; nothing was written
            return ImportResult(latest, created=False)

        rekey_for_asset(
            s, engagement.asset_id, findings
        )  # before the plan, and before they are stored
        plan, existing_rows = _decide(
            s,
            org_id=org_id,
            test=locked,
            engagement=engagement,
            findings=findings,
            close_missing=close_missing,
            scope=scope,
        )
        now = datetime.now(timezone.utc)
        label = f"{test.name}: {file_name}" if file_name else test.name
        scan = Scan(
            org_id=org_id,
            status="completed",
            source_type="import",
            source_ref=file_name or f"import:{file_digest[:12]}",
            source_label=label[:300],
            tools=[parser],
            asset_id=engagement.asset_id,
            started_at=now,
            finished_at=now,
        )
        s.add(scan)
        s.flush()

        changes = repo.apply_reimport_plan(
            s,
            asset_id=engagement.asset_id,
            findings=findings,
            plan=plan,
            existing_rows=existing_rows,
            record_changes=True,
            retest_source=f"the upload into {test.name}",
        )
        # Issues first: a finding's issue_id is a foreign key, and one transaction has no commit
        # between the two to order them (SQLite never notices; Postgres does).
        s.flush()
        repo.add_findings(s, scan.id, findings, list(plan.updates), commit=False)
        if record is None:
            record = repo.add_import_record(
                s,
                org_id=org_id,
                test_id=test.id,
                scan_id=scan.id,
                parser=parser,
                file_digest=file_digest,
                file_name=file_name,
                size_bytes=size_bytes,
                close_missing=close_missing,
                scope=scope,
                created_by=created_by,
            )
        else:
            record.scan_id, record.close_missing, record.scope = scan.id, close_missing, scope
            # A Test's current snapshot is its latest import by time, and a queued import is created
            # before it is applied: re-stamp it, so application order is what "latest" means.
            record.created_at = now
        record.status, record.mode, record.upload_path, record.error = (
            "applied",
            "apply",
            None,
            None,
        )
        record.new_count = len(plan.new_issue_ids)
        record.unchanged_count = len(plan.unchanged_issue_ids)
        record.reopened_count = len(plan.reopened_issue_ids)
        record.closed_count = len(plan.closed_issue_ids)
        record.detached_count = len(plan.detached_issue_ids)
        record.warnings = list(warnings or [])
        record.changes = changes

        changed: frozenset[str] = frozenset()
        if components:  # an SBOM: its packages are this Test's part of the project's inventory
            changed = inventory.record(
                s, org_id=org_id, asset_id=engagement.asset_id, scan_id=scan.id,
                source=inventory.import_source(test.id), packages=components, commit=False,
            ).changed  # fmt: skip
        repo.stage_issue_events(
            s,
            org_id=org_id,
            asset_id=engagement.asset_id,
            scan_id=scan.id,
            plan=plan,
            source="import",
            import_id=record.id,
        )
        repo.add_outbox_event(
            s,
            org_id=org_id,
            event_type="scan.completed",
            payload={
                "scan_id": scan.id,
                "asset_id": engagement.asset_id,
                "status": "completed",
                "source": "import",
                "import_id": record.id,
                "counts": plan.counts,
            },
        )
        s.commit()
        return ImportResult(
            record, created=True, inventory_changed=changed, asset_id=engagement.asset_id
        )
    except Exception:
        s.rollback()
        raise


def revert_latest_import(s: Session, *, org_id: str, test_id: str) -> RevertResult:
    """Undo the most recent applied import into a Test (plan §42.1: "reversible -- for example when
    someone uploads last quarter's file by mistake"). Only the latest: reverting an older one would
    mean re-deriving every later import's diff.

    Each Issue is restored only if it is still in the state the import left it in. If a scan or
    another import has changed it since, that later change is the truth and is left alone (counted
    as `skipped`) -- an undo must never overwrite something newer than what it undoes."""
    try:
        _test, engagement = _load(s, org_id, test_id)
        s.scalars(
            select(EngagementTest).where(EngagementTest.id == test_id).with_for_update()
        ).one()
        record = repo.latest_applied_import(s, test_id, org_id)
        if record is None:
            raise ImportRequestError("this test has no applied import to revert")
        scan_id = record.scan_id

        restored = deleted = skipped = 0
        changed: frozenset[str] = frozenset()
        for change in record.changes:
            row = s.get(IssueRow, change["issue_id"])
            if row is None:
                continue
            if row.state != change.get("after_state"):
                skipped += 1
                continue
            if change["created"]:
                elsewhere = s.scalar(
                    select(func.count())
                    .select_from(FindingRow)
                    .where(FindingRow.issue_id == row.id, FindingRow.scan_id != scan_id)
                )
                if elsewhere:
                    skipped += 1  # another scan or import has since reported it: it is real now
                else:
                    s.delete(row)
                    deleted += 1
                continue
            prior = change["prior"]
            row.state = prior["state"]
            row.fixed_at = _dt(prior["fixed_at"])
            row.last_seen_at = _dt(prior["last_seen_at"]) or row.last_seen_at
            row.severity, row.title, row.path = prior["severity"], prior["title"], prior["path"]
            row.category = prior["category"]
            row.fingerprint = prior["fingerprint"]
            row.fallback_fingerprint = prior["fallback_fingerprint"]
            if "retest_status" in prior:  # records from before Week 64 carry no retest state
                row.retest_status, row.retest_note = prior["retest_status"], prior["retest_note"]
                row.retest_decided_at = _dt(prior["retest_decided_at"])
                row.retest_decided_by = prior["retest_decided_by"]
            restored += 1

        if scan_id is not None:
            s.flush()  # issue changes first, so the findings' issue_id FKs resolve cleanly
            s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
            record.scan_id = None
            changed = frozenset(inventory.forget_scan(s, scan_id))  # the previous SBOM is current
            s.flush()
            s.execute(delete(Scan).where(Scan.id == scan_id))
        record.status = "reverted"
        record.reverted_at = datetime.now(timezone.utc)
        repo.add_outbox_event(
            s,
            org_id=org_id,
            event_type="import.reverted",
            payload={"import_id": record.id, "test_id": test_id, "counts": _counts(record)},
        )
        s.commit()
        return RevertResult(
            record, restored=restored, deleted=deleted, skipped=skipped,
            inventory_changed=changed, asset_id=engagement.asset_id,
        )  # fmt: skip
    except Exception:
        s.rollback()
        raise


def _dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _counts(record: ImportRecord) -> dict[str, int]:
    return {
        "new": record.new_count,
        "unchanged": record.unchanged_count,
        "reopened": record.reopened_count,
        "closed": record.closed_count,
        "detached": record.detached_count,
    }


__all__ = [
    "ImportRequestError",
    "ImportPreview",
    "ImportResult",
    "RevertResult",
    "apply_import",
    "preview_import",
    "revert_latest_import",
]
