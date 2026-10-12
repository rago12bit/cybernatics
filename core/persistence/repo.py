"""Data access for scans, tool runs and findings."""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Collection, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, cast

from sqlalchemy import and_, case, delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

import core.audit as audit
import core.metrics  # noqa: F401  (marks metrics dirty when Issues change)
from core.assets import asset_key
from core.dast import ownership
from core.dast.mapping import crawl_samples, sampled_places
from core.dedup.settings import rekey_for_asset
from core.embeddings.chunk import CodeChunk
from core.imports.reimport import ReimportPlan, plan_reimport
from core.issues import (
    LIVE_STATES,
    ExistingIssue,
    IssueUpdate,
    State,
    SyncResult,
    classify_for_pr,
    fallback_key,
)
from core.models import Finding, finding_from_dict
from core.persistence.models import (
    DEFAULT_RETENTION_DAYS,
    SEVERITY_RANK,
    ApiToken,
    Asset,
    AssetVerification,
    AuditCheckpoint,
    AuditEntry,
    AutomationRule,
    CodeChunkIndexRow,
    CodeChunkRow,
    CopilotConversationRow,
    CopilotMessageRow,
    DataRetentionPolicyRow,
    Engagement,
    EngagementTest,
    ExternalIssueLinkRow,
    FindingRow,
    GithubInstallation,
    HypothesisRow,
    ImportRecord,
    IntegrationSettingsRow,
    IssueRow,
    Organization,
    OutboxEvent,
    PluginAllowlistRow,
    Portfolio,
    RiskAcceptanceIssue,
    Scan,
    ScanDataKeyRow,
    ThreatModelRow,
    ToolRun,
)
from core.rag.embed import HashingEmbedder
from core.tenancy import DEFAULT_ORG_ID, session_org, session_projects
from core.triage_assistant.contract import TriageVerdict

log = logging.getLogger(__name__)

TERMINAL = frozenset({"completed", "partial", "failed"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get_or_create_asset(
    s: Session, *, source_type: str, source_label: str, org_id: str = DEFAULT_ORG_ID
) -> Asset:
    """The row a repeated scan is matched against (ADR-0012). Identity is `core.assets.asset_key`
    scoped to one organization (ADR-0013) — two orgs scanning the same public repo get separate
    Assets, so neither sees the other's Issue history. The label is refreshed to the most recent
    scan's, since that's what a person actually reads."""
    key = asset_key(source_type, source_label)
    asset = s.scalars(
        select(Asset).where(
            Asset.org_id == org_id, Asset.source_type == source_type, Asset.key == key
        )
    ).one_or_none()
    if asset is None:
        asset = Asset(org_id=org_id, source_type=source_type, key=key, label=source_label)
        s.add(asset)
    else:
        asset.label, asset.last_scanned_at = source_label, _now()
    s.commit()
    return asset


def get_or_create_ci_engagement(s: Session, *, asset_id: str, org_id: str) -> Engagement:
    """Every Asset's one standing "ci" Engagement (plan §40 change C11, Week 53, ADR-0039) --
    created lazily on an asset's first ToolRun, the same way migration 0026 backfilled one for every
    pre-existing Asset, so a project created before or after this feature shipped always has exactly
    one. Idempotent: a second call for the same asset returns the same row, never a duplicate."""
    existing = s.scalars(
        select(Engagement).where(
            Engagement.asset_id == asset_id, Engagement.org_id == org_id,
            Engagement.engagement_type == "ci",
        )
    ).first()  # fmt: skip
    if existing is not None:
        return existing
    asset = s.get(Asset, asset_id)
    label = asset.label if asset is not None else asset_id
    engagement = Engagement(
        org_id=org_id, asset_id=asset_id, name=f"{label} CI", engagement_type="ci", status="active"
    )
    s.add(engagement)
    s.commit()
    return engagement


def get_or_create_import_engagement(s: Session, *, asset_id: str, org_id: str) -> Engagement:
    """The standing "import" Engagement of an asset (ADR-0040): the default home for a report
    uploaded without naming an engagement, created lazily the way the "ci" one is. A pen test or
    audit that needs its own scope, dates and lead is a separate "assessment" engagement a person
    creates explicitly (`create_engagement`); this one is just "reports from tools we don't run"."""
    existing = s.scalars(
        select(Engagement).where(
            Engagement.asset_id == asset_id,
            Engagement.org_id == org_id,
            Engagement.engagement_type == "import",
        )
    ).first()
    if existing is not None:
        return existing
    asset = s.get(Asset, asset_id)
    label = asset.label if asset is not None else asset_id
    engagement = Engagement(
        org_id=org_id, asset_id=asset_id, name=f"{label} imports", engagement_type="import"
    )
    s.add(engagement)
    s.commit()
    return engagement


def create_portfolio(
    s: Session, *, org_id: str, name: str, description: str | None = None
) -> Portfolio:
    portfolio = Portfolio(org_id=org_id, name=name, description=description)
    s.add(portfolio)
    s.commit()
    return portfolio


def list_portfolios(s: Session, org_id: str) -> list[Portfolio]:
    return list(
        s.scalars(select(Portfolio).where(Portfolio.org_id == org_id).order_by(Portfolio.name))
    )


def get_portfolio(s: Session, portfolio_id: str, org_id: str) -> Portfolio | None:
    return s.scalars(
        select(Portfolio).where(Portfolio.id == portfolio_id, Portfolio.org_id == org_id)
    ).one_or_none()


def create_engagement(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    name: str,
    engagement_type: str = "adhoc",
    portfolio_id: str | None = None,
    target_end_at: datetime | None = None,
) -> Engagement:
    """A person-created Engagement -- "pentest"/"audit"/"adhoc" (plan §40 change C11): distinct from
    `get_or_create_ci_engagement`'s own lazily-created, singleton "ci" one, and never that type
    itself (a second "ci" engagement for the same asset would split its ToolRun history across two
    rows, defeating the one-standing-engagement invariant that function maintains)."""
    if engagement_type == "ci":
        raise ValueError('engagement_type "ci" is reserved for get_or_create_ci_engagement')
    engagement = Engagement(
        org_id=org_id, asset_id=asset_id, portfolio_id=portfolio_id, name=name,
        engagement_type=engagement_type, target_end_at=target_end_at,
        status="in_progress",  # the assessment lifecycle (Week 64, `core.engagements`)
    )  # fmt: skip
    s.add(engagement)
    s.commit()
    return engagement


def get_engagement(s: Session, engagement_id: str, org_id: str) -> Engagement | None:
    return s.scalars(
        select(Engagement).where(Engagement.id == engagement_id, Engagement.org_id == org_id)
    ).one_or_none()


def list_engagements_for_asset(s: Session, asset_id: str, org_id: str) -> list[Engagement]:
    return list(
        s.scalars(
            select(Engagement)
            .where(Engagement.asset_id == asset_id, Engagement.org_id == org_id)
            .order_by(Engagement.started_at.desc())
        )
    )


def list_tool_runs_for_engagement(s: Session, engagement_id: str, org_id: str) -> list[ToolRun]:
    """The Tests (plan §40/§42) within one Engagement -- a ToolRun joined back through `scans` to
    confirm org membership, the same EXISTS-through-the-parent shape `tool_runs`' own RLS policy
    already uses (migration 0005), so an engagement id from another org can't be used to read
    another org's tool runs even if RLS were somehow bypassed at the application layer too."""
    return list(
        s.scalars(
            select(ToolRun)
            .join(Scan, Scan.id == ToolRun.scan_id)
            .where(ToolRun.engagement_id == engagement_id, Scan.org_id == org_id)
            .order_by(ToolRun.id.desc())
        )
    )


def get_or_create_engagement_test(
    s: Session, *, org_id: str, engagement_id: str, name: str, parser: str | None = None
) -> EngagementTest:
    """The persistent Test (ADR-0040) an uploaded report is reimported into, created on first use
    and reused after: a second upload "into the same Test" must find the same row, or there would
    be no previous snapshot to compare against. Raises ValueError for an engagement that isn't in
    this org (or doesn't exist) rather than minting a Test under someone else's engagement.

    Engagement types for person-created work are free text; the plan names "assessment" and
    "import" alongside the "ci" one `get_or_create_ci_engagement` owns."""
    if get_engagement(s, engagement_id, org_id) is None:
        raise ValueError(f"engagement {engagement_id} not found")
    existing = s.scalars(
        select(EngagementTest).where(
            EngagementTest.engagement_id == engagement_id,
            EngagementTest.org_id == org_id,
            EngagementTest.name == name,
        )
    ).one_or_none()
    if existing is not None:
        return existing
    test = EngagementTest(org_id=org_id, engagement_id=engagement_id, name=name, parser=parser)
    s.add(test)
    s.commit()
    return test


def get_engagement_test(s: Session, test_id: str, org_id: str) -> EngagementTest | None:
    return s.scalars(
        select(EngagementTest).where(EngagementTest.id == test_id, EngagementTest.org_id == org_id)
    ).one_or_none()


def list_engagement_tests(s: Session, engagement_id: str, org_id: str) -> list[EngagementTest]:
    return list(
        s.scalars(
            select(EngagementTest)
            .where(EngagementTest.engagement_id == engagement_id, EngagementTest.org_id == org_id)
            .order_by(EngagementTest.name)
        )
    )


def list_tests_for_asset(
    s: Session, asset_id: str, org_id: str
) -> list[tuple[EngagementTest, Engagement]]:
    """Every persistent Test of a project with its engagement, for choosing where an upload goes."""
    return [
        (t, e)
        for t, e in s.execute(
            select(EngagementTest, Engagement)
            .join(Engagement, Engagement.id == EngagementTest.engagement_id)
            .where(Engagement.asset_id == asset_id, EngagementTest.org_id == org_id)
            .order_by(Engagement.name, EngagementTest.name)
        )
    ]


def add_import_record(
    s: Session,
    *,
    org_id: str,
    test_id: str,
    scan_id: str | None,
    parser: str,
    file_digest: str,
    file_name: str | None = None,
    size_bytes: int = 0,
    close_missing: bool = True,
    scope: str = "test",
    created_by: str | None = None,
    status: str = "applied",
    mode: str = "apply",
    upload_path: str | None = None,
) -> ImportRecord:
    """Stages (does not commit) a new ImportRecord: the ingest service writes it in the same
    transaction as the Issue changes it describes, so a crash can't leave one without the other."""
    record = ImportRecord(
        org_id=org_id, test_id=test_id, scan_id=scan_id, parser=parser, file_digest=file_digest,
        file_name=file_name, size_bytes=size_bytes, close_missing=close_missing, scope=scope,
        created_by=created_by, status=status, mode=mode, upload_path=upload_path,
    )  # fmt: skip
    s.add(record)
    s.flush()
    return record


def get_import_record(s: Session, import_id: str, org_id: str) -> ImportRecord | None:
    return s.scalars(
        select(ImportRecord).where(ImportRecord.id == import_id, ImportRecord.org_id == org_id)
    ).one_or_none()


def list_import_records(
    s: Session, test_id: str, org_id: str, *, limit: int = 50
) -> list[ImportRecord]:
    """A Test's import history, newest first -- the "import history with counts" (plan §54)."""
    return list(
        s.scalars(
            select(ImportRecord)
            .where(ImportRecord.test_id == test_id, ImportRecord.org_id == org_id)
            .order_by(ImportRecord.created_at.desc(), ImportRecord.id.desc())
            .limit(limit)
        )
    )


def latest_applied_import(s: Session, test_id: str, org_id: str) -> ImportRecord | None:
    """The Test's current snapshot: what the next upload is compared against, and the only import
    that can be reverted (ADR-0040). A reverted import is history, not a snapshot."""
    return s.scalars(
        select(ImportRecord)
        .where(
            ImportRecord.test_id == test_id,
            ImportRecord.org_id == org_id,
            ImportRecord.status == "applied",
        )
        .order_by(ImportRecord.created_at.desc(), ImportRecord.id.desc())
        .limit(1)
    ).one_or_none()


def add_outbox_event(
    s: Session, *, org_id: str, event_type: str, payload: dict[str, Any]
) -> OutboxEvent:
    """Stages (does not commit) a domain event -- the outbox pattern (plan §41.1): it commits or
    rolls back together with the change that caused it, so "saved" and "announced" can't diverge."""
    event = OutboxEvent(org_id=org_id, event_type=event_type, payload=payload)
    s.add(event)
    return event


def pending_outbox_events(s: Session, org_id: str, *, limit: int = 100) -> list[OutboxEvent]:
    return list(
        s.scalars(
            select(OutboxEvent)
            .where(OutboxEvent.org_id == org_id, OutboxEvent.dispatched_at.is_(None))
            .order_by(OutboxEvent.id)
            .limit(limit)
        )
    )


def mark_outbox_dispatched(s: Session, org_id: str, event_ids: list[int]) -> None:
    """One statement: loading the batch's rows to set them one by one took 78 ms per 500."""
    s.execute(
        update(OutboxEvent)
        .where(OutboxEvent.org_id == org_id, OutboxEvent.id.in_(event_ids))
        .values(dispatched_at=_now())
        .execution_options(synchronize_session=False)
    )
    s.commit()


def create_scan(
    s: Session,
    *,
    source_type: str,
    source_ref: str,
    source_label: str,
    tools: list[str],
    org_id: str = DEFAULT_ORG_ID,
    ref: str | None = None,
    asset_label: str | None = None,
    github_repo: str | None = None,
    github_pr_number: int | None = None,
    github_installation_id: str | None = None,
    github_head_sha: str | None = None,
) -> Scan:
    """`asset_label` (plan §36, PR mode): the identity a PR-triggered scan's Asset is matched
    against must be the repository's own normalized URL, same as an ordinary scan of it -- not the
    "owner/repo#42" string `source_label` displays for this one scan -- or a PR scan would resolve
    to its own throwaway per-PR Asset instead of the repository's real one, and "new in this PR"
    would compare against nothing every time. Defaults to `source_label`, unchanged for every
    caller that only ever scans a whole repository (there, the two are already the same thing)."""
    asset = get_or_create_asset(
        s, source_type=source_type, source_label=asset_label or source_label, org_id=org_id
    )
    scan = Scan(
        org_id=org_id,
        source_type=source_type,
        source_ref=source_ref,
        source_label=source_label,
        tools=tools,
        asset_id=asset.id,
        ref=ref,
        github_repo=github_repo,
        github_pr_number=github_pr_number,
        github_installation_id=github_installation_id,
        github_head_sha=github_head_sha,
    )
    s.add(scan)
    s.commit()
    return scan


def create_dast_campaign(
    s: Session, *, asset: Asset, mode: str, org_id: str = DEFAULT_ORG_ID
) -> Scan:
    """Unlike `create_scan`, this never calls `get_or_create_asset`: the Asset must already exist
    and already be ownership-verified (`core.dast.ownership`) by the time a campaign is allowed to
    start -- the caller (the API endpoint) is responsible for that gate, not this function."""
    from core.dast.campaign import tools_for_mode

    scan = Scan(
        org_id=org_id,
        source_type="web",
        source_ref=f"https://{asset.key}",
        source_label=asset.key,
        tools=list(tools_for_mode(mode)),
        asset_id=asset.id,
        dast_mode=mode,
    )
    s.add(scan)
    s.commit()
    return scan


def last_active_campaign_started_at(
    s: Session, asset_id: str, *, org_id: str | None = None, exclude_scan_id: str | None = None
) -> datetime | None:
    """The most recent ACTIVE campaign's start time for this asset -- what `core.dast.campaign.
    check_active_scan_rate_limit` compares "now" against. Passive campaigns never count: the rate
    limit polices back-to-back active scans specifically (see that function's own docstring).

    `exclude_scan_id`: the worker's own re-check (`core.dast.pipeline.run_dast_campaign_job`) must
    not count the very campaign it's currently running as "the most recent prior one," or every
    active campaign would rate-limit itself against its own start time. Filtering by id here is
    exact and unambiguous -- comparing timestamps instead (e.g. "is this the same moment as my own
    created_at?") breaks under SQLite, which returns naive datetimes even for tz-aware columns."""
    q = (
        select(Scan.created_at)
        .where(Scan.asset_id == asset_id, Scan.dast_mode == "active")
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    if exclude_scan_id is not None:
        q = q.where(Scan.id != exclude_scan_id)
    started_at = s.scalars(q).first()
    if started_at is not None and started_at.tzinfo is None:  # SQLite drops tzinfo even here
        started_at = started_at.replace(tzinfo=timezone.utc)
    return started_at


def list_dast_campaigns(
    s: Session, asset_id: str, *, org_id: str | None = None, limit: int = 20
) -> list[Scan]:
    q = (
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.dast_mode.is_not(None))
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    return list(s.scalars(q))


def list_scans(s: Session, limit: int = 20, *, org_id: str | None = None) -> list[Scan]:
    """`org_id=None` is a trusted-internal, unscoped read (no such caller is left in the API; every
    client-facing endpoint passes the request's real org). Application-level filtering here is
    belt-and-suspenders alongside Postgres RLS (ADR-0013) — SQLite test runs have no RLS, so this
    is what actually proves isolation in the fast test suite."""
    # An import (ADR-0040) is stored as a scan so its findings keep their foreign keys and RLS, but
    # it is a file someone uploaded, not a scan someone ran: "recent scans" is not where it belongs
    # (its history is under its Test), though its own scan page still opens by id.
    q = (
        select(Scan)
        .where(Scan.source_type != "import")
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    return list(s.scalars(q))


def get_scan(s: Session, scan_id: str, *, org_id: str | None = None) -> Scan | None:
    """`org_id=None` is the trusted-internal read the worker uses (it already knows the exact scan
    id it was dispatched for; there is no cross-tenant question to ask). Every client-facing API
    lookup passes the request's real org, so a scan in a different org is invisible, not just
    unauthorized — a 404, never a 403 (ADR-0013)."""
    scan = s.get(Scan, scan_id)
    if scan is None or (org_id is not None and scan.org_id != org_id):
        return None
    return scan


def scan_compute_seconds(s: Session, scan_id: str) -> float:
    """Sum of every real scanner's own wall-clock time for this scan (`ToolRun.duration_seconds`,
    Week 50 plan §23's cost dashboard) -- the scanner-compute half of a scan's estimated cost."""
    total = s.scalar(
        select(func.coalesce(func.sum(ToolRun.duration_seconds), 0.0)).where(
            ToolRun.scan_id == scan_id
        )
    )
    return float(total or 0.0)


def cost_summary_scans(s: Session, *, org_id: str, since: datetime) -> list[tuple[Scan, float]]:
    """Every scan for `org_id` created since `since`, paired with its own summed scanner compute
    time -- one query, not one-per-scan (Week 50 plan §23's cost dashboard)."""
    compute = (
        select(ToolRun.scan_id, func.coalesce(func.sum(ToolRun.duration_seconds), 0.0).label("cs"))
        .group_by(ToolRun.scan_id)
        .subquery()
    )
    rows = s.execute(
        select(Scan, func.coalesce(compute.c.cs, 0.0))
        .outerjoin(compute, compute.c.scan_id == Scan.id)
        .where(Scan.org_id == org_id, Scan.created_at >= since)
        .order_by(Scan.created_at.desc())
    ).all()
    return [(scan, float(cs)) for scan, cs in rows]


# ---------------------------------------------------------------------------------------------
# Assets as projects (plan §27): the project overview screen (Week 33, §28.1) is built entirely
# from data that already exists -- Asset (ADR-0012), IssueRow's lifecycle timestamps, and the same
# risk-sorted FindingRow query the scan-scoped "Fix first" widget already uses. Nothing here is a
# new source of truth.
# ---------------------------------------------------------------------------------------------

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def list_assets(s: Session, *, org_id: str | None = None, limit: int = 50) -> list[Asset]:
    q = select(Asset).order_by(Asset.last_scanned_at.desc()).limit(limit)
    if org_id is not None:
        q = q.where(Asset.org_id == org_id)
    visible = session_projects(s)  # Week 75: a person limited to some projects (RLS does too)
    if visible is not None:
        q = q.where(Asset.id.in_(visible))
    return list(s.scalars(q))


def get_asset(s: Session, asset_id: str, *, org_id: str | None = None) -> Asset | None:
    asset = s.get(Asset, asset_id)
    if asset is None or (org_id is not None and asset.org_id != org_id):
        return None
    visible = session_projects(s)
    if visible is not None and asset.id not in visible:
        return None
    return asset


# ---------------------------------------------------------------------------------------------
# Web assets and ownership verification (Week 49 task 1, plan §22.4, ADR-0035).
# ---------------------------------------------------------------------------------------------


def register_web_asset(
    s: Session,
    *,
    domain: str,
    method: str,
    org_id: str = DEFAULT_ORG_ID,
    source_asset_id: str | None = None,
) -> tuple[Asset, AssetVerification]:
    """Registering the same domain again replaces its verification row with a fresh token and
    resets status to `pending` (`merge`, not `add`) -- deliberately invalidating whatever DNS/
    well-known record was published for the previous token, since there is no way to tell from here
    whether the person re-registering is the same owner choosing a different method or losing access
    to the first one.

    `source_asset_id` (Week 49 task 4, plan §22.4): optionally links this web target to the git/
    archive Asset whose SAST scans provide the route map DAST correlation needs. Must already exist
    in the SAME org -- raises `ValueError` otherwise, rather than silently either ignoring it or
    linking across a tenant boundary. `set_web_asset_source` changes it later."""
    if source_asset_id is not None:
        _source_project(s, source_asset_id, org_id)
    asset = get_or_create_asset(s, source_type="web", source_label=domain, org_id=org_id)
    if source_asset_id is not None:
        asset.linked_source_asset_id = source_asset_id
    verification = AssetVerification(
        asset_id=asset.id,
        method=method,
        token=ownership.generate_token(),
        status="pending",
    )
    merged = s.merge(verification)
    s.commit()
    return asset, merged


def _source_project(s: Session, source_asset_id: str, org_id: str) -> Asset:
    """A project a web target's code can come from: in the same organization, and code (a git
    repository or an archive), not another site."""
    source = get_asset(s, source_asset_id, org_id=org_id)
    if source is None:
        raise ValueError(f"source_asset_id {source_asset_id!r} not found in this organization")
    if source.source_type == "web":
        raise ValueError("a web target's source is a code project (git or archive), not a site")
    return source


def set_web_asset_source(
    s: Session, asset: Asset, source_asset_id: str | None, *, org_id: str, actor: str
) -> Asset:
    """Link a web target to the project its code is in, change the link, or (None) remove it --
    after registration, without registering again, so its verification is untouched. Audit-logged
    when it changes (commits). Raises `ValueError` for a target that is not a site or a source that
    is not a code project of the same organization."""
    if asset.source_type != "web":
        raise ValueError("only a web target links to source code")
    if source_asset_id is not None:
        _source_project(s, source_asset_id, org_id)
    previous = asset.linked_source_asset_id
    if previous == source_asset_id:
        return asset
    asset.linked_source_asset_id = source_asset_id
    s.flush()
    action = "asset.source.linked" if source_asset_id else "asset.source.unlinked"
    append_audit_entry(  # commits
        s, actor=actor, action=action, target=asset.id,
        payload={"org_id": org_id, "source_asset_id": source_asset_id, "previous": previous},
    )  # fmt: skip
    return asset


def get_asset_verification(
    s: Session, asset_id: str, *, org_id: str | None = None
) -> AssetVerification | None:
    asset = get_asset(s, asset_id, org_id=org_id)
    if asset is None:
        return None
    return s.get(AssetVerification, asset_id)


def record_verification_check(
    s: Session, verification: AssetVerification, *, ok: bool, error: str | None
) -> AssetVerification:
    now = _now()
    verification.last_checked_at = now
    verification.last_error = error
    verification.status = "verified" if ok else "failed"
    if ok and verification.verified_at is None:
        verification.verified_at = now
    s.commit()
    return verification


def is_asset_verified(s: Session, asset_id: str, *, org_id: str | None = None) -> bool:
    """The cached status from the last check -- cheap, used for list/display views. A DAST campaign
    starting must call `core.dast.ownership.verify` live instead of trusting this (plan §22.4: "re-
    checked before every campaign"), since a domain can be reassigned or a DNS/well-known record
    removed at any time after a past check passed."""
    verification = get_asset_verification(s, asset_id, org_id=org_id)
    return verification is not None and verification.status == "verified"


def latest_scan_for_asset(
    s: Session, asset_id: str, *, org_id: str | None = None, statuses: frozenset[str] = TERMINAL
) -> Scan | None:
    """The most recent scan of this asset that actually finished -- a queued or running scan has
    no findings to build an overview from yet. An import (ADR-0040) is stored as a scan but is a
    different thing -- a file someone uploaded -- so it is never "the latest scan"."""
    q = (
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.source_type != "import")
        .order_by(Scan.created_at.desc())
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    for scan in s.scalars(q):
        if scan.status in statuses:
            return scan
    return None


def previous_scan_for_asset(
    s: Session,
    asset_id: str,
    before: Scan,
    *,
    org_id: str | None = None,
    statuses: frozenset[str] = TERMINAL,
) -> Scan | None:
    """The completed scan immediately before `before`, for "since previous scan" deltas."""
    q = (
        select(Scan)
        .where(
            Scan.asset_id == asset_id,
            Scan.created_at < before.created_at,
            Scan.source_type != "import",
        )
        .order_by(Scan.created_at.desc())
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    for scan in s.scalars(q):
        if scan.status in statuses:
            return scan
    return None


def since_previous_scan_counts(
    s: Session, asset_id: str, latest_scan_id: str, previous: Scan | None
) -> dict[str, int]:
    """Fixed/new/returned since the scan before this one. "new" and "returned" come straight from
    `issue_counts` (already computed at sync time, ADR-0012's new/reintroduced states); "fixed"
    isn't in that table (a fixed issue has no row in the *new* scan to count), so it's counted
    directly: issues that flipped to `fixed` after the previous scan finished. `previous=None`
    (this is the asset's first scan) floors the window at the epoch, so every currently-fixed issue
    counts once, not zero."""
    counts = issue_counts(s, latest_scan_id)
    since = previous.finished_at if previous is not None and previous.finished_at else EPOCH
    if since.tzinfo is None:  # SQLite returns naive datetimes even for tz-aware columns
        since = since.replace(tzinfo=timezone.utc)
    fixed = (
        s.scalar(
            select(func.count())
            .select_from(IssueRow)
            .where(
                IssueRow.asset_id == asset_id,
                IssueRow.state == "fixed",
                IssueRow.fixed_at.is_not(None),
                IssueRow.fixed_at > since,
            )
        )
        or 0
    )
    return {"fixed": fixed, "new": counts.get("new", 0), "returned": counts.get("reintroduced", 0)}


def open_issue_trend(
    s: Session, asset_id: str, *, points: int = 7, org_id: str | None = None
) -> list[dict[str, Any]]:
    """Open-issue count at each of the last `points` completed scans, oldest first -- reconstructed
    from IssueRow's first_seen_at/fixed_at rather than stored per-scan, since nothing snapshots that
    today. An issue counts as open as of a scan if it existed by then and wasn't fixed yet (or was
    fixed later)."""
    q = (
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.status.in_(TERMINAL), Scan.finished_at.is_not(None))
        .order_by(Scan.created_at.desc())
        .limit(points)
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    scans = list(reversed(list(s.scalars(q))))
    out: list[dict[str, Any]] = []
    for scan in scans:
        finished = scan.finished_at
        assert finished is not None
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=timezone.utc)
        open_count = (
            s.scalar(
                select(func.count())
                .select_from(IssueRow)
                .where(
                    IssueRow.asset_id == asset_id,
                    IssueRow.first_seen_at <= finished,
                    or_(IssueRow.fixed_at.is_(None), IssueRow.fixed_at > finished),
                )
            )
            or 0
        )
        out.append({"scan_id": scan.id, "finished_at": scan.finished_at, "open_count": open_count})
    return out


@dataclass
class ScanComparison:
    """Plan §28.6/§36: two of one asset's scans, side by side. `earlier`/`later` are ordered by
    `created_at`, not by which one the caller happened to pass first."""

    earlier: Scan
    later: Scan
    new: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    reintroduced: list[dict[str, Any]] = field(default_factory=list)
    unchanged: list[dict[str, Any]] = field(default_factory=list)


def compare_scans(
    s: Session, scan_id_a: str, scan_id_b: str, *, org_id: str
) -> ScanComparison | None:
    """Categorize the issues between two scans of the *same* asset: new, fixed, reintroduced,
    unchanged (plan §28.6's scan comparison screen). `None` if either scan doesn't exist in this
    org, or the two don't share an asset -- comparing across assets is meaningless.

    An issue present in `later` but not `earlier` is "reintroduced" rather than "new" if it already
    existed by `earlier`'s time (first seen at or before `earlier` finished) -- it was absent from
    that specific scan, then came back, exactly like the reintroduced state `core.issues.sync`
    already tracks, just evaluated against these two scans specifically rather than "now".
    """
    a, b = get_scan(s, scan_id_a, org_id=org_id), get_scan(s, scan_id_b, org_id=org_id)
    if a is None or b is None or a.asset_id is None or a.asset_id != b.asset_id:
        return None
    earlier, later = (a, b) if a.created_at <= b.created_at else (b, a)

    def issue_ids(scan_id: str) -> set[str]:
        rows = s.scalars(
            select(FindingRow.issue_id).where(
                FindingRow.scan_id == scan_id, FindingRow.issue_id.is_not(None)
            )
        )
        return {r for r in rows if r is not None}

    ids_earlier, ids_later = issue_ids(earlier.id), issue_ids(later.id)
    all_ids = ids_earlier | ids_later
    issue_rows = (
        {r.id: r for r in s.scalars(select(IssueRow).where(IssueRow.id.in_(all_ids)))}
        if all_ids
        else {}
    )
    earlier_end = earlier.finished_at or earlier.created_at
    if earlier_end.tzinfo is None:  # SQLite returns naive datetimes even for tz-aware columns
        earlier_end = earlier_end.replace(tzinfo=timezone.utc)

    result = ScanComparison(earlier, later)
    for issue_id in all_ids:
        row = issue_rows.get(issue_id)
        if row is None:  # deleted since (org data-deletion, ADR-0007) -- nothing left to show
            continue
        view = {
            "id": row.id, "title": row.title, "severity": row.severity,
            "category": row.category, "path": row.path,
        }  # fmt: skip
        in_earlier, in_later = issue_id in ids_earlier, issue_id in ids_later
        if in_earlier and in_later:
            result.unchanged.append(view)
        elif in_earlier:
            result.fixed.append(view)
        else:
            first_seen = row.first_seen_at
            if first_seen.tzinfo is None:
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            (result.reintroduced if first_seen <= earlier_end else result.new).append(view)
    return result


# ---------------------------------------------------------------------------------------------
# Issues (Week 34, plan §28.3): the asset-level, cross-scan view of currently-open findings.
# "Currently open" for an asset's *latest* scan is exactly that scan's FindingRows carrying an
# issue_id -- any Issue not found there was necessarily marked `fixed` when that scan synced
# (core/issues.py), so there's no separate "is this issue still live" query to write. The only new
# thing this section adds is triage: a human decision layered on top of that.
# ---------------------------------------------------------------------------------------------

ACTIVE_TRIAGE_STATUSES = ("open",)  # the default queue: everything not deliberately set aside


def _active_triage_clause(now: datetime) -> ColumnElement[bool]:
    """An issue counts as "still in the active queue" if it's untouched, OR it was accepted but
    that acceptance has since expired (§28.3: accepted risk "reappears automatically")."""
    return or_(
        IssueRow.triage_status == "open",
        and_(
            IssueRow.triage_status == "accepted",
            IssueRow.triage_expires_at.is_not(None),
            IssueRow.triage_expires_at <= now,
        ),
    )


def list_asset_issues(
    s: Session,
    asset_id: str,
    latest_scan_id: str | Sequence[str],
    *,
    severities: list[str] | None = None,
    categories: list[str] | None = None,
    triage: list[str] | None = None,
    issue_filter: ColumnElement[bool] | None = None,
    sort: str = "risk",
    limit: int = 100,
    offset: int = 0,
) -> FindingPage:
    """Findings from the asset's latest scan, each annotated with its Issue's triage state.
    `issue_filter` narrows by any condition on the Issue (the SLA filter, `core.sla.service`).
    `triage=None` (the default) is the active triage queue: untouched issues, plus any accepted
    issue whose expiry has passed. Pass an explicit list (e.g. `["accepted", "not_a_risk"]`) to see
    triaged-away issues instead.

    Several scans (`latest_scan_id` a list, Week 74): the project's current snapshots -- its latest
    scan and each Test's latest applied import (`open_snapshot_scan_ids`) -- with one row per Issue:
    the first scan's occurrence when it has one, else the newest import's."""
    scan_ids = [latest_scan_id] if isinstance(latest_scan_id, str) else list(latest_scan_id)
    conds: list[ColumnElement[bool]] = [
        FindingRow.scan_id.in_(scan_ids),
        FindingRow.issue_id.is_not(None),
    ]
    if severities:
        conds.append(FindingRow.severity.in_([x.upper() for x in severities]))
    if categories:
        conds.append(FindingRow.category.in_([x.lower() for x in categories]))
    if len(scan_ids) > 1:  # one occurrence per Issue
        first = select(FindingRow.issue_id).where(
            FindingRow.scan_id == scan_ids[0], FindingRow.issue_id.is_not(None)
        )
        newest_elsewhere = (
            select(func.max(FindingRow.pk))
            .where(FindingRow.scan_id.in_(scan_ids[1:]), FindingRow.issue_id.not_in(first))
            .group_by(FindingRow.issue_id)
        )
        conds.append(or_(FindingRow.scan_id == scan_ids[0], FindingRow.pk.in_(newest_elsewhere)))

    # An Issue a tester or a targeted retest confirmed fixed (Week 64) can still have an occurrence
    # in the latest scan; it leaves the table until a scan reports it again.
    issue_ids_q = select(IssueRow.id).where(
        IssueRow.asset_id == asset_id, IssueRow.state != "fixed"
    )
    if triage:
        issue_ids_q = issue_ids_q.where(IssueRow.triage_status.in_(triage))
    else:
        issue_ids_q = issue_ids_q.where(_active_triage_clause(_now()))
    if issue_filter is not None:
        issue_ids_q = issue_ids_q.where(issue_filter)
    conds.append(FindingRow.issue_id.in_(issue_ids_q))

    total = s.scalar(select(func.count()).select_from(FindingRow).where(*conds)) or 0
    # Priority (Week 63, plan §44.3) is the Issue's; v2's score on the occurrence breaks ties
    # (scores capped at 100) and covers an Issue not ranked yet.
    v2 = func.coalesce(FindingRow.risk_score, -1)
    priority = func.coalesce(IssueRow.priority_score, FindingRow.risk_score, -1)
    order: list[Any]
    if sort == "path":
        order = [FindingRow.path, FindingRow.start_line]
    elif sort == "risk":
        order = [priority.desc(), v2.desc()]
    else:
        order = [
            FindingRow.severity_rank.desc(),
            priority.desc(),
            v2.desc(),
            FindingRow.path,
            FindingRow.start_line,
        ]
    rows = list(
        s.scalars(
            select(FindingRow)
            .join(IssueRow, IssueRow.id == FindingRow.issue_id)
            .where(*conds)
            .order_by(*order, FindingRow.pk)
            .limit(limit)
            .offset(offset)
        )
    )
    issue_ids = [r.issue_id for r in rows if r.issue_id]
    triage_by_id = (
        {i.id: i for i in s.scalars(select(IssueRow).where(IssueRow.id.in_(issue_ids)))}
        if issue_ids
        else {}
    )
    items = []
    for r in rows:
        d = {**r.data, "scan_id": r.scan_id}
        issue_row = triage_by_id.get(r.issue_id) if r.issue_id else None
        d["issue"] = (
            {
                "id": r.issue_id,
                "state": r.issue_state,
                "triage_status": issue_row.triage_status if issue_row else "open",
                "triage_reason": issue_row.triage_reason if issue_row else None,
                "triage_justification": issue_row.triage_justification if issue_row else None,
                "triage_expires_at": issue_row.triage_expires_at if issue_row else None,
                "first_seen_at": issue_row.first_seen_at if issue_row else None,
                "confirmed_at_runtime_at": (
                    issue_row.confirmed_at_runtime_at if issue_row else None
                ),
                "priority": _priority_view(issue_row),
                "retest_status": issue_row.retest_status if issue_row else None,
            }
            if r.issue_id
            else None
        )
        items.append(d)
    return FindingPage(total, items)


def _priority_view(issue: IssueRow | None) -> dict[str, Any] | None:
    from core.priority.service import view

    return view(issue)


def get_issue(s: Session, issue_id: str, *, org_id: str | None = None) -> IssueRow | None:
    """App-level org check (belt-and-suspenders alongside Postgres RLS, ADR-0013) -- `issues` has
    no `org_id` column of its own, so this joins through `assets`, exactly like the RLS policy
    itself does (migration 0005)."""
    q = select(IssueRow).where(IssueRow.id == issue_id)
    if org_id is not None:
        q = q.join(Asset, Asset.id == IssueRow.asset_id).where(Asset.org_id == org_id)
    visible = session_projects(s)
    if visible is not None:
        q = q.where(IssueRow.asset_id.in_(visible))
    return s.scalars(q).one_or_none()


def latest_occurrence_scan_id(s: Session, issue_id: str) -> str | None:
    """The scan (a native scan or an import) holding this issue's most recent occurrence. An issue
    only an import or a manual finding reported (ADR-0040, ADR-0044) has no occurrence in the
    asset's latest native scan, but is an Issue all the same and must be openable."""
    return s.scalar(
        select(FindingRow.scan_id)
        .join(Scan, Scan.id == FindingRow.scan_id)
        .where(FindingRow.issue_id == issue_id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )


def get_issue_finding(s: Session, issue_id: str, latest_scan_id: str) -> dict[str, Any] | None:
    """The full canonical Finding for one issue's detail screen (plan §28.3) -- its occurrence in
    the asset's latest scan, the same source `list_asset_issues` reads, just for one issue instead
    of a page of them."""
    row = s.scalar(
        select(FindingRow).where(
            FindingRow.scan_id == latest_scan_id, FindingRow.issue_id == issue_id
        )
    )
    if row is None:
        return None
    issue_row = s.get(IssueRow, issue_id)
    d = {**row.data, "scan_id": latest_scan_id}
    d["issue"] = {
        "id": issue_id,
        "state": row.issue_state,
        "triage_status": issue_row.triage_status if issue_row else "open",
        "triage_reason": issue_row.triage_reason if issue_row else None,
        "triage_justification": issue_row.triage_justification if issue_row else None,
        "triage_expires_at": issue_row.triage_expires_at if issue_row else None,
        "first_seen_at": issue_row.first_seen_at if issue_row else None,
        "assistant_verdict": issue_row.assistant_verdict if issue_row else None,
        "assistant_verdict_confidence": (
            issue_row.assistant_verdict_confidence if issue_row else None
        ),
        "assistant_verdict_rationale": issue_row.assistant_verdict_rationale if issue_row else None,
        "assistant_verdict_lines": issue_row.assistant_verdict_lines if issue_row else None,
        "assistant_verdict_model": issue_row.assistant_verdict_model if issue_row else None,
        "assistant_verdict_at": issue_row.assistant_verdict_at if issue_row else None,
        "confirmed_at_runtime_at": issue_row.confirmed_at_runtime_at if issue_row else None,
        "priority": _priority_view(issue_row),
        "retest_status": issue_row.retest_status if issue_row else None,
    }
    return d


def set_assistant_verdict(
    s: Session,
    issue_id: str,
    *,
    verdict: str,
    confidence: str,
    rationale: str,
    lines: list[int],
    model: str,
) -> IssueRow:
    """Store a triage-assistant verdict on an Issue (plan §21.3). Advisory only: nothing here
    touches `triage_status` -- a person, never a model, decides that (`triage_issue`, above)."""
    row = s.get(IssueRow, issue_id)
    if row is None:
        raise LookupError(f"issue {issue_id} not found")
    row.assistant_verdict = verdict
    row.assistant_verdict_confidence = confidence
    row.assistant_verdict_rationale = rationale
    row.assistant_verdict_lines = lines
    row.assistant_verdict_model = model
    row.assistant_verdict_at = _now()
    from core.priority.service import rescore

    rescore(s, row)  # the verdict is a priority factor
    s.commit()
    s.refresh(row)
    return row


def assistant_verdicts_for_asset(s: Session, asset_id: str) -> dict[str, TriageVerdict]:
    """fingerprint -> verdict for every Issue of this asset that already carries one (plan §21.3:
    "one input to the ranker"). Read by `core.pipeline` before a new scan's findings are scored, so
    a verdict generated from one occurrence keeps informing the risk score of every later scan that
    reproduces the same finding (same fingerprint) -- until a fresh verdict or a changed finding
    (new fingerprint) supersedes it. `core.correlation.engine.fingerprint()` is the one true
    source of a finding's fingerprint; `IssueRow.fingerprint` is that same value once an occurrence
    has been matched to an Issue (`core/issues.py`), so keying on it here needs no recomputation."""
    rows = s.scalars(
        select(IssueRow).where(
            IssueRow.asset_id == asset_id, IssueRow.assistant_verdict.is_not(None)
        )
    ).all()
    return {
        r.fingerprint: TriageVerdict(
            verdict=cast(Any, r.assistant_verdict),
            confidence=cast(Any, r.assistant_verdict_confidence),
            rationale=r.assistant_verdict_rationale or "",
            supporting_lines=tuple(r.assistant_verdict_lines or ()),
        )
        for r in rows
    }


def triage_issue(
    s: Session,
    issue_id: str,
    *,
    org_id: str,
    action: str,
    reason: str | None = None,
    expires_at: datetime | None = None,
    actor: str,
    justification: str | None = None,
) -> IssueRow:
    """Mark an issue `not_a_risk` (requires `reason`) or `accepted` (requires `expires_at`), or
    `reopen` it back to the active queue. Writes an audit entry either way (plan §28.3: "Both write
    to the audit log (§19.3)") -- `reopen` too, since undoing a triage decision is itself a
    security-relevant action worth a durable record.

    `justification` (Week 69, plan §46.3): for a dependency Issue marked not a risk, why, in
    OpenVEX's vocabulary (`core.vex.vocab`); exported in the project's VEX documents."""
    from core.vex.vocab import check_justification

    if action not in ("not_a_risk", "accepted", "reopen"):
        raise ValueError(f"unknown triage action: {action}")
    justification = check_justification(justification)
    if justification and action != "not_a_risk":
        raise ValueError("a VEX justification only goes with marking an issue not a risk")
    row = get_issue(s, issue_id, org_id=org_id)
    if row is None:
        raise LookupError("issue not found")
    if justification and row.category not in ("sca", "container"):
        raise ValueError("a VEX justification is only for dependency issues")
    row.triage_justification = justification
    now = _now()
    if action == "not_a_risk":
        if not reason or not reason.strip():
            raise ValueError("a reason is required to mark an issue as not a risk")
        row.triage_status, row.triage_reason, row.triage_expires_at = (
            "not_a_risk",
            reason.strip(),
            None,
        )
    elif action == "accepted":
        if expires_at is None:
            raise ValueError("an expiry date is required to accept a risk")
        row.triage_status, row.triage_reason, row.triage_expires_at = (
            "accepted",
            reason.strip() if reason else None,
            expires_at,
        )
    else:  # reopen
        row.triage_status, row.triage_reason, row.triage_expires_at = "open", None, None
    row.triaged_at, row.triaged_by = now, actor
    payload = {
        "action": action,
        "reason": reason,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }
    if justification:
        payload["justification"] = justification
    # append_audit_entry() commits -- the same flush also persists this row's pending changes above,
    # so the triage decision and its audit entry land together, in one transaction.
    append_audit_entry(
        s, actor=actor, action=f"issue.triage.{action}", target=issue_id, payload=payload
    )
    return row


def issue_history(s: Session, issue_id: str) -> list[dict[str, Any]]:
    """A real event timeline for one issue (plan §28.3), built from what's actually recorded: when
    it was first seen, every triage decision made about it since (the tamper-evident audit log,
    ADR-0019 -- `target` is the issue id), and when it was fixed, if it has been. Nothing here is
    synthesized; an issue with no triage history just has one or two entries."""
    issue = s.get(IssueRow, issue_id)
    events: list[dict[str, Any]] = []
    if issue is not None:
        events.append({"at": issue.first_seen_at, "label": "First seen"})
        if issue.fixed_at is not None:
            events.append({"at": issue.fixed_at, "label": "Fixed"})
    # Its own triage entries, and every risk acceptance that covers it (Week 62).
    acceptances = [
        f"risk_acceptance:{a}"
        for a in s.scalars(
            select(RiskAcceptanceIssue.acceptance_id).where(
                RiskAcceptanceIssue.issue_id == issue_id
            )
        )
    ]
    entries = list(
        s.scalars(
            select(AuditEntry)
            .where(AuditEntry.target.in_([issue_id, *acceptances]))
            .order_by(AuditEntry.seq)
        )
    )
    # A change a rule made (Week 65) says which rule.
    rule_ids = {e.actor.split(":", 1)[1] for e in entries if e.actor.startswith("rule:")}
    rule_names: dict[str, str] = {}
    if rule_ids:
        q = select(AutomationRule.id, AutomationRule.name).where(AutomationRule.id.in_(rule_ids))
        rule_names = {i: n for i, n in s.execute(q)}
    for e in entries:
        label = _audit_action_label(e.action)
        if e.actor.startswith("rule:"):
            label += f" by the rule “{rule_names.get(e.actor.split(':', 1)[1], 'deleted')}”"
        elif e.actor.startswith("ticket:"):
            label += f" by its ticket, {e.actor.split(':', 1)[1]}"
        events.append({"at": e.timestamp, "label": label})
    # A retest decided by a scan, an upload or a targeted retest (Week 64) is that run's outcome,
    # not a person's decision, so it is an outbox event rather than an audit entry.
    for ev in s.scalars(
        select(OutboxEvent).where(
            OutboxEvent.event_type.in_(("issue.retest_passed", "issue.retest_failed")),
            OutboxEvent.payload["issue_id"].as_string() == issue_id,
        )
    ):
        if ev.payload.get("detail"):
            word = "passed" if ev.event_type.endswith("passed") else "failed"
            events.append({"at": ev.created_at, "label": f"Retest {word}: {ev.payload['detail']}"})
    events.sort(key=lambda ev: ev["at"])
    return events


def _audit_action_label(action: str) -> str:
    return {
        "issue.triage.not_a_risk": "Marked as not a risk",
        "issue.triage.accepted": "Risk accepted",
        "issue.triage.reopen": "Reopened",
        "risk_acceptance.requested": "Risk acceptance requested",
        "risk_acceptance.approved": "Risk acceptance approved",
        "risk_acceptance.rejected": "Risk acceptance rejected",
        "risk_acceptance.withdrawn": "Risk acceptance withdrawn",
        "risk_acceptance.lapsed": "Risk acceptance request lapsed",
        "risk_acceptance.expired": "Risk acceptance expired",
        "risk_acceptance.reinstated": "Risk acceptance reinstated",
        "risk_acceptance.proof_added": "Proof added to the risk acceptance",
        "issue.retest.requested": "Marked ready for retest",
        "issue.retest.passed": "Retest passed: confirmed fixed",
        "issue.retest.failed": "Retest failed: reproduced",
        "issue.retest.cancelled": "Retest request cancelled",
        "issue.retest.targeted": "Targeted retest started",
        "issue.note.added": "Note added",
        "issue.note.edited": "Note edited",
        "issue.note.deleted": "Note deleted",
        "tags.changed": "Tags changed",
        "issue.assigned": "Assigned",
        "issue.bulk.undone": "Bulk change undone",
        "issue.unassigned": "Unassigned",
        "issue.priority.set": "Priority set",
        "issue.priority.cleared": "Priority back to the computed band",
        "issue.fix.requested": "Verified fix requested",
        "issue.ticket.filed": "Ticket filed",
        "issue.group.joined": "Added to a group",
        "issue.group.left": "Removed from its group",
    }.get(action, action)


def reset_scan_results(s: Session, scan_id: str) -> None:
    """Make a (re)started scan idempotent: a redelivered task must not duplicate rows."""
    s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
    s.execute(delete(ToolRun).where(ToolRun.scan_id == scan_id))
    s.commit()


def mark_running(s: Session, scan_id: str) -> None:
    scan = s.get(Scan, scan_id)
    assert scan is not None
    scan.status, scan.started_at, scan.error = "running", _now(), None
    s.commit()


def finish_scan(s: Session, scan_id: str, status: str, error: str | None = None) -> None:
    scan = s.get(Scan, scan_id)
    assert scan is not None
    scan.status, scan.finished_at, scan.error = status, _now(), error
    # What the scan changed, as an import's event already says (Week 66: rules read
    # `input.scan.counts`): its Issue events were written when its findings were synced.
    counts = {"new": 0, "reopened": 0, "closed": 0}
    for (kind,) in s.execute(
        select(OutboxEvent.event_type).where(
            OutboxEvent.org_id == scan.org_id,
            OutboxEvent.event_type.in_(("issue.created", "issue.reopened", "issue.closed")),
            OutboxEvent.payload["scan_id"].as_string() == scan_id,
        )
    ):
        counts[{"issue.created": "new", "issue.reopened": "reopened"}.get(kind, "closed")] += 1
    add_outbox_event(
        s,
        org_id=scan.org_id,
        event_type="scan.completed",
        payload={"scan_id": scan_id, "asset_id": scan.asset_id, "status": status,
                 "source": "scan", "counts": counts},
    )  # fmt: skip
    s.commit()


def set_sbom_summary(s: Session, scan_id: str, summary: dict[str, Any] | None) -> None:
    """`None` (no "syft" in this scan's tools, or a corrupt SBOM) leaves the column at its default
    `NULL` -- absent, not a fabricated empty summary (plan §20.5)."""
    if summary is None:
        return
    scan = s.get(Scan, scan_id)
    assert scan is not None
    scan.sbom_summary = summary
    s.commit()


def set_route_map(s: Session, scan_id: str, route_map: list[dict[str, Any]]) -> None:
    """Unlike `set_sbom_summary`, an empty list is still written: "this scan found no Python route
    decorators" is informative (and distinguishes an old scan, before this column existed, whose
    value is genuinely `NULL`) from "this scan never looked" (Week 49 task 4, plan §22.4)."""
    scan = s.get(Scan, scan_id)
    assert scan is not None
    scan.route_map = route_map
    s.commit()


def set_entrypoints(s: Session, scan_id: str, entrypoints: list[dict[str, Any]] | None) -> None:
    """Every HTTP entrypoint code intelligence found in this scan (Week 59, plan §43.2's route
    picker). `None` (the analysis did not run) is left as null, unlike an empty list."""
    if entrypoints is None:
        return
    scan = s.get(Scan, scan_id)
    assert scan is not None
    scan.entrypoints = entrypoints
    s.commit()


def latest_scan_with_route_map(
    s: Session, asset_id: str, *, org_id: str | None = None, candidates: int = 10
) -> Scan | None:
    """The most recent completed SAST/archive/git scan of this asset that has a non-empty route
    map -- what a DAST campaign (`core.dast.pipeline`) correlates its own findings against. `None`
    when the asset has never had a scan with Python route handlers in it (including every web-only
    asset, which never runs a SAST scan at all). Filters "non-empty" in Python rather than with a
    JSON-array-length SQL function, whose name differs between SQLite and Postgres -- `candidates`
    recent completed scans is enough to find one with real routes without needing either dialect's
    own JSON functions at all."""
    q = (
        select(Scan)
        .where(Scan.asset_id == asset_id, Scan.status == "completed", Scan.route_map.is_not(None))
        .order_by(Scan.created_at.desc())
        .limit(candidates)
    )
    if org_id is not None:
        q = q.where(Scan.org_id == org_id)
    for scan in s.scalars(q):
        if scan.route_map:
            return scan
    return None


def issue_findings_for_scan(s: Session, asset_id: str, scan_id: str) -> list[tuple[str, Finding]]:
    """Every open issue from one scan, reconstructed as a real `Finding` via `FindingRow.data`
    (`Finding.to_dict`'s inverse) -- the same round-trip
    `core.attackpath.service._all_issue_findings` already does for attack-path generation, here for
    Week 49 task 4's DAST correlation instead."""
    out: list[tuple[str, Finding]] = []
    offset = 0
    page_size = 200
    while True:
        page = list_asset_issues(s, asset_id, scan_id, sort="path", limit=page_size, offset=offset)
        for d in page.items:
            issue = d.get("issue")
            if issue and issue.get("id"):
                out.append((issue["id"], finding_from_dict(d)))
        if offset + page_size >= page.total:
            break
        offset += page_size
    return out


def mark_issue_confirmed_at_runtime(s: Session, issue_id: str, *, scan_id: str) -> None:
    issue = s.get(IssueRow, issue_id)
    if issue is None:
        return
    if issue.confirmed_at_runtime_at is None:
        issue.confirmed_at_runtime_at = _now()
    issue.confirmed_by_scan_id = scan_id
    from core.priority.service import rescore

    rescore(s, issue)  # runtime confirmation is a priority factor
    s.commit()


def add_tool_run(s: Session, scan_id: str, tool: str, block: dict[str, Any]) -> None:
    """Every ToolRun is a Test within its asset's standing "ci" Engagement (plan §40/§42, ADR-0039)
    -- resolved (and lazily created, for an asset old enough to predate this feature) from the
    scan's own `org_id`/`asset_id` rather than threaded through every one of this function's several
    call sites. A scan with no asset (none exist in practice -- `create_scan` always resolves one
    first -- but the column is nullable) simply gets a ToolRun with no engagement, same as any
    pre-migration-0026 row."""
    scan = s.get(Scan, scan_id)
    engagement_id = (
        get_or_create_ci_engagement(s, asset_id=scan.asset_id, org_id=scan.org_id).id
        if scan is not None and scan.asset_id is not None
        else None
    )
    s.add(
        ToolRun(
            scan_id=scan_id,
            tool=tool,
            status=block["status"],
            findings_count=block.get("findings", 0),
            exit_code=block.get("exit_code"),
            duration_seconds=block.get("duration_seconds"),
            error=block.get("error") or block.get("reason"),
            engagement_id=engagement_id,
        )
    )
    s.commit()


def set_raw_artifact(
    s: Session, scan_id: str, tool: str, key: str | None, withheld: str | None
) -> None:
    run = s.scalars(select(ToolRun).where(ToolRun.scan_id == scan_id, ToolRun.tool == tool)).one()
    run.raw_object_key, run.raw_withheld_reason = key, withheld
    s.commit()


def _existing_issues(s: Session, asset_id: str) -> tuple[list[IssueRow], list[ExistingIssue]]:
    rows = list(s.scalars(select(IssueRow).where(IssueRow.asset_id == asset_id)))
    existing = [
        ExistingIssue(r.id, r.category, r.fingerprint, r.fallback_fingerprint, cast(State, r.state))
        for r in rows
    ]
    return rows, existing


def classify_findings_for_pr(
    s: Session, scan_id: str, findings: list[Finding]
) -> list[IssueUpdate]:
    """Read-only PR-mode counterpart to `sync_issues_for_scan` (plan §36): "new in this PR" without
    writing anything back to `issues` -- see `core.issues.classify_for_pr`'s docstring for why a PR
    scan must never mutate the asset's real Issue history. `[]` when the scan has no asset."""
    scan = s.get(Scan, scan_id)
    assert scan is not None
    if scan.asset_id is None:
        return []
    _, existing = _existing_issues(s, scan.asset_id)
    return classify_for_pr(findings, existing)


def import_snapshot_scan_ids(
    s: Session, org_id: str, asset_id: str, *, exclude_test_ids: frozenset[str] = frozenset()
) -> list[str]:
    """The scan behind each Test's current snapshot (its latest applied import) across every
    engagement of this asset: the "other sources" a native scan, or an import into a different Test,
    must not close an Issue out from under (ADR-0040)."""
    test_ids = s.scalars(
        select(EngagementTest.id)
        .join(Engagement, Engagement.id == EngagementTest.engagement_id)
        .where(Engagement.asset_id == asset_id, EngagementTest.org_id == org_id)
    )
    out = []
    for test_id in test_ids:
        if test_id in exclude_test_ids:
            continue
        latest = latest_applied_import(s, test_id, org_id)
        if latest is not None and latest.scan_id is not None:
            out.append(latest.scan_id)
    return out


def open_snapshot_scan_ids(s: Session, org_id: str, asset_id: str) -> list[str]:
    """Every source of the project's open Issues as it stands: its latest scan first (when it has
    one), then each Test's latest applied import -- what the Issues table lists (Week 74: imported
    Issues were missing from it, though the import screen links there)."""
    latest = latest_scan_for_asset(s, asset_id, org_id=org_id)
    return ([latest.id] if latest is not None else []) + import_snapshot_scan_ids(
        s, org_id, asset_id
    )


def latest_native_snapshot_scan_id(s: Session, org_id: str, asset_id: str) -> str | None:
    """The asset's latest ordinary scan of its default branch that finished: the "CI" source. A
    pull-request scan (`ref` set) never syncs Issues, and an import is not native, so neither is
    the snapshot Issue state follows."""
    return s.scalars(
        select(Scan.id)
        .where(
            Scan.asset_id == asset_id,
            Scan.org_id == org_id,
            Scan.source_type != "import",
            Scan.ref.is_(None),
            Scan.status.in_(("completed", "partial")),
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    ).first()


def issue_ids_in_scans(s: Session, scan_ids: list[str]) -> set[str]:
    if not scan_ids:
        return set()
    return {
        i
        for i in s.scalars(
            select(FindingRow.issue_id).where(
                FindingRow.scan_id.in_(scan_ids), FindingRow.issue_id.is_not(None)
            )
        )
        if i is not None
    }


def issues_at_sampled_places(
    s: Session, issue_ids: Collection[str], samples: frozenset[tuple[str, str]]
) -> set[str]:
    """Of `issue_ids`, the web Issues whose last reported place is one of `samples` -- a (rule,
    host) this run's tool lists only some places for (`core.dast.mapping.crawl_samples`). Missing
    from the run, they are held open rather than closed."""
    if not samples or not issue_ids:
        return set()
    ids = sorted(issue_ids)
    held: set[str] = set()
    for start in range(0, len(ids), 500):
        latest = (
            select(func.max(FindingRow.pk))
            .where(FindingRow.issue_id.in_(ids[start : start + 500]), FindingRow.category == "dast")
            .group_by(FindingRow.issue_id)
        )
        for issue_id, data in s.execute(
            select(FindingRow.issue_id, FindingRow.data).where(FindingRow.pk.in_(latest))
        ):
            location = data.get("location") or {}
            rule_ids = (data.get("evidence") or {}).get("rule_ids") or {}
            if sampled_places(str(location.get("host") or ""), rule_ids) & samples:
                held.add(issue_id)
    return held


def _issue_prior(row: IssueRow) -> dict[str, Any]:
    return {
        "state": row.state,
        "fixed_at": row.fixed_at.isoformat() if row.fixed_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "severity": row.severity,
        "title": row.title,
        "path": row.path,
        "category": row.category,
        "fingerprint": row.fingerprint,
        "fallback_fingerprint": row.fallback_fingerprint,
        # An upload can decide a requested retest (Week 64); undoing it undoes that too.
        "retest_status": row.retest_status,
        "retest_note": row.retest_note,
        "retest_decided_at": row.retest_decided_at.isoformat() if row.retest_decided_at else None,
        "retest_decided_by": row.retest_decided_by,
    }


def apply_reimport_plan(
    s: Session,
    *,
    asset_id: str,
    findings: list[Finding],
    plan: ReimportPlan,
    existing_rows: list[IssueRow],
    record_changes: bool = False,
    retest_source: str | None = None,
) -> list[dict[str, Any]]:
    """Write a decided `ReimportPlan` to the `issues` table. The one writer for both a native scan
    and an import (ADR-0040): the *decision* is `plan_reimport`, shared; so is this. Stages only --
    the caller commits, so an import can write its findings, record and events in one transaction.

    With `record_changes`, returns what an import needs to be undone: for every Issue touched, its
    state before (None for one this call created) and the state it was left in."""
    now = _now()
    by_id = {r.id: r for r in existing_rows}
    final = plan.resulting_states()
    changes: dict[str, dict[str, Any]] = {}

    def remember(row: IssueRow) -> None:
        if record_changes and row.id not in changes:
            changes[row.id] = {"issue_id": row.id, "created": False, "prior": _issue_prior(row)}

    for f, u in zip(findings, plan.updates, strict=True):
        assert u.issue_id is not None  # sync() (unlike classify_for_pr) always allocates a real id
        row = by_id.get(u.issue_id)
        if row is None:  # brand new issue
            row = IssueRow(
                id=u.issue_id,
                asset_id=asset_id,
                fingerprint=u.fingerprint,
                fallback_fingerprint=None,
                state=final[u.issue_id],
                category=f.taxonomy.category.value,
                severity=f.scoring.normalized_severity.value,
                path=f.location.path,
                title=f.title,
                first_seen_at=now,
                last_seen_at=now,
            )
            s.add(row)
            by_id[u.issue_id] = row
            if record_changes:
                changes[row.id] = {"issue_id": row.id, "created": True, "prior": None}
        else:
            remember(row)
            row.fingerprint = u.fingerprint
            row.state = final[u.issue_id]
            row.category = f.taxonomy.category.value
            row.severity = f.scoring.normalized_severity.value
            row.path = f.location.path
            row.title = f.title
            row.last_seen_at = now
            row.fixed_at = None
        # A fallback key needs the *original* Finding, not the ExistingIssue snapshot; recompute it
        # here rather than threading it through IssueUpdate, since it's cheap and keeps the pure
        # module focused on identity decisions, not field bookkeeping.
        row.fallback_fingerprint = fallback_key(f)

    for issue_id in plan.closed_issue_ids:
        row = by_id[issue_id]
        remember(row)
        row.state, row.fixed_at = "fixed", now

    if retest_source is not None:  # the next scan is the retest (plan §43.3)
        from core.retest.service import on_ingest

        on_ingest(
            s, by_id, still=[*plan.unchanged_issue_ids, *plan.reopened_issue_ids],
            closed=list(plan.closed_issue_ids), source=retest_source,
        )  # fmt: skip

    out = list(changes.values())
    for change in out:
        change["after_state"] = by_id[change["issue_id"]].state
    return out


def stage_issue_events(
    s: Session,
    *,
    org_id: str,
    asset_id: str,
    scan_id: str,
    plan: ReimportPlan,
    source: str,
    import_id: str | None = None,
) -> None:
    """One outbox event per Issue that appeared, came back, or was closed -- written in the same
    transaction as the change (plan §41.1)."""
    base = {"asset_id": asset_id, "scan_id": scan_id, "source": source}
    if import_id is not None:
        base["import_id"] = import_id
    for event_type, ids in (
        ("issue.created", plan.new_issue_ids),
        ("issue.reopened", plan.reopened_issue_ids),
        ("issue.closed", plan.closed_issue_ids),
    ):
        for issue_id in ids:
            add_outbox_event(
                s, org_id=org_id, event_type=event_type, payload={**base, "issue_id": issue_id}
            )


def sync_issues_for_scan(s: Session, scan_id: str, findings: list[Finding]) -> SyncResult:
    """Match this scan's findings against the asset's existing issues (ADR-0012, `core/issues.py`)
    and persist the lifecycle transitions. Returns one `IssueUpdate` per input finding, in the same
    order, so the caller can attach `issue_id`/`state` to each finding's stored row without relying
    on finding ids (which `add_findings` may rename on collision).

    This is the same decision and the same writer an import uses (`core.imports`, ADR-0040): a
    native scan is a source that owns every live Issue (so it can close any of them by not seeing
    it), except one an imported report still lists -- a scan that no longer sees something a pen
    tester's file still reports has not fixed it.

    A scan with no asset (there is always one from `create_scan`, but a row could predate this
    column) is a no-op: every finding gets no issue.
    """
    scan = s.get(Scan, scan_id)
    assert scan is not None
    if scan.asset_id is None:
        return SyncResult()
    rekey_for_asset(s, scan.asset_id, findings)  # a source the project deduplicates by its own key
    existing_rows, existing = _existing_issues(s, scan.asset_id)
    live = {i.id for i in existing if i.state in LIVE_STATES}
    plan = plan_reimport(
        findings,
        existing,
        previous_issue_ids=live,
        other_live_issue_ids=issue_ids_in_scans(
            s, import_snapshot_scan_ids(s, scan.org_id, scan.asset_id)
        ),
        held_issue_ids=issues_at_sampled_places(s, live, crawl_samples(findings)),
        new_issue_id=_new_issue_id,
    )
    apply_reimport_plan(
        s, asset_id=scan.asset_id, findings=findings, plan=plan, existing_rows=existing_rows,
        retest_source=f"the scan of {_now():%d %b %Y}",
    )  # fmt: skip
    stage_issue_events(
        s, org_id=scan.org_id, asset_id=scan.asset_id, scan_id=scan_id, plan=plan, source="scan"
    )
    s.commit()
    return SyncResult(
        updates=list(plan.updates),
        fixed_issue_ids=list(plan.closed_issue_ids),
        new_count=len(plan.new_issue_ids),
        reintroduced_count=len(plan.reopened_issue_ids),
        fixed_count=len(plan.closed_issue_ids),
    )


def _new_issue_id() -> str:
    return str(uuid.uuid4())


def add_findings(
    s: Session,
    scan_id: str,
    findings: list[Finding],
    issue_updates: list[IssueUpdate] | None = None,
    *,
    commit: bool = True,
) -> None:
    seen: set[str] = set()
    ranked: list[tuple[str, dict[str, Any]]] = []  # (issue id, stored finding), for priority
    updates_by_position: list[IssueUpdate | None] = (
        list(issue_updates) if issue_updates else [None] * len(findings)
    )
    for f, upd in zip(findings, updates_by_position, strict=True):
        if f.id in seen:  # never drop a finding silently: disambiguate and say so
            n = 2
            while f"{f.id}#{n}" in seen:
                n += 1
            log.warning("finding id collision in scan %s: %s (kept as #%d)", scan_id, f.id, n)
            f.id = f"{f.id}#{n}"
        seen.add(f.id)
        d = f.to_dict()
        sev = f.scoring.normalized_severity.value
        s.add(
            FindingRow(
                scan_id=scan_id,
                finding_id=f.id,
                fingerprint=f.fingerprint,
                category=f.taxonomy.category.value,
                severity=sev,
                severity_rank=SEVERITY_RANK[sev],
                risk_score=f.scoring.risk_score,
                path=f.location.path,
                start_line=f.location.start_line,
                tools=list(f.evidence.reported_by),
                data=d,
                issue_id=upd.issue_id if upd else None,
                issue_state=upd.state if upd else None,
            )
        )
        if upd and upd.issue_id:
            ranked.append((upd.issue_id, d))
    if ranked:
        from core.priority.service import refresh_ingested

        scan = s.get(Scan, scan_id)
        if scan is not None and scan.asset_id is not None:
            refresh_ingested(s, scan.asset_id, ranked)
    if commit:
        s.commit()


def _with_issue(row: FindingRow) -> dict[str, Any]:
    """The stored canonical Finding, plus which Issue (ADR-0012) it belongs to and that issue's
    current lifecycle state — `new` on its first sighting, `open` after, `reintroduced` if it had
    been fixed and came back. `None` for scans with no asset, or scans that never resolved (partial
    or failed scans don't sync issues at all, since absence there wouldn't mean "fixed")."""
    issue = {"id": row.issue_id, "state": row.issue_state} if row.issue_id else None
    return {**row.data, "issue": issue}


@dataclass
class FindingPage:
    total: int
    items: list[dict[str, Any]]


def query_findings(
    s: Session,
    scan_id: str,
    *,
    severities: list[str] | None = None,
    categories: list[str] | None = None,
    tool: str | None = None,
    path_contains: str | None = None,
    sort: str = "severity",
    limit: int = 100,
    offset: int = 0,
) -> FindingPage:
    conds = [FindingRow.scan_id == scan_id]
    if severities:
        conds.append(FindingRow.severity.in_([x.upper() for x in severities]))
    if categories:
        conds.append(FindingRow.category.in_([x.lower() for x in categories]))
    if path_contains:
        escaped = path_contains.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        conds.append(FindingRow.path.like(f"%{escaped}%", escape="\\"))
    rows_q = select(FindingRow).where(*conds)
    if tool:
        # JSON-array membership is dialect-specific; filter by tool in Python over the scan's rows
        # only when requested (scans are bounded by ingestion limits).
        rows = [r for r in s.scalars(rows_q) if tool in r.tools]
        rows = _sort(rows, sort)
        return FindingPage(len(rows), [_with_issue(r) for r in rows[offset : offset + limit]])
    total = s.scalar(select(func.count()).select_from(FindingRow).where(*conds)) or 0
    order: list[Any]
    if sort == "path":
        order = [FindingRow.path, FindingRow.start_line]
    elif sort == "risk":
        order = [case((FindingRow.risk_score.is_(None), -1), else_=FindingRow.risk_score).desc()]
    else:
        order = [
            FindingRow.severity_rank.desc(),
            case((FindingRow.risk_score.is_(None), -1), else_=FindingRow.risk_score).desc(),
            FindingRow.path,
            FindingRow.start_line,
        ]
    rows_q = rows_q.order_by(*order, FindingRow.pk).limit(limit).offset(offset)
    return FindingPage(total, [_with_issue(r) for r in s.scalars(rows_q)])


def _sort(rows: list[FindingRow], sort: str) -> list[FindingRow]:
    if sort == "path":
        return sorted(rows, key=lambda r: (r.path, r.start_line, r.pk))
    if sort == "risk":
        return sorted(
            rows, key=lambda r: (-(r.risk_score if r.risk_score is not None else -1), r.pk)
        )
    return sorted(
        rows,
        key=lambda r: (
            -r.severity_rank,
            -(r.risk_score if r.risk_score is not None else -1),
            r.path,
            r.start_line,
            r.pk,
        ),
    )


def severity_counts(s: Session, scan_id: str) -> dict[str, int]:
    rows = s.execute(
        select(FindingRow.severity, func.count())
        .where(FindingRow.scan_id == scan_id)
        .group_by(FindingRow.severity)
    ).all()
    return {sev: n for sev, n in rows}


def issue_counts(s: Session, scan_id: str) -> dict[str, int]:
    """Findings by Issue lifecycle state (ADR-0012). Empty for scans with no synced issues — a
    scan that isn't "completed", or one that predates Week 28 and hasn't been backfilled."""
    rows = s.execute(
        select(FindingRow.issue_state, func.count())
        .where(FindingRow.scan_id == scan_id, FindingRow.issue_state.is_not(None))
        .group_by(FindingRow.issue_state)
    ).all()
    return {state: n for state, n in rows if state is not None}


def get_installation(s: Session, installation_id: str) -> GithubInstallation | None:
    """`github_installations` deliberately carries no Row-Level Security policy (unlike every
    table that holds actual scan data) -- this lookup is *how* a webhook's org context gets
    resolved in the first place, so it cannot itself require org context to already be set. It's
    a directory table,
    like `organizations` itself, not tenant-owned content: knowing "installation X belongs to org Y"
    isn't a cross-tenant data leak the way a scan's findings would be. See `set_session_org`'s and
    `get_or_create_installation`'s docstrings for how the *next* query in the same session gets
    properly org-scoped, right after this one resolves which org that is."""
    return s.get(GithubInstallation, installation_id)


def get_or_create_installation(
    s: Session, *, installation_id: str, account_login: str
) -> GithubInstallation:
    """A GitHub App installation IS a tenant boundary for now (ADR-0013/ADR-0017): installing the
    App on an account creates that account's Organization the first time we hear about it, since
    there is no separate org-management API yet. A `created` webhook redelivered (GitHub retries
    webhooks it isn't sure were received) must not create a second org, hence get-or-create.

    Callers that go on to write anything else in this same session (an `Asset`/`Scan` for a PR
    scan, which DO carry RLS) must call `core.tenancy.set_session_org(s, row.org_id)` first -- this
    function only resolves *which* org, it doesn't set the session's org context, since a plain
    lookup (the common case: an already-installed app) shouldn't have the side effect of changing
    it.
    """
    row = s.get(GithubInstallation, installation_id)
    if row is not None:
        return row
    org = Organization(name=f"GitHub: {account_login}")
    s.add(org)
    s.flush()  # `org.id`'s default (core.persistence.models._uuid) is only assigned on flush, not
    # at construction -- reading it beforehand (as the FK value below needs to) would insert NULL.
    row = GithubInstallation(id=installation_id, account_login=account_login, org_id=org.id)
    s.add(row)
    s.commit()
    return row


def delete_installation(s: Session, installation_id: str) -> None:
    """Uninstalling the App only removes the installation mapping -- never the Organization or its
    scan/issue history, which stays exactly as durable as any other org's (ADR-0013). Reinstalling
    later (a new installation id, GitHub never reuses one) starts a *new* org rather than resuming
    the old one; there's no way to prove it's the same account asking, so this doesn't try to guess.
    """
    row = s.get(GithubInstallation, installation_id)
    if row is not None:
        s.delete(row)
        s.commit()


def create_api_token(
    s: Session,
    *,
    org_id: str,
    name: str,
    scopes: list[str],
    expires_at: datetime | None = None,
    user_id: str | None = None,
) -> tuple[ApiToken, str]:
    """Returns `(row, raw_token)` -- the raw secret is generated here and returned exactly once;
    only its hash is ever persisted (`core/tokens.py`). Callers (the `bulwark token create` CLI)
    must show `raw_token` to the operator and never log or store it themselves."""
    from core.tokens import generate_token

    generated = generate_token()
    row = ApiToken(
        org_id=org_id, name=name, token_hash=generated.token_hash,
        display_prefix=generated.display_prefix, scopes=sorted(scopes), expires_at=expires_at,
        user_id=user_id,
    )  # fmt: skip
    s.add(row)
    s.commit()
    return row, generated.raw


def get_api_token_by_hash(s: Session, token_hash: str) -> ApiToken | None:
    """No org filter, deliberately -- see `ApiToken`'s docstring. Authenticating a request with a
    token is what *resolves* its org context; this lookup can't be gated by org context that
    doesn't exist yet at this point in the request."""
    return s.scalar(select(ApiToken).where(ApiToken.token_hash == token_hash))


def touch_api_token(s: Session, token_id: str) -> None:
    row = s.get(ApiToken, token_id)
    if row is not None:
        row.last_used_at = _now()
        s.commit()


def list_api_tokens(s: Session, org_id: str) -> list[ApiToken]:
    return list(
        s.scalars(
            select(ApiToken).where(ApiToken.org_id == org_id).order_by(ApiToken.created_at.desc())
        )
    )


def revoke_api_token(s: Session, token_id: str) -> bool:
    row = s.get(ApiToken, token_id)
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = _now()
    s.commit()
    return True


def append_audit_entry(
    s: Session,
    *,
    actor: str,
    action: str,
    target: str,
    payload: dict[str, Any],
    org_id: str | None = None,
) -> AuditEntry | None:
    """A bounded optimistic-concurrency retry, not a database lock -- see `AuditEntry`'s docstring
    for why that's an accepted, documented simplification at this project's current scale (one API
    process, one worker), not a claim that a concurrent-write race is impossible.

    Writes a version-2 entry (`core.audit`). Its organization is `org_id`, else the one the session
    acts for (`core.tenancy.set_session_org`), else the payload's `org_id`; none for a
    deployment-wide action (a CLI command, a GitHub installation).

    Inside `audit_in_one_commit`, the entry is only staged (and None returned): it is written, and
    committed, with everything else the block changed."""
    org = org_id or session_org(s) or payload.get("org_id")
    org = str(org) if org else None
    deferred = s.info.get(_DEFERRED_AUDIT)
    if deferred is not None:
        deferred.append({"actor": actor, "action": action, "target": target, "payload": payload,
                         "org_id": org})  # fmt: skip
        return None
    digest = audit.payload_digest(payload)
    for _ in range(5):
        last = s.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
        seq = (last.seq + 1) if last else 1
        prev_hash = last.entry_hash if last else audit.GENESIS_HASH
        now = _now()
        body = audit.body_digest(
            timestamp=now, org_id=org, actor=actor, action=action, target=target,
            payload_digest=digest,
        )  # fmt: skip
        entry_hash = audit.compute_hash_v2(seq=seq, prev_hash=prev_hash, body_digest=body)
        row = AuditEntry(
            seq=seq, prev_hash=prev_hash, entry_hash=entry_hash, timestamp=now, actor=actor,
            action=action, target=target, payload_digest=digest, version=2, org_id=org,
            body_digest=body,
        )  # fmt: skip
        s.add(row)
        try:
            s.commit()
            return row
        except IntegrityError:
            s.rollback()
    raise RuntimeError("could not append an audit entry after 5 attempts (high write contention)")


_DEFERRED_AUDIT = "bulwark.audit_in_one_commit"


@contextmanager
def audit_in_one_commit(s: Session, *, enabled: bool = True) -> Iterator[None]:
    """Everything the block changes, and every audit entry it appends, in one commit at its end --
    rather than a commit (and a read of the chain's tip) per entry, which is most of what a rule
    acting on many Issues costs (scripts/bench-rules.py). Code inside must commit only through
    `append_audit_entry`. If the block raises, nothing is written and the session is left for the
    caller to roll back. A concurrent append can take the next `seq` first; the entries are then
    chained again on the new tip, in a savepoint, up to five times."""
    if not enabled or _DEFERRED_AUDIT in s.info:
        yield
        return
    entries: list[dict[str, Any]] = []
    s.info[_DEFERRED_AUDIT] = entries
    try:
        yield
    finally:
        s.info.pop(_DEFERRED_AUDIT, None)
    for _ in range(5):
        try:
            with s.begin_nested():
                stage_audit_entries(s, entries)
                s.flush()
        except IntegrityError:
            continue
        s.commit()
        return
    raise RuntimeError("could not append audit entries after 5 attempts (high write contention)")


def audit_deferred(s: Session) -> int | None:
    """How many entries `audit_in_one_commit` holds so far, or None outside one."""
    entries = s.info.get(_DEFERRED_AUDIT)
    return None if entries is None else len(entries)


def drop_deferred_audit(s: Session, keep: int) -> None:
    """A savepoint inside `audit_in_one_commit` was rolled back: so are the entries it staged."""
    del s.info[_DEFERRED_AUDIT][keep:]


def stage_audit_entries(
    s: Session, entries: list[dict[str, Any]], *, org_id: str | None = None
) -> None:
    """Many entries, chained in order, staged in the session without committing: a bulk change
    (core.search.bulk) commits them with the rows they describe, in one transaction. Each dict has
    `actor`, `action`, `target`, `payload` and, optionally, its own `org_id`. A concurrent append
    makes the commit fail on `seq`; the caller rolls back and runs the whole change again."""
    if not entries:
        return
    last = s.scalar(select(AuditEntry).order_by(AuditEntry.seq.desc()).limit(1))
    seq = last.seq if last else 0
    prev_hash = last.entry_hash if last else audit.GENESIS_HASH
    now = _now()
    for e in entries:
        seq += 1
        digest = audit.payload_digest(e["payload"])
        org = e.get("org_id", org_id)
        body = audit.body_digest(
            timestamp=now, org_id=org, actor=e["actor"], action=e["action"], target=e["target"],
            payload_digest=digest,
        )  # fmt: skip
        entry_hash = audit.compute_hash_v2(seq=seq, prev_hash=prev_hash, body_digest=body)
        s.add(AuditEntry(
            seq=seq, prev_hash=prev_hash, entry_hash=entry_hash, timestamp=now, actor=e["actor"],
            action=e["action"], target=e["target"], payload_digest=digest, version=2,
            org_id=org, body_digest=body,
        ))  # fmt: skip
        prev_hash = entry_hash


def list_audit_entries(s: Session, *, since_seq: int = 0) -> list[AuditEntry]:
    return list(
        s.scalars(select(AuditEntry).where(AuditEntry.seq > since_seq).order_by(AuditEntry.seq))
    )


def latest_checkpoint(s: Session) -> AuditCheckpoint | None:
    return s.scalar(select(AuditCheckpoint).order_by(AuditCheckpoint.seq_end.desc()).limit(1))


def record_checkpoint(
    s: Session, *, seq_end: int, chain_hash: str, signature_bundle: str, rekor_log_index: int | None
) -> AuditCheckpoint:
    row = AuditCheckpoint(
        seq_end=seq_end, chain_hash=chain_hash, signature_bundle=signature_bundle,
        rekor_log_index=rekor_log_index,
    )  # fmt: skip
    s.add(row)
    s.commit()
    return row


def list_checkpoints(s: Session) -> list[AuditCheckpoint]:
    return list(s.scalars(select(AuditCheckpoint).order_by(AuditCheckpoint.seq_end)))


# ---- Hypotheses lane (Week 43, plan §21.4) -------------------------------------------------------


def create_hypothesis(
    s: Session,
    asset_id: str,
    *,
    method: str,
    path: str,
    file: str,
    line: int,
    evidence: str,
    suggested_check: str,
    confidence: str,
    snippet: str,
    model: str,
) -> HypothesisRow:
    row = HypothesisRow(
        asset_id=asset_id, route_method=method, route_path=path, file=file, line=line,
        evidence=evidence, suggested_check=suggested_check, confidence=confidence,
        snippet=snippet, model=model,
    )  # fmt: skip
    s.add(row)
    s.commit()
    s.refresh(row)
    return row


def list_hypotheses(
    s: Session, asset_id: str, *, org_id: str | None = None, status: str | None = None
) -> list[HypothesisRow]:
    q = select(HypothesisRow).where(HypothesisRow.asset_id == asset_id)
    if org_id is not None:
        q = q.join(Asset, Asset.id == HypothesisRow.asset_id).where(Asset.org_id == org_id)
    if status is not None:
        q = q.where(HypothesisRow.status == status)
    return list(s.scalars(q.order_by(HypothesisRow.created_at.desc())))


def get_hypothesis(
    s: Session, hypothesis_id: str, *, org_id: str | None = None
) -> HypothesisRow | None:
    q = select(HypothesisRow).where(HypothesisRow.id == hypothesis_id)
    if org_id is not None:
        q = q.join(Asset, Asset.id == HypothesisRow.asset_id).where(Asset.org_id == org_id)
    return s.scalars(q).one_or_none()


def dismiss_hypothesis(s: Session, hypothesis_id: str, *, actor: str) -> HypothesisRow:
    row = s.get(HypothesisRow, hypothesis_id)
    if row is None:
        raise LookupError(f"hypothesis {hypothesis_id} not found")
    if row.status != "open":
        raise ValueError(f"hypothesis is already {row.status}")
    row.status, row.updated_at = "dismissed", _now()
    append_audit_entry(
        s, actor=actor, action="hypothesis.dismiss", target=hypothesis_id, payload={}
    )  # fmt: skip
    return row


def promote_hypothesis(s: Session, hypothesis_id: str, *, actor: str) -> IssueRow:
    """Confirm a Hypotheses-lane candidate into a real Issue (plan §21.4), `source="llm-confirmed"`.

    Deliberately NOT `core.issues.sync`: that function reconciles a whole scan's worth of findings
    against history and would read every other currently-open Issue as "absent from this scan,
    therefore fixed" if handed just this one synthetic finding. A promoted hypothesis instead gets
    a direct, narrow insert: one new Issue, one new occurrence (a `FindingRow`) attached to the
    asset's latest scan, exactly as if that scan had reported it -- nothing else about that scan's
    history is touched.

    Scored with the same `core.risk.score_finding` every scanner-sourced finding gets, so a
    promoted hypothesis sorts sensibly in the issues table instead of carrying no risk score at
    all; there is no CVE or scanner-agreement signal to weigh here, so `Feeds()` (empty) and the
    confidence implied by the model's own stated confidence are all it has to go on -- a
    documented, honest floor, not a guessed-at precise number.
    """
    from core.models import Category, Finding, Location, Severity, Taxonomy
    from core.risk import Feeds, score_finding

    hyp = s.get(HypothesisRow, hypothesis_id)
    if hyp is None:
        raise LookupError(f"hypothesis {hypothesis_id} not found")
    if hyp.status != "open":
        raise ValueError(f"hypothesis is already {hyp.status}")
    latest = latest_scan_for_asset(s, hyp.asset_id)
    if latest is None:
        raise LookupError("this asset has no completed scan to attach the promoted issue to")

    finding_id = f"hypothesis:{hyp.id}"
    fingerprint = hashlib.sha256(
        f"hypothesis:{hyp.asset_id}:{hyp.file}:{hyp.line}:{hyp.route_method}:{hyp.route_path}".encode()
    ).hexdigest()[:32]
    confidence_value = {"high": 0.8, "medium": 0.6, "low": 0.4}[hyp.confidence]
    finding = Finding(
        id=finding_id,
        title=f"Missing authorization check: {hyp.route_method} {hyp.route_path}".strip(),
        description=f"{hyp.evidence}\n\nSuggested check: {hyp.suggested_check}",
        location=Location(hyp.file, hyp.line, hyp.line, hyp.snippet),
        taxonomy=Taxonomy(Category.SAST, cwe=("CWE-862",)),
    )
    finding.scoring.normalized_severity = Severity.MEDIUM
    finding.scoring.confidence = confidence_value
    finding.evidence.reported_by = ["hypotheses-lane"]
    finding.evidence.agreement_count = 1
    finding.fingerprint = fingerprint
    finding = score_finding(finding, Feeds())

    issue = IssueRow(
        asset_id=hyp.asset_id, fingerprint=fingerprint, state="new", category="sast",
        severity="MEDIUM", path=hyp.file, title=finding.title, source="llm-confirmed",
    )  # fmt: skip
    s.add(issue)
    s.flush()  # assigns issue.id, needed by the FindingRow below

    s.add(
        FindingRow(
            scan_id=latest.id,
            finding_id=finding_id,
            fingerprint=fingerprint,
            category="sast",
            severity="MEDIUM",
            severity_rank=SEVERITY_RANK["MEDIUM"],
            path=hyp.file,
            start_line=hyp.line,
            tools=["hypotheses-lane"],
            data=finding.to_dict(),
            issue_id=issue.id,
            issue_state="new",
            risk_score=finding.scoring.risk_score,
        )  # fmt: skip
    )
    from core.priority.service import refresh_ingested

    refresh_ingested(s, hyp.asset_id, [(issue.id, finding.to_dict())])
    hyp.status, hyp.promoted_issue_id, hyp.updated_at = "promoted", issue.id, _now()
    append_audit_entry(
        s, actor=actor, action="hypothesis.promote", target=hypothesis_id,
        payload={"issue_id": issue.id},
    )  # fmt: skip
    s.refresh(issue)
    return issue


# ---- Code chunk embeddings (Week 44, plan §21.5) --------------------------------------------


def refresh_code_chunks(s: Session, asset_id: str, chunks: list[CodeChunk]) -> dict[str, Any]:
    """Replace an asset's entire chunk index in one transaction: fit a fresh `HashingEmbedder` on
    this asset's own chunk texts (see `CodeChunkIndexRow`'s docstring for why per-asset, not one
    global fit), embed every chunk, delete the old rows, insert the new ones. Mirrors
    `core.rag.store.load_corpus`, scoped to one asset instead of the whole knowledge base."""
    texts = [c.text for c in chunks]
    embedder = HashingEmbedder.fit(texts)
    vectors = embedder.embed_documents(texts)
    s.execute(delete(CodeChunkRow).where(CodeChunkRow.asset_id == asset_id))
    for chunk, vector in zip(chunks, vectors, strict=True):
        s.add(
            CodeChunkRow(
                id=chunk.id, asset_id=asset_id, path=chunk.path, symbol_name=chunk.symbol_name,
                qualified_name=chunk.qualified_name, kind=chunk.kind, language=chunk.language,
                start_line=chunk.start_line, end_line=chunk.end_line, snippet=chunk.text,
                embedding=vector,
            )
        )  # fmt: skip
    index = s.get(CodeChunkIndexRow, asset_id)
    if index is None:
        s.add(
            CodeChunkIndexRow(
                asset_id=asset_id, embedder=embedder.name, dim=embedder.dim,
                idf=embedder.idf, chunk_count=len(chunks),
            )
        )  # fmt: skip
    else:
        index.embedder, index.dim, index.idf = embedder.name, embedder.dim, embedder.idf
        index.chunk_count, index.updated_at = len(chunks), _now()
    s.commit()
    return {"chunks": len(chunks), "embedder": embedder.name}


def search_code_chunks(
    s: Session, asset_id: str, query: str, k: int = 5, *, org_id: str | None = None
) -> list[tuple[CodeChunkRow, float]]:
    """Top-k chunks of one asset's code by cosine similarity -- always tenant-filtered (plan §21.5),
    RLS on Postgres plus the same app-level `org_id` check `list_hypotheses`/`get_hypothesis`
    already layer on top of it for SQLite. Empty asset (never indexed) returns `[]`, not an error:
    a copilot question about an asset with no chunk index yet should get "no relevant code found,"
    not a 500."""
    if org_id is not None:
        asset = s.get(Asset, asset_id)
        if asset is None or asset.org_id != org_id:
            return []
    index = s.get(CodeChunkIndexRow, asset_id)
    if index is None:
        return []
    embedder = HashingEmbedder(idf=list(index.idf), dim=index.dim)
    q = embedder.embed_query(query)
    if s.get_bind().dialect.name == "postgresql":
        qv = "[" + ",".join(f"{x:.6f}" for x in q) + "]"
        rows = s.execute(
            text(
                "SELECT id, 1 - (embedding <=> CAST(:q AS vector)) AS score FROM code_chunks "
                "WHERE asset_id = :asset_id ORDER BY embedding <=> CAST(:q AS vector) LIMIT :k"
            ),
            {"q": qv, "asset_id": asset_id, "k": k},
        ).all()
        scores = {r.id: float(r.score) for r in rows}
        found = {
            row.id: row
            for row in s.scalars(select(CodeChunkRow).where(CodeChunkRow.id.in_(list(scores))))
        }
        return [(found[i], scores[i]) for i in scores if i in found]
    # Queries are sparse (tens of non-zero buckets out of 1024): score only those, same trick
    # `core.rag.store.KnowledgeBase.search` uses for its own non-Postgres fallback.
    nz = [(i, x) for i, x in enumerate(q) if x]
    scored = [
        (sum(x * row.embedding[i] for i, x in nz), row)
        for row in s.scalars(select(CodeChunkRow).where(CodeChunkRow.asset_id == asset_id))
    ]
    scored.sort(key=lambda t: (-t[0], t[1].id))
    return [(row, score) for score, row in scored[:k]]


# ---- Copilot conversations (Week 44 task 3, plan §21.5) ---------------------------------------


def create_conversation(
    s: Session, asset_id: str, *, context_kind: str | None = None, context_id: str | None = None
) -> CopilotConversationRow:
    row = CopilotConversationRow(
        asset_id=asset_id, context_kind=context_kind, context_id=context_id
    )
    s.add(row)
    s.commit()
    s.refresh(row)
    return row


def get_conversation(
    s: Session, conversation_id: str, *, org_id: str | None = None
) -> CopilotConversationRow | None:
    q = select(CopilotConversationRow).where(CopilotConversationRow.id == conversation_id)
    if org_id is not None:
        q = q.join(Asset, Asset.id == CopilotConversationRow.asset_id).where(Asset.org_id == org_id)
    return s.scalars(q).one_or_none()


def add_message(
    s: Session,
    conversation_id: str,
    *,
    role: str,
    content: str,
    citations: list[dict[str, Any]] | None = None,
    tokens_used: int | None = None,
) -> CopilotMessageRow:
    row = CopilotMessageRow(
        conversation_id=conversation_id, role=role, content=content, citations=citations,
        tokens_used=tokens_used,
    )  # fmt: skip
    s.add(row)
    conversation = s.get(CopilotConversationRow, conversation_id)
    if conversation is not None:
        conversation.last_message_at = _now()
    s.commit()
    s.refresh(row)
    return row


def list_messages(
    s: Session, conversation_id: str, *, org_id: str | None = None
) -> list[CopilotMessageRow]:
    q = select(CopilotMessageRow).where(CopilotMessageRow.conversation_id == conversation_id)
    if org_id is not None:
        q = (
            q.join(
                CopilotConversationRow,
                CopilotConversationRow.id == CopilotMessageRow.conversation_id,
            )
            .join(Asset, Asset.id == CopilotConversationRow.asset_id)
            .where(Asset.org_id == org_id)
        )
    return list(s.scalars(q.order_by(CopilotMessageRow.created_at)))


def get_threat_model(s: Session, asset_id: str) -> ThreatModelRow | None:
    return s.get(ThreatModelRow, asset_id)


def save_threat_model(
    s: Session,
    asset_id: str,
    mermaid: str,
    stride: list[dict[str, Any]],
    *,
    source: str,
    actor: str | None,
) -> ThreatModelRow:
    """`source` is "generated" or "edited" -- the caller's job to say which, never inferred here.
    Replaces the asset's one current row in place and bumps `version`; never keeps prior content."""
    row = s.get(ThreatModelRow, asset_id)
    if row is None:
        row = ThreatModelRow(asset_id=asset_id, version=0)
        s.add(row)
    row.mermaid = mermaid
    row.stride = stride
    row.version += 1
    row.source = source
    row.updated_at = _now()
    row.updated_by = actor
    s.commit()
    s.refresh(row)
    return row


def get_scan_data_key(s: Session, scan_id: str) -> ScanDataKeyRow | None:
    """None means either no data key was ever minted for this scan, or it was crypto-shredded
    (Week 47 task 2) -- callers cannot tell which from this alone, by design: both mean 'this
    scan's encrypted artifacts can no longer be decrypted'."""
    return s.get(ScanDataKeyRow, scan_id)


def save_scan_data_key(s: Session, scan_id: str, org_id: str, wrapped_dek: bytes) -> ScanDataKeyRow:
    """Called once per scan, the first time something needs to encrypt data for it -- a scan's data
    key never changes after that (encrypting more objects for the same scan reuses it), so this
    does not overwrite an existing row; call get_scan_data_key first if a caller needs to know
    whether one already exists."""
    row = ScanDataKeyRow(scan_id=scan_id, org_id=org_id, wrapped_dek=wrapped_dek)
    s.add(row)
    s.commit()
    s.refresh(row)
    return row


def delete_scan_data_key(s: Session, scan_id: str) -> bool:
    """Crypto-shredding (Week 47 task 2, plan §22.2): destroys the scan's data key, making every
    object encrypted under it permanently unreadable, backups included -- the ciphertext itself is
    never touched by this call. Returns whether a row actually existed to delete."""
    row = s.get(ScanDataKeyRow, scan_id)
    if row is None:
        return False
    s.delete(row)
    s.commit()
    return True


def get_retention_days(s: Session, org_id: str) -> int:
    """DEFAULT_RETENTION_DAYS (7, plan §22.2) for an org that has never set its own -- there is no
    row to look up in the common case, by design (DataRetentionPolicyRow's own docstring)."""
    row = s.get(DataRetentionPolicyRow, org_id)
    return row.retention_days if row is not None else DEFAULT_RETENTION_DAYS


def set_retention_days(s: Session, org_id: str, retention_days: int) -> DataRetentionPolicyRow:
    if retention_days < 1:
        raise ValueError("retention_days must be at least 1")
    row = s.get(DataRetentionPolicyRow, org_id)
    if row is None:
        row = DataRetentionPolicyRow(org_id=org_id, retention_days=retention_days)
        s.add(row)
    else:
        row.retention_days = retention_days
    row.updated_at = _now()
    s.commit()
    s.refresh(row)
    return row


# ---- Plugin allowlist (Week 51 task 1, plan §23) -------------------------------------------------


def is_plugin_allowed(s: Session, org_id: str, plugin_name: str) -> bool:
    """Default-deny (PluginAllowlistRow's own docstring): no row, or a row with enabled=False, both
    mean "not allowed" -- the opposite default sense of get_retention_days above."""
    row = s.get(PluginAllowlistRow, (org_id, plugin_name))
    return row is not None and row.enabled


def set_plugin_allowed(
    s: Session, org_id: str, plugin_name: str, *, enabled: bool, allowed_by: str
) -> PluginAllowlistRow:
    row = s.get(PluginAllowlistRow, (org_id, plugin_name))
    if row is None:
        row = PluginAllowlistRow(org_id=org_id, plugin_name=plugin_name, allowed_by=allowed_by)
        s.add(row)
    row.enabled, row.allowed_by, row.allowed_at = enabled, allowed_by, _now()
    append_audit_entry(
        s, actor=allowed_by, action="plugin.allow" if enabled else "plugin.revoke",
        target=plugin_name, payload={"org_id": org_id},
    )  # fmt: skip
    s.commit()
    s.refresh(row)
    return row


def list_plugin_allowlist(s: Session, org_id: str) -> list[PluginAllowlistRow]:
    return list(
        s.scalars(
            select(PluginAllowlistRow)
            .where(PluginAllowlistRow.org_id == org_id)
            .order_by(PluginAllowlistRow.plugin_name)
        )
    )


# ---- Integrations (Week 51 task 2, plan §23) ------------------------------------------------


_INTEGRATION_FIELDS = (
    "slack_webhook_url", "discord_webhook_url", "outbound_webhook_url", "outbound_webhook_secret",
    "github_token", "github_issues_repo", "github_webhook_secret", "jira_base_url", "jira_email",
    "jira_api_token", "jira_project_key", "jira_webhook_secret", "teams_webhook_url",
)  # fmt: skip


def get_integration_settings(s: Session, org_id: str) -> IntegrationSettingsRow | None:
    """`None` means every integration is off (IntegrationSettingsRow's own docstring) -- there is
    no "default" settings row the way retention has one."""
    return s.get(IntegrationSettingsRow, org_id)


def set_integration_settings(
    s: Session, org_id: str, *, actor: str, **fields: str | None
) -> IntegrationSettingsRow:
    """Replaces every field named in `_INTEGRATION_FIELDS` with what's given (`None` clears it) --
    a full-replace PUT, the same semantics `set_retention_days` uses for its one field, just over
    more of them. Never logs a field's *value* to the audit log (several are bearer credentials);
    only which fields were touched, and by whom (`actor`, the caller's own token identity -- same
    attribution `set_plugin_allowed`'s `allowed_by` records)."""
    unknown = set(fields) - set(_INTEGRATION_FIELDS)
    if unknown:
        raise ValueError(f"unknown integration setting(s): {sorted(unknown)}")
    row = s.get(IntegrationSettingsRow, org_id)
    if row is None:
        row = IntegrationSettingsRow(org_id=org_id)
        s.add(row)
    for name in _INTEGRATION_FIELDS:
        if name in fields:
            setattr(row, name, fields[name])
    row.updated_at = _now()
    append_audit_entry(
        s, actor=actor, action="integrations.settings_updated", target=org_id,
        payload={"fields_set": sorted(fields)},
    )  # fmt: skip
    s.commit()
    s.refresh(row)
    return row


def create_external_link(
    s: Session, *, issue_id: str, org_id: str, provider: str, external_id: str, external_url: str
) -> ExternalIssueLinkRow:
    row = ExternalIssueLinkRow(
        issue_id=issue_id, org_id=org_id, provider=provider, external_id=external_id,
        external_url=external_url,
    )  # fmt: skip
    s.add(row)
    s.commit()
    s.refresh(row)
    return row


def get_external_link(s: Session, issue_id: str, provider: str) -> ExternalIssueLinkRow | None:
    return s.scalar(
        select(ExternalIssueLinkRow).where(
            ExternalIssueLinkRow.issue_id == issue_id, ExternalIssueLinkRow.provider == provider
        )
    )


def get_external_link_by_external_id(
    s: Session, org_id: str, provider: str, external_id: str
) -> ExternalIssueLinkRow | None:
    """How an inbound webhook (a GitHub `issues` event, a Jira `issue_updated` event) finds which
    Bulwark Issue an externally changed ticket belongs to."""
    return s.scalar(
        select(ExternalIssueLinkRow).where(
            ExternalIssueLinkRow.org_id == org_id,
            ExternalIssueLinkRow.provider == provider,
            ExternalIssueLinkRow.external_id == external_id,
        )
    )


def set_external_link_status(s: Session, link_id: str, status: str) -> None:
    """Sync metadata only -- see ExternalIssueLinkRow's own docstring for why this never touches
    IssueRow.state."""
    row = s.get(ExternalIssueLinkRow, link_id)
    if row is not None:
        row.external_status, row.updated_at = status, _now()
        s.commit()
