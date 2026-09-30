"""Relational schema (SQLAlchemy 2.0): findings keep full canonical JSON + indexed columns."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from core.tenancy import DEFAULT_ORG_ID

JsonType = JSON().with_variant(JSONB(), "postgresql")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Organization(Base):
    """A tenant (ADR-0013). Deliberately minimal: no membership, roles or sign-up flow yet — that's
    the plan's §19.1/§19.2, separate identity work. This table exists so `org_id` foreign keys have
    somewhere to point, and so the bootstrap `DEFAULT_ORG_ID` row (every pre-Week-29 record, and
    every caller that doesn't specify an org) is a real row, not a magic string with nothing behind
    it."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class GithubInstallation(Base):
    """One GitHub App installation (Week 30, ADR-0017) -- an org or user account that installed
    Bulwark's GitHub App, on some or all of their repositories. Maps 1:1 onto a Bulwark
    `Organization` (ADR-0013): installing the App is, in effect, how a tenant is created for now,
    since there is no separate org-management API yet (ADR-0013's own deferred item)."""

    __tablename__ = "github_installations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # GitHub's installation id
    account_login: Mapped[str] = mapped_column(String(200))  # the org/user that installed it
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ApiToken(Base):
    """A scoped, revocable API token (Week 29 backfill, ADR-0018, plan §19.2) -- an alternative to
    the single shared `BULWARK_API_TOKEN` that authenticates as one specific organization with one
    specific set of scopes, rather than as "the whole deployment." Like `GithubInstallation`, this
    table carries no Row-Level Security policy: authenticating a request is what *resolves* org
    context in the first place (`api/deps.py`'s `require_auth`), so the lookup that does it can't
    itself require org context to already be set (`core/persistence/repo.py`'s
    `get_api_token_by_hash` has the full reasoning). Only `token_hash` is ever stored -- the raw
    token is shown to its creator exactly once (`core/tokens.py`)."""

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))  # human label ("CI pipeline", "laptop")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_prefix: Mapped[str] = mapped_column(String(20))  # safe to show afterwards
    scopes: Mapped[list[str]] = mapped_column(JsonType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditEntry(Base):
    """One link in the tamper-evident hash chain (Week 30 backfill, ADR-0019, plan §19.3). A
    single, global, operator-facing ledger -- not per-organization -- since there's no per-org
    sign-in yet for a per-org audit screen to gate access to; `core/audit.py` has the hash logic.

    `seq` is application-assigned (not a DB autoincrement): the chain needs to know the exact
    sequence number *before* the row exists, to hash it. `core/persistence/repo.py`'s
    `append_audit_entry` handles the read-latest-then-insert race with a bounded retry loop rather
    than a DB lock -- a documented, accepted simplification at this project's current scale (one API
    process, one worker), not a claim that races are impossible."""

    __tablename__ = "audit_entries"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    prev_hash: Mapped[str] = mapped_column(String(64))
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(
        String(200)
    )  # e.g. "cli:token-create", "webhook:installation"
    action: Mapped[str] = mapped_column(String(100), index=True)  # e.g. "token.created"
    target: Mapped[str] = mapped_column(String(200))  # the affected object's id
    payload_digest: Mapped[str] = mapped_column(
        String(64)
    )  # sha256 of the payload; never the payload


class AuditCheckpoint(Base):
    """A point in the chain whose hash has been signed and published to Sigstore's Rekor
    transparency log (`core/audit_rekor.py`) -- what makes truncating or rewriting entries *before*
    this point detectable against a log neither Bulwark nor an attacker controls."""

    __tablename__ = "audit_checkpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    seq_end: Mapped[int] = mapped_column(Integer, index=True)  # last seq this checkpoint covers
    chain_hash: Mapped[str] = mapped_column(String(64))  # entry_hash of the entry at seq_end
    signature_bundle: Mapped[str] = mapped_column(Text)  # the cosign Sigstore bundle, JSON
    rekor_log_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Asset(Base):
    """The identity a repeated scan is matched against (ADR-0012): one row per distinct repository
    or archive name, regardless of how many times it's been scanned. See `core/assets.py` for how
    the key is derived; this table only stores it.

    Scoped by `org_id` (ADR-0013): two organizations scanning the same public repository must never
    share an Asset, or one org's Issue history (and counts) would leak into the other's."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    source_type: Mapped[str] = mapped_column(String(16))  # git | archive
    key: Mapped[str] = mapped_column(String(500))  # normalized identity, core.assets.asset_key
    label: Mapped[str] = mapped_column(String(300))  # most recent human-readable label
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    issues: Mapped[list[IssueRow]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "source_type", "key", name="uq_assets_org_type_key"),
    )


class IssueRow(Base):
    """One vulnerability tracked across every scan of one asset (ADR-0012). `core/issues.py` is the
    pure logic that decides identity and lifecycle; this table just stores the result."""

    __tablename__ = "issues"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(80))
    fallback_fingerprint: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(16), index=True)  # new | open | fixed | reintroduced
    # A snapshot from the most recent occurrence, so issues can be listed without joining back to
    # findings. The full canonical Finding lives on the Occurrence row (FindingRow).
    category: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Triage (Week 34, plan §28.3): a human decision layered on top of `state`, not a replacement
    # for it -- an issue a scan still finds can independently be "open" (untouched), "not_a_risk"
    # (a person said so, with a reason), or "accepted" (a person said so, with an expiry; it
    # reappears in the active queue automatically once `triage_expires_at` passes).
    triage_status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    triage_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    triage_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triaged_by: Mapped[str | None] = mapped_column(String(200), nullable=True)

    asset: Mapped[Asset] = relationship(back_populates="issues")

    __table_args__ = (
        UniqueConstraint(
            "asset_id", "category", "fingerprint", name="uq_issues_asset_category_fingerprint"
        ),
        Index("ix_issues_asset_state", "asset_id", "state"),
    )


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    status: Mapped[str] = mapped_column(String(16), index=True, default="queued")
    source_type: Mapped[str] = mapped_column(String(16))  # git | archive
    source_ref: Mapped[str] = mapped_column(Text)  # git URL, or server-side archive path
    source_label: Mapped[str] = mapped_column(String(300))  # safe display name
    # A specific git ref to check out instead of the default branch (Week 30, ADR-0017) -- today
    # only ever `refs/pull/<n>/head`, set by a GitHub App pull_request webhook. Null for every
    # ordinary API-created scan, which still scans the default branch exactly as before.
    ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Set together with `ref`, only for a GitHub App pull_request scan: where to post the result
    # back to when the scan finishes. All three are null for every non-GitHub-triggered scan.
    github_repo: Mapped[str | None] = mapped_column(String(200), nullable=True)  # "owner/repo"
    github_pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    github_installation_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    tools: Mapped[list[str]] = mapped_column(JsonType)
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Supply-chain risk (plan §20.5), set only when "syft" was one of `tools` and it produced a
    # readable SBOM: every package (name/version/ecosystem/purl/license/direct-or-transitive/its
    # own dependency edges), plus an OpenSSF Scorecard result for each direct one, when resolved.
    # One JSON blob, not a normalized table, matching `FindingRow.data`/`RemediationCache.payload`
    # -- nothing here needs server-side filtering or pagination; the Dependencies screen renders it
    # whole.
    sbom_summary: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    # Model gateway token budget (plan §21.1, ADR-0026): total tokens every AI remediation call tied
    # to this scan has actually used. A running counter updated in place, unlike sbom_summary's
    # write-once snapshot -- `core.llm.budget.check()` compares it against a per-scan cap before
    # each call, so one scan generating suggestions for every one of its findings can't alone
    # exhaust an organization's whole monthly budget.
    llm_tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tool_runs: Mapped[list[ToolRun]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ToolRun.id"
    )


class ToolRun(Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tool: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # ok | timeout | error | skipped
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_object_key: Mapped[str | None] = mapped_column(String(300), nullable=True)
    raw_withheld_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="tool_runs")

    __table_args__ = (UniqueConstraint("scan_id", "tool", name="uq_tool_runs_scan_tool"),)


class FindingRow(Base):
    __tablename__ = "findings"

    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    finding_id: Mapped[str] = mapped_column(String(500))
    fingerprint: Mapped[str] = mapped_column(String(80), default="")
    category: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16))
    severity_rank: Mapped[int] = mapped_column(Integer)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    path: Mapped[str] = mapped_column(Text)
    start_line: Mapped[int] = mapped_column(Integer)
    tools: Mapped[list[str]] = mapped_column(JsonType)  # evidence.reported_by, for filtering
    data: Mapped[dict[str, Any]] = mapped_column(JsonType)  # full canonical Finding
    # This row is one Occurrence of an Issue (ADR-0012). Nullable because a scan with no asset (the
    # API always creates one, but the column must survive an old row from before this existed) has
    # nothing to attach an Issue to.
    issue_id: Mapped[str | None] = mapped_column(
        ForeignKey("issues.id", ondelete="SET NULL"), nullable=True, index=True
    )
    issue_state: Mapped[str | None] = mapped_column(String(16), nullable=True)

    __table_args__ = (
        UniqueConstraint("scan_id", "finding_id", name="uq_findings_scan_finding"),
        Index("ix_findings_scan_sev", "scan_id", "severity_rank"),
        Index("ix_findings_scan_category", "scan_id", "category"),
    )


class RemediationCache(Base):
    """AI remediation text shared across scans: the same SQLi in fifty repos costs one model call.

    Keyed by (rule, snippet hash or package, model, prompt version); see core/llm/cache.py.
    Only successful model replies are stored, never static fallbacks or failures.
    """

    __tablename__ = "remediation_cache"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(300), index=True)
    model: Mapped[str] = mapped_column(String(100))
    prompt_version: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)  # where the patch (if any) applies
    start_line: Mapped[int] = mapped_column(Integer)
    payload: Mapped[dict[str, Any]] = mapped_column(JsonType)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    hits: Mapped[int] = mapped_column(Integer, default=0)


class LlmUsage(Base):
    """One row per (org, calendar month): a running total of model-gateway tokens spent, the other
    half of the token budget alongside `Scan.llm_tokens_used` (core/llm/budget.py, ADR-0026).

    A dedicated table, not a JSON blob on `Organization` -- unlike `Scan.sbom_summary` (write once,
    by the one scan that owns it), this counter is incremented by many concurrent scans within the
    same org and month, which needs a race-free `UPDATE ... SET tokens = tokens + :n`, not a
    read-modify-write of a JSON document.
    """

    __tablename__ = "llm_usage"

    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), primary_key=True)
    period: Mapped[str] = mapped_column(String(7), primary_key=True)  # "YYYY-MM", UTC
    tokens: Mapped[int] = mapped_column(Integer, default=0)


class VerifiedFixRun(Base):
    """One verified-fix Temporal workflow's own record for one Issue (plan §21.2, ADR-0027).

    A new table, not an overload of `IssueRow.triage_status`: triage is a human decision layered on
    top of scan-derived state (its own docstring says so explicitly); "an automated agent is
    mid-attempt, or is waiting on a human to approve its patch" is a different concept the schema
    should not conflate with it, the same reasoning that gave `RemediationCache` (Week 12) and
    `LlmUsage` (Week 41) their own tables instead of new columns bolted onto whatever they're about.

    `latest_patch`/`verification_record` are JSON blobs, not normalized columns, matching
    `FindingRow.data`/`RemediationCache.payload`'s "keep the full document, index only what needs
    filtering" pattern -- the fix-review screen renders one run's whole record at once.
    """

    __tablename__ = "verified_fix_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    issue_id: Mapped[str] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    workflow_id: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    # running | awaiting_approval | approved | rejected | opened_pr | failed | inconclusive
    status: Mapped[str] = mapped_column(String(20), default="running", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    latest_patch: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    verification_record: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    # Which of ADR-0015's three limits ended this run, when one did -- "overall_timeout" |
    # "per_attempt_timeout" | "max_attempts_exhausted" | None (ended normally: approved/rejected).
    ended_reason: Mapped[str | None] = mapped_column(String(30), nullable=True)
    pr_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
