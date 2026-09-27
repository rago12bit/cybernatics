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
    tools: Mapped[list[str]] = mapped_column(JsonType)
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
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
