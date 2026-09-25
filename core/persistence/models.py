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

JsonType = JSON().with_variant(JSONB(), "postgresql")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(16), index=True, default="queued")
    source_type: Mapped[str] = mapped_column(String(16))  # git | archive
    source_ref: Mapped[str] = mapped_column(Text)  # git URL, or server-side archive path
    source_label: Mapped[str] = mapped_column(String(300))  # safe display name
    tools: Mapped[list[str]] = mapped_column(JsonType)
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
