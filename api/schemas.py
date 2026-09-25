from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class GitSource(BaseModel):
    type: Literal["git"]
    url: str = Field(max_length=300, examples=["https://github.com/OWASP/NodeGoat"])


class ScanRequest(BaseModel):
    source: GitSource
    tools: list[str] | None = Field(default=None, description="Defaults to all tools.")


class ScanCreated(BaseModel):
    id: str
    status: str


class ToolStatus(BaseModel):
    status: str
    findings: int = 0
    exit_code: int | None = None
    duration_seconds: float | None = None
    error: str | None = None
    raw_artifact: str | None = Field(default=None, description="withheld/available")


class ScanView(BaseModel):
    id: str
    status: str
    source_type: str
    source_label: str
    tools: list[str]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    tool_status: dict[str, ToolStatus]
    severity_counts: dict[str, int]
    raw_findings: int = Field(description="Sum of every tool's findings before correlation.")
    unique_findings: int = Field(description="Findings after cross-tool deduplication.")
    dedup_rate: float = Field(description="1 - unique/raw; 0 when there were no findings.")


class FindingsPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[dict[str, Any]]


class ScanSummary(BaseModel):
    id: str
    status: str
    source_type: str
    source_label: str
    created_at: datetime
    finished_at: datetime | None
    unique_findings: int
    severity_counts: dict[str, int]


class FeedsStatus(BaseModel):
    """State of the exploit-likelihood feeds behind risk scores. Empty until the first download."""

    fetched_at: str | None = None
    stale: bool = True
    epss: dict[str, Any] | None = Field(
        default=None, description="FIRST.org EPSS: score date, rows."
    )
    kev: dict[str, Any] | None = Field(
        default=None, description="CISA KEV: catalog version, entries."
    )
    errors: dict[str, str] = Field(
        default_factory=dict, description="Last download error per feed."
    )
