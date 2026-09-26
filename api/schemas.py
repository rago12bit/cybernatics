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
    warnings: list[str] = Field(
        default_factory=list, description="Succeeded but possibly incomplete."
    )
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


class SuggestionRequest(BaseModel):
    finding_id: str = Field(
        min_length=1, max_length=500, description="A finding's `id` within the scan."
    )


class RemediationView(BaseModel):
    """Guidance for one finding. `source` says whether a model wrote it."""

    source: str = Field(
        description="'ai' (written by a model) or 'static' (reference text, no model)."
    )
    label: str = Field(
        description="Always shown with the content, e.g. 'AI suggestion: review before applying'."
    )
    explanation: str
    impact: str
    fix_summary: str
    suggested_patch: str | None = Field(
        description="A unified diff as TEXT. Bulwark never applies it."
    )
    confidence: str = Field(
        description="Confidence in the fix, not in whether the finding is real."
    )
    model: str | None = None
    degraded_reason: str | None = None
    warnings: list[str] = Field(default_factory=list)
    references: list[dict[str, str]] = Field(default_factory=list)
    patch_status: str | None = Field(
        default=None, description="'verified' (matches the code) or 'unverified'."
    )
    from_cache: bool = False
    generated_at: str | None = None


class GuidanceView(BaseModel):
    finding_id: str
    static: RemediationView = Field(description="Deterministic reference guidance; always present.")
    ai: RemediationView | None = Field(
        description="A previously generated AI suggestion, if one is cached."
    )
    ai_enabled: bool = Field(description="Whether this server can generate AI suggestions.")
    model: str | None = None
