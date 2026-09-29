from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class GitSource(BaseModel):
    type: Literal["git"]
    url: str = Field(max_length=300, examples=["https://github.com/OWASP/NodeGoat"])


class ScanRequest(BaseModel):
    source: GitSource
    tools: list[str] | None = Field(
        default=None,
        description="Defaults to the five default tools: bandit, semgrep, gitleaks, "
        "trivy, osv-scanner.",
    )


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
    issue_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Findings by Issue lifecycle state (new/open/reintroduced) for this scan's "
        "asset. Empty for scans that didn't finish 'completed', since only a full scan can "
        "tell an issue was fixed; see ADR-0012.",
    )


class FindingsPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[dict[str, Any]]


class DependenciesView(BaseModel):
    """Plan §20.5's Dependencies screen: one project's latest SBOM (`Scan.sbom_summary`), or an
    empty view when no scan has opted into `syft` yet -- never a 404, matching
    `/assets/{id}/issues`'s own "empty, not missing" shape."""

    scan_id: str | None = Field(description="The scan this SBOM came from; null if there is none.")
    generated_at: datetime | None = None
    components: int = 0
    ecosystems: dict[str, int] = Field(default_factory=dict)
    packages: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Each: name, version, ecosystem, purl, license, path, relation "
        "(direct|transitive|root|unknown), depends_on (purls), scorecard (or null).",
    )


class ScanSummary(BaseModel):
    id: str
    status: str
    source_type: str
    source_label: str
    created_at: datetime
    finished_at: datetime | None
    unique_findings: int
    severity_counts: dict[str, int]


class AssetSummary(BaseModel):
    """A project (plan §27) — one distinct repository/archive, org-scoped (ADR-0012, ADR-0013)."""

    id: str
    label: str
    source_type: str
    last_scanned_at: datetime
    latest_scan_id: str | None
    latest_scan_status: str | None
    open_issue_count: int = Field(
        description="Open issues as of the latest completed scan; 0 if no scan has completed yet."
    )


class ScannedTool(BaseModel):
    tool: str
    status: str
    findings: int = 0


class TriageRequest(BaseModel):
    action: Literal["not_a_risk", "accepted", "reopen"]
    reason: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = None


class BulkTriageRequest(BaseModel):
    issue_ids: list[str] = Field(min_length=1, max_length=500)
    action: Literal["not_a_risk", "accepted", "reopen"]
    reason: str | None = Field(default=None, max_length=2000)
    expires_at: datetime | None = None


class IssueView(BaseModel):
    id: str
    state: str
    triage_status: str
    triage_reason: str | None
    triage_expires_at: datetime | None


class BulkTriageResult(BaseModel):
    updated: list[str]
    failed: list[dict[str, str]] = Field(
        description="Each item: {issue_id, error} — one issue failing (e.g. not found in this "
        "org) doesn't abort the rest of the batch."
    )


class IssueHistoryEvent(BaseModel):
    at: datetime
    label: str


class TrendPoint(BaseModel):
    scan_id: str
    finished_at: datetime
    open_count: int


class ComparedIssue(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    path: str


class ScanComparisonSide(BaseModel):
    scan_id: str
    source_label: str
    finished_at: datetime | None
    github_pr_number: int | None


class ScanComparisonView(BaseModel):
    """Plan §28.6's scan comparison screen: two of an asset's scans, side by side."""

    earlier: ScanComparisonSide
    later: ScanComparisonSide
    new: list[ComparedIssue]
    fixed: list[ComparedIssue]
    reintroduced: list[ComparedIssue]
    unchanged: list[ComparedIssue]


class ProjectOverview(BaseModel):
    """Plan §28.1's project overview screen, built entirely from existing scan/issue data —
    see core/persistence/repo.py's asset-overview functions for how each field is derived."""

    asset: AssetSummary
    verdict_count: int = Field(
        description="Critical/high-severity, currently-reachable issues from the latest scan's "
        "risk-ranked top items — the plan's calm-by-default rule (§29.2): an unreachable critical "
        "doesn't inflate this count."
    )
    fix_first: list[dict[str, Any]] = Field(
        description="Same Finding shape as FindingsPage.items, risk-sorted, from the latest scan."
    )
    more_at_lower_risk: int
    since_previous_scan: dict[str, int] = Field(
        description="fixed/new/returned since the scan before this one (ADR-0012's issue states); "
        "not a literal 7-day calendar window."
    )
    trend: list[TrendPoint]
    scanned: list[ScannedTool]
    latest_scan_id: str | None
    latest_scan_finished_at: datetime | None


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
    tokens_used: int = Field(
        default=0, description="Tokens this call actually spent; 0 for static text or a cache hit."
    )


class GuidanceView(BaseModel):
    finding_id: str
    static: RemediationView = Field(description="Deterministic reference guidance; always present.")
    ai: RemediationView | None = Field(
        description="A previously generated AI suggestion, if one is cached."
    )
    ai_enabled: bool = Field(description="Whether this server can generate AI suggestions.")
    model: str | None = None
