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


class RegisterWebAssetRequest(BaseModel):
    """Registering a DAST target (plan §22.4) -- this alone does not authorize scanning it; the
    returned instructions must be satisfied and `/verify` must pass before a campaign can start."""

    domain: str = Field(max_length=255, examples=["example.com"])
    method: Literal["dns_txt", "well_known"]
    source_asset_id: str | None = Field(
        default=None,
        description="Optionally link to an existing git/archive project (plan §22.4, Week 49 task "
        "4): its SAST scans' route map is what lets a later DAST finding be marked 'confirmed at "
        "runtime.' Must belong to the same organization.",
    )


class StartDastCampaignRequest(BaseModel):
    """Start a DAST campaign (plan §22.4, Week 49 task 3) against an already ownership-verified web
    Asset. "passive" (ZAP baseline only) runs unconditionally once verification passes; "active"
    (adds curated Nuclei) is rate-limited to one per asset per
    `core.dast.campaign.ACTIVE_SCAN_MIN_INTERVAL`."""

    mode: Literal["passive", "active"]


class AssetVerificationView(BaseModel):
    asset_id: str
    domain: str
    method: str
    status: str = Field(description="pending | verified | failed")
    record_name: str | None = Field(default=None, description="dns_txt only")
    record_value: str | None = Field(default=None, description="dns_txt only")
    well_known_url: str | None = Field(default=None, description="well_known only")
    file_content: str | None = Field(default=None, description="well_known only")
    created_at: datetime
    verified_at: datetime | None
    last_checked_at: datetime | None
    last_error: str | None


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


class ScanCostView(BaseModel):
    """Plan §23's cost-per-scan dashboard (Week 50) -- an estimate, not a bill; see
    core/observability/cost.py's own docstring for what it does and doesn't account for."""

    scan_id: str
    compute_seconds: float
    compute_usd: float
    llm_tokens: int
    llm_usd: float
    total_usd: float


class CostSummaryRow(BaseModel):
    scan_id: str
    source_label: str
    created_at: datetime
    compute_seconds: float
    llm_tokens: int
    total_usd: float


class CostSummaryView(BaseModel):
    days: int
    scan_count: int
    total_compute_seconds: float
    total_llm_tokens: int
    total_compute_usd: float
    total_llm_usd: float
    total_usd: float
    scans: list[CostSummaryRow]


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


class TriageAssistantView(BaseModel):
    """A model's verdict on one Issue (plan §21.3) -- advisory only, distinct from `IssueView`'s
    `triage_status` (a human decision, ADR-0012). `null` if the assistant has never run for this
    issue, which is the normal state until someone asks for one."""

    verdict: Literal["likely_real", "likely_false_positive", "unsure"]
    confidence: Literal["high", "medium", "low"]
    rationale: str
    supporting_lines: list[int]
    model: str
    generated_at: datetime


class HypothesisView(BaseModel):
    """One Hypotheses-lane candidate (plan §21.4) -- off by default, its own tab, excluded from the
    risk score and policy gates until a person promotes it. `promoted_issue_id` is set only once
    `status` is "promoted"."""

    id: str
    route_method: str
    route_path: str
    file: str
    line: int
    evidence: str
    suggested_check: str
    confidence: Literal["high", "medium", "low"]
    model: str
    status: Literal["open", "promoted", "dismissed"]
    promoted_issue_id: str | None
    created_at: datetime


class AttackPathNodeView(BaseModel):
    id: str
    kind: Literal["entrypoint", "issue", "secret", "cloud_resource"]
    label: str
    issue_id: str | None
    detail: str


class AttackPathEdgeView(BaseModel):
    kind: Literal["reachable_from", "grants_access_to", "exposes"]
    source: str
    target: str
    rule_id: str


class AttackPathView(BaseModel):
    """One ranked attack path (plan §21.6, §28.5). `narrative` is `None` when no model is routed
    for Task.ATTACK_PATH -- unlike the copilot, this never 409s for that: the graph itself (nodes,
    edges, ranking, cheapest_link) is always real and useful without a model, only the prose
    description is best-effort on top of it."""

    id: str
    likelihood: Literal["low", "medium", "high"]
    impact: Literal["low", "medium", "high", "critical"]
    rank_score: float
    cheapest_link: str
    narrative: str | None
    nodes: list[AttackPathNodeView]
    edges: list[AttackPathEdgeView]


class StrideRowView(BaseModel):
    element: str
    element_kind: Literal["external_entity", "process", "data_store", "external_interactor"]
    category: str
    prompt: str


class ThreatModelView(BaseModel):
    """A project's threat-model draft (plan §21.7): a Mermaid data-flow diagram plus a STRIDE
    table, generated from code intelligence -- a starting point for a person's own review, not an
    assessment. `source` says whether the current content is the last generate output or a
    person's own edit."""

    asset_id: str
    mermaid: str
    stride: list[StrideRowView]
    version: int
    source: Literal["generated", "edited"]
    updated_at: datetime
    updated_by: str | None


class SaveThreatModelRequest(BaseModel):
    mermaid: str
    stride: list[StrideRowView]


class RetentionSettingsView(BaseModel):
    """How long this organization keeps a scan's encrypted artifacts before crypto-shredding them
    (Week 47 task 2, plan §22.2). Never having set one returns the plan's own default (7 days), not
    an error or a null -- there is always an effective policy, even if no row exists for it yet."""

    org_id: str
    retention_days: int = Field(ge=1)


class SaveRetentionSettingsRequest(BaseModel):
    retention_days: int = Field(ge=1)


class PluginView(BaseModel):
    """One discovered third-party scanner-adapter plugin (Week 51 task 1, plan §23). `allowed`
    reflects the calling organization's own allowlist row right now -- it is not re-verified against
    Sigstore here (that only happens when a scan actually requests this tool); a plugin can show
    `allowed=True` and still fail at scan time if its image's signature has since gone bad."""

    name: str
    package_name: str
    package_version: str
    image: str
    certificate_identity: str
    certificate_oidc_issuer: str
    allowed: bool


class SetPluginAllowedRequest(BaseModel):
    enabled: bool = True


class IntegrationSettingsView(BaseModel):
    """Never echoes a secret value back (Week 51 task 2, plan §23) -- a webhook URL, a GitHub PAT,
    and a Jira API token are each themselves a bearer credential. `*_configured` says whether one is
    set; the non-secret fields (which repo/project an issue gets filed into) are shown in full since
    they're just config, not something that grants access on their own."""

    org_id: str
    slack_configured: bool
    discord_configured: bool
    outbound_webhook_configured: bool
    github_configured: bool
    github_issues_repo: str | None
    jira_configured: bool
    jira_base_url: str | None
    jira_project_key: str | None


class SaveIntegrationSettingsRequest(BaseModel):
    """A full replacement of this organization's integration settings (same semantics as
    `SaveRetentionSettingsRequest`'s single value, just over more fields): a field omitted here is
    cleared, not left unchanged. Re-fetch via `GET /settings/integrations` and resend every field
    you want to keep."""

    slack_webhook_url: str | None = None
    discord_webhook_url: str | None = None
    outbound_webhook_url: str | None = None
    outbound_webhook_secret: str | None = None
    github_token: str | None = None
    github_issues_repo: str | None = None
    github_webhook_secret: str | None = None
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    jira_webhook_secret: str | None = None


class GenerateHypothesesResult(BaseModel):
    generated: int = Field(description="How many NEW hypotheses this run surfaced and stored.")
    hypotheses: list[HypothesisView]


class PromoteHypothesisResult(BaseModel):
    issue_id: str = Field(description="The new Issue's id, source='llm-confirmed'.")


class VerifiedFixRequest(BaseModel):
    run_tests: bool = Field(
        default=False,
        description="Also run the project's own test suite as part of verification. Only takes "
        "effect when the asset is linked to a verified GitHub App installation (plan §21.2); "
        "silently ignored otherwise, never a 4xx for asking.",
    )
    test_image: str | None = Field(
        default=None, description="A Docker image to run tests in, e.g. 'python:3.12-slim'. "
        "Required when run_tests is true.",
    )  # fmt: skip
    test_command: str | None = Field(
        default=None,
        description="Shell command to install deps and run tests, e.g. 'pip install -r "
        "requirements.txt && pytest -q'. Required when run_tests is true.",
    )


class VerifiedFixStarted(BaseModel):
    run_id: str
    workflow_id: str


class VerifiedFixView(BaseModel):
    run_id: str
    issue_id: str
    status: str = Field(
        description="running | awaiting_approval | approved | rejected | opened_pr | failed | "
        "inconclusive"
    )
    attempts: int
    latest_patch: dict[str, Any] | None = Field(
        description="explanation/patch/confidence/tokens_used for the most recent attempt, once "
        "one has passed verification."
    )
    verification_record: list[dict[str, Any]] = Field(
        description="Every attempt's own verification steps, in order -- the audit trail ADR-0015 "
        "requires."
    )
    ended_reason: str | None = Field(
        description="Which limit ended a non-normal run: overall_timeout | per_attempt_timeout | "
        "max_attempts_exhausted | approval_timeout, or null for a normal approve/reject/opened_pr."
    )
    pr_url: str | None = None
    created_at: datetime
    updated_at: datetime


class StartConversationRequest(BaseModel):
    """Optional page context the panel was opened from (plan §28.6: "keeps page context"). Purely
    informational -- never used for authorization, and never required to start a conversation."""

    context_kind: Literal["issue", "scan"] | None = None
    context_id: str | None = None


class ConversationView(BaseModel):
    id: str
    asset_id: str
    context_kind: str | None
    context_id: str | None
    created_at: datetime
    last_message_at: datetime


class PostMessageRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class CitationView(BaseModel):
    kind: Literal["issue", "code"]
    issue_id: str | None = None
    path: str | None = None
    line: int | None = None


class MessageView(BaseModel):
    id: str
    role: Literal["user", "assistant"]
    content: str
    citations: list[CitationView] | None
    created_at: datetime
