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
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from core.persistence.vector_type import Vector
from core.rag.embed import DIM as _EMBED_DIM
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
    source_type: Mapped[str] = mapped_column(String(16))  # git | archive | web
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


class AssetVerification(Base):
    """Proof that whoever registered a web Asset actually controls it (plan §22.4, ADR-0035) --
    required before any DAST campaign may run against it. One row per Asset (a `web` one; a git/
    archive Asset never gets one), not a history: re-verifying overwrites `status`/`checked_at`/
    `error` in place, since only the current, live state matters -- a campaign gate checks "is this
    verified right now," never "was this ever verified." `token` is generated once at registration
    and never rotates on its own; registering the same domain again (a fresh `POST`) replaces it,
    which deliberately invalidates any DNS/well-known record already published for the old token."""

    __tablename__ = "asset_verifications"

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    method: Mapped[str] = mapped_column(String(16))  # dns_txt | well_known
    token: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset: Mapped[Asset] = relationship()


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

    # Where this Issue came from (Week 43, plan §21.4): "scanner" for every ordinary issue (the
    # default, and every issue that existed before this column did); "llm-confirmed" only for one
    # promoted from the Hypotheses lane (`core.hypotheses`), and only once a person confirmed it --
    # `core.hypotheses.repo`-style promotion is the one and only writer of that value.
    source: Mapped[str] = mapped_column(String(20), default="scanner")

    # Triage ASSISTANT (Week 43, plan §21.3): a model's verdict, distinct from the human decision
    # above -- deliberately named `assistant_*`, never `triage_*`, so nothing here is mistakable for
    # a human triage action. Advisory only: `core.risk.score` reads it as one ranking input (never
    # zero, never suppressing), and no code path lets it write `triage_status` itself.
    assistant_verdict: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    assistant_verdict_confidence: Mapped[str | None] = mapped_column(String(16), nullable=True)
    assistant_verdict_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    assistant_verdict_lines: Mapped[list[int] | None] = mapped_column(JsonType, nullable=True)
    assistant_verdict_model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    assistant_verdict_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

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
    source_type: Mapped[str] = mapped_column(String(16))  # git | archive | web
    source_ref: Mapped[str] = mapped_column(
        Text
    )  # git URL, server-side archive path, or target URL
    source_label: Mapped[str] = mapped_column(String(300))  # safe display name
    # Set only for a DAST campaign (source_type="web", Week 49 task 3, plan §22.4): "passive" (ZAP
    # baseline only) or "active" (adds curated Nuclei, rate-limited -- core.dast.campaign). Null for
    # every SAST/SCA scan, which has no such concept.
    dast_mode: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
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


class HypothesisRow(Base):
    """One Hypotheses-lane candidate the model chose to surface (Week 43, plan §21.4). Off by
    default, its own tab, excluded from the risk score and policy gates -- a genuinely separate
    table from `IssueRow`, not a variant `state`, precisely because it must NOT show up anywhere an
    Issue does until a person promotes it (the plan's own rule: LLM-originated content never enters
    the main issue list on its own).

    `snippet` is the exact code shown to the model at generation time, kept here so `promote()` can
    build a real Finding/Issue occurrence without a second clone of the repository."""

    __tablename__ = "hypotheses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    route_method: Mapped[str] = mapped_column(String(16))
    route_path: Mapped[str] = mapped_column(Text)
    file: Mapped[str] = mapped_column(Text)
    line: Mapped[int] = mapped_column(Integer)
    evidence: Mapped[str] = mapped_column(Text)
    suggested_check: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(16))
    snippet: Mapped[str] = mapped_column(Text)
    model: Mapped[str] = mapped_column(String(100))
    # open | promoted | dismissed
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    promoted_issue_id: Mapped[str | None] = mapped_column(
        ForeignKey("issues.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CodeChunkIndexRow(Base):
    """One row per asset: the hashed-embedder weights (`core.rag.embed.HashingEmbedder`) its
    `code_chunks` rows were embedded with (Week 44, plan §21.5's retrieval). A fresh fit per asset,
    not the remediation knowledge base's one global fit (`core.rag.store.KbMeta`) -- each asset's
    source code is its own small, distinct corpus, and nothing here ever compares one asset's chunk
    vectors against another's, so there is no reason to share weights across them."""

    __tablename__ = "code_chunk_indexes"

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    embedder: Mapped[str] = mapped_column(String(50))
    dim: Mapped[int] = mapped_column(Integer)
    idf: Mapped[list[float]] = mapped_column(JsonType)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CodeChunkRow(Base):
    """One function-level chunk of an asset's latest-indexed source (Week 44, plan §21.5), for the
    copilot's grounded retrieval. `id` is `core.codeintel.models.symbol_id()`'s own stable id, so
    re-indexing the same unchanged function produces the same row id (an upsert-by-replace, not an
    ever-growing table across refreshes -- see `core.embeddings.service.refresh_code_chunks`)."""

    __tablename__ = "code_chunks"

    id: Mapped[str] = mapped_column(String(600), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    path: Mapped[str] = mapped_column(Text)
    symbol_name: Mapped[str] = mapped_column(String(300))
    qualified_name: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(16))
    language: Mapped[str] = mapped_column(String(16))
    start_line: Mapped[int] = mapped_column(Integer)
    end_line: Mapped[int] = mapped_column(Integer)
    snippet: Mapped[str] = mapped_column(Text)
    embedding: Mapped[list[float]] = mapped_column(Vector(_EMBED_DIM))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CopilotConversationRow(Base):
    """One chat session against one asset (Week 44 task 3, plan §21.5). `context_kind`/`context_id`
    carry the page the panel was opened from ("issue"/<id> or "scan"/<id>, per §28.6's "keeps page
    context" rule) -- advisory only, never used for authorization; RLS/`org_id` checks always go
    through `asset_id`, not through whatever issue or scan is named here."""

    __tablename__ = "copilot_conversations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    context_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
    context_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_message_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class CopilotMessageRow(Base):
    """One turn of a copilot conversation: a user question or the copilot's own cited answer
    (`role` "user"/"assistant"). `citations` is null for a user message, and for an assistant
    message is exactly what `core.copilot.contract.validate_citations` already accepted -- never
    stored before validation passes."""

    __tablename__ = "copilot_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    conversation_id: Mapped[str] = mapped_column(
        ForeignKey("copilot_conversations.id", ondelete="CASCADE"), index=True
    )
    role: Mapped[str] = mapped_column(String(16))
    content: Mapped[str] = mapped_column(Text)
    citations: Mapped[list[dict[str, Any]] | None] = mapped_column(JsonType, nullable=True)
    tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ThreatModelRow(Base):
    """One project's threat-model draft (Week 45 task 3, plan §21.7): a Mermaid data-flow diagram
    plus a STRIDE table, generated from code intelligence already computed for this asset. One
    current row per asset (`asset_id` is itself the primary key) -- `version` increments on every
    save, `source` says whether the current content is the last `generate` output or a person's own
    `edit`, so a client can tell whether regenerating would discard something a person wrote."""

    __tablename__ = "threat_models"

    asset_id: Mapped[str] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    mermaid: Mapped[str] = mapped_column(Text)
    stride: Mapped[list[dict[str, Any]]] = mapped_column(JsonType)
    version: Mapped[int] = mapped_column(Integer, default=1)
    source: Mapped[str] = mapped_column(String(16))  # "generated" | "edited"
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)


class ScanDataKeyRow(Base):
    """A scan's envelope-encryption data key, wrapped by its organization's OpenBao KEK (Week 47
    task 1, plan §22.2, ADR-0032). `wrapped_dek` is OpenBao's own ciphertext string, encoded to
    bytes (core.secrets.openbao.encode_wrapped_key) -- the plaintext data key is never persisted
    anywhere, only held in memory for the duration of one encrypt/decrypt call. Deleting this row
    is Week 47 task 2's crypto-shredding: without it, every object encrypted under this key is
    permanently unreadable, backups included."""

    __tablename__ = "scan_data_keys"

    scan_id: Mapped[str] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


DEFAULT_RETENTION_DAYS = 7


class DataRetentionPolicyRow(Base):
    """How long an organization keeps a scan's encrypted artifacts before crypto-shredding them
    (Week 47 task 2, plan §22.2, ADR-0032). Lazily created: an org with no row here uses
    DEFAULT_RETENTION_DAYS (core.persistence.repo.get_retention_days), so this table only holds
    organizations that changed the default, not every organization that exists."""

    __tablename__ = "data_retention_policies"

    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    retention_days: Mapped[int] = mapped_column(Integer, default=DEFAULT_RETENTION_DAYS)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
