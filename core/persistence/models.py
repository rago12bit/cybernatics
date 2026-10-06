"""Relational schema (SQLAlchemy 2.0): findings keep full canonical JSON + indexed columns."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
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

from core.persistence.utc_type import UtcDateTime
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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class GithubInstallation(Base):
    """One GitHub App installation (Week 30, ADR-0017) -- an org or user account that installed
    Bulwark's GitHub App, on some or all of their repositories. Maps 1:1 onto a Bulwark
    `Organization` (ADR-0013): installing the App is, in effect, how a tenant is created for now,
    since there is no separate org-management API yet (ADR-0013's own deferred item)."""

    __tablename__ = "github_installations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # GitHub's installation id
    account_login: Mapped[str] = mapped_column(String(200))  # the org/user that installed it
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)


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
    timestamp: Mapped[datetime] = mapped_column(UtcDateTime())
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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    last_scanned_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    # Set only on a `web` Asset, optionally, at registration (Week 49 task 4, plan §22.4): the
    # git/archive Asset whose SAST scans' `route_map` a DAST campaign against this target should
    # correlate its findings against ("confirmed at runtime," core.dast.correlate). No FK: a web
    # Asset must survive the source Asset it's linked to being deleted independently --
    # `repo.register_web_asset` enforces same-org at write time instead, so this never silently
    # points at another organization's project even without a DB-level constraint.
    linked_source_asset_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # The business unit the project belongs to (Week 64, plan §49): its tags are inherited by the
    # project and its Issues. Optional; a project need not be in a portfolio.
    portfolio_id: Mapped[str | None] = mapped_column(
        ForeignKey("portfolios.id", ondelete="SET NULL"), nullable=True, index=True
    )

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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    verified_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    asset: Mapped[Asset] = relationship()


class Portfolio(Base):
    """Groups projects/Assets by business unit (plan §40 change C11, Week 53, ADR-0039): "teams
    group projects by business unit." Purely organizational -- an Engagement's `portfolio_id` is
    nullable, so a project can exist (and be scanned) without ever being assigned to one."""

    __tablename__ = "portfolios"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class Engagement(Base):
    """A time-boxed activity against one Asset (plan §40 change C11, Week 53, ADR-0039): "pen tests
    and audits are time-boxed engagements; imported reports need a home that isn't a scan." Every
    Asset gets one "ci" Engagement automatically (migration 0026's own backfill, and
    `core.persistence.repo.get_or_create_ci_engagement` for every Asset created since); a person (or
    a later v3 import flow) creates "pentest"/"audit"/"adhoc" ones explicitly. A ToolRun belongs to
    exactly one Engagement via its own `engagement_id` -- see that column's docstring for why
    "Test" (plan §40/§42) is an existing ToolRun row, not a new table."""

    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    portfolio_id: Mapped[str | None] = mapped_column(
        ForeignKey("portfolios.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(300))
    engagement_type: Mapped[str] = mapped_column(String(16), default="ci")  # ci|pentest|audit|adhoc
    status: Mapped[str] = mapped_column(String(16), default="active")  # active|completed
    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    target_end_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    # An assessment (Week 64, plan §43.1): scope, people, a checklist, and the report written on
    # closing. Its `status` is planned | in_progress | reporting | closed; the standing "ci" and
    # "import" engagements keep active | completed. People are names (or API token names) until
    # user accounts exist (Week 75).
    scope_targets: Mapped[list[str]] = mapped_column(JsonType, default=list)  # hosts, URLs, repos
    scope_routes: Mapped[list[str]] = mapped_column(
        JsonType, default=list
    )  # "/v2/", "POST /orders"
    out_of_scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    lead: Mapped[str | None] = mapped_column(String(200), nullable=True)
    testers: Mapped[list[str]] = mapped_column(JsonType, default=list)
    checklist: Mapped[str | None] = mapped_column(String(32), nullable=True)  # "wstg-4.2", ...
    closed_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    # The report written on closing: a snapshot of what it says, rendered to Markdown or HTML on
    # download (`core.engagements.report`), so a later change to an Issue never rewrites it.
    report: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    report_generated_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)

    asset: Mapped[Asset] = relationship()


class EngagementChecklistItem(Base):
    """One checklist entry's result in an assessment (plan §43.1): only entries someone touched have
    a row; the rest are "not started". `item_id` is the catalogue's own id ("WSTG-INFO-02",
    "V2.1.1"), from `core/engagements/checklists/`."""

    __tablename__ = "engagement_checklist_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    item_id: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16))  # pass | fail | not_applicable | in_progress
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (
        UniqueConstraint("engagement_id", "item_id", name="uq_engagement_checklist_item"),
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
    first_seen_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    fixed_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

    # Triage (Week 34, plan §28.3): a human decision layered on top of `state`, not a replacement
    # for it -- an issue a scan still finds can independently be "open" (untouched), "not_a_risk"
    # (a person said so, with a reason), or "accepted" (a person said so, with an expiry; it
    # reappears in the active queue automatically once `triage_expires_at` passes).
    triage_status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    triage_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    triage_expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    triaged_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
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
    assistant_verdict_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

    # "Confirmed at runtime" (Week 49 task 4, plan §22.4): set only when a DAST campaign's finding
    # correlated against this Issue on the same route+CWE (`core.dast.correlate`) -- a static
    # finding a real HTTP request actually reached, not merely a model's or a tool's guess.
    # `confirmed_by_scan_id` has no FK: it names the DAST campaign (a Scan row) that confirmed it,
    # which may belong to a different asset-scan lineage than this Issue's own SAST scans and must
    # survive that campaign scan being deleted independently of this Issue's own lifecycle.
    confirmed_at_runtime_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    confirmed_by_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # SLA (Week 61, plan §44.1): the clock runs from first detection -- `first_seen_at`, which
    # reimport never resets -- unless something restarted it (a risk acceptance that expired with
    # "restart the SLA", Week 62), in which case from `sla_started_at`. `sla_notified` is the last
    # SLA state announced ("due_soon" or "breached"), so each crossing is announced exactly once.
    sla_started_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    sla_notified: Mapped[str | None] = mapped_column(String(16), nullable=True)
    sla_notified_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

    # Priority (Week 63, plan §44.3): the score the issues table ranks by, its band (P1-P4, which
    # an SLA can key on), and why -- each factor with its weight. Written at ingest and by a
    # recomputation (`core.priority.service`). `priority_version` is the project's priority policy
    # version that computed it; 0 means no policy, so the score is the v2 risk score unchanged.
    priority_score: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    priority_band: Mapped[str | None] = mapped_column(String(4), nullable=True, index=True)
    priority_factors: Mapped[list[dict[str, Any]] | None] = mapped_column(JsonType, nullable=True)
    priority_version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Retest (Week 64, plan §43.3): a developer marks the Issue ready for retest ("requested"); a
    # tester confirms it fixed ("passed", and the Issue is fixed) or reproduces it ("failed", back
    # to open with a note). For a scanner's Issue the next scan, or a targeted retest of the one
    # rule, decides instead (`core.retest`).
    retest_status: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    retest_requested_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    retest_requested_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    retest_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    retest_decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    retest_decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Week 65 (plan §45): who owns the fix -- a person's actor ("token:<prefix>"), set by a person
    # or a rule -- and a priority band a person or a rule set by hand. The override wins over the
    # computed band everywhere a band is read (the issues table, the SLA), and a recomputation never
    # clears it: only a person or a rule does.
    assignee: Mapped[str | None] = mapped_column(String(200), nullable=True, index=True)
    assigned_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    priority_override: Mapped[str | None] = mapped_column(String(4), nullable=True)
    priority_override_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Week 66 (plan §41.2, §49): Issues one ticket tracks together.
    group_id: Mapped[str | None] = mapped_column(
        ForeignKey("issue_groups.id", ondelete="SET NULL"), nullable=True, index=True
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
    # Web-route handlers found in this scan's own Python source (Week 49 task 4, plan §22.4):
    # `[{"route": "/assets/*/campaigns", "path": "api/main.py", "line": 648}, ...]`. What a later
    # DAST campaign's `core.dast.correlate` matches a live finding's route against to mark a
    # static finding "confirmed at runtime." Empty list (not null) for an ordinary scan that found
    # no Python route decorators at all -- null only for a scan from before this column existed.
    route_map: Mapped[list[dict[str, Any]] | None] = mapped_column(JsonType, nullable=True)
    # Every HTTP entrypoint code intelligence found (Week 59, plan §20.2 / §43.2), any framework it
    # knows, with the verb: `[{"method": "POST", "route": "/orders", "path": "app/api.py",
    # "line": 41, "symbol": "create_order", "framework": "fastapi"}]`. What the manual finding
    # form's route picker offers. Null for a scan from before migration 0031, or one whose code
    # analysis did not run.
    entrypoints: Mapped[list[dict[str, Any]] | None] = mapped_column(JsonType, nullable=True)
    # Model gateway token budget (plan §21.1, ADR-0026): total tokens every AI remediation call tied
    # to this scan has actually used. A running counter updated in place, unlike sbom_summary's
    # write-once snapshot -- `core.llm.budget.check()` compares it against a per-scan cap before
    # each call, so one scan generating suggestions for every one of its findings can't alone
    # exhaust an organization's whole monthly budget.
    llm_tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

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
    # The v3 hierarchy's "Test" concept (plan §40 change C11, ADR-0039, migration 0026): a ToolRun
    # already is "one tool's results," so Engagement attaches to the existing row instead of a new
    # parallel table duplicating these same columns. Nullable because RLS on `tool_runs` itself is
    # (and stays) the existing EXISTS-through-`scans` policy, not this column -- a null
    # engagement_id is a data-migration/backfill state, never a tenancy gap.
    engagement_id: Mapped[str | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True, index=True
    )

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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    last_message_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
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
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


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
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class PluginAllowlistRow(Base):
    """A third-party scanner-adapter plugin an organization has chosen to trust (Week 51 task 1,
    plan §23). Default-deny, the opposite lazy-creation sense of DataRetentionPolicyRow above: no
    row for (org_id, plugin_name) means "not allowed," not "allowed with a default" -- a plugin
    discovered via entry-point but never explicitly allowlisted must never run just because it's
    installed alongside Bulwark. `core.plugins.signing` re-verifies the plugin image's Sigstore
    signature every time it actually runs, not only once at allow-time -- this row records an
    organization's decision to trust the *publisher identity*, not a one-time image hash pin."""

    __tablename__ = "plugin_allowlist"

    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    plugin_name: Mapped[str] = mapped_column(String(200), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_by: Mapped[str] = mapped_column(String(200))  # audit actor, e.g. "token:abc123"
    allowed_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class IntegrationSettingsRow(Base):
    """One organization's notification/ticketing integration config (Week 51 task 2, plan §23).
    Lazily created like DataRetentionPolicyRow: no row means every integration is off, not a
    default-enabled one -- "off means off" (core/secrets/resolve.py's own stated convention),
    applied here too.

    All of these are plaintext columns. That's a real, disclosed gap, not an oversight: the Slack/
    Discord webhook URLs, the GitHub PAT, and the Jira API token are each themselves a bearer
    credential, and unlike a scan's object-storage data (`ScanDataKeyRow`, envelope-encrypted via
    OpenBao Transit), nothing here is wrapped at rest. Doing the same OpenBao-envelope treatment for
    these is real future work -- see docs/v2-week51-verification.md for why it wasn't done this
    task, and `core/secrets/openbao.py`'s `OpenBaoClient` for the primitives it would reuse
    (`ensure_org_key`/`generate_data_key`/`unwrap_data_key`, one durable per-org key rather than a
    fresh one per scan)."""

    __tablename__ = "integration_settings"

    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True
    )
    slack_webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    discord_webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    outbound_webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    outbound_webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    github_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    github_issues_repo: Mapped[str | None] = mapped_column(String(200), nullable=True)
    github_webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    jira_base_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    jira_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    jira_api_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    jira_project_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    teams_webhook_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    jira_webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class ExternalIssueLinkRow(Base):
    """Maps one Bulwark Issue to one externally created ticket (Week 51 task 2, plan §23) -- what
    "two-way status sync" needs in both directions: Bulwark -> external (close/reopen the linked
    ticket when `core.issues.sync` transitions the Issue to fixed/reintroduced) and external ->
    Bulwark (an inbound webhook looks a ticket up by `(org_id, provider, external_id)` to find which
    Issue it belongs to).

    `external_status` is sync metadata only -- it is never read back into `IssueRow.state`. A human
    closing a GitHub issue or Jira ticket does not, by itself, change Bulwark's own belief about
    whether the vulnerability is still present; only the next scan (`core.issues.sync`) can do that.
    Treating an external close as authoritative would let a person silently hide a still-exploitable
    finding from Bulwark's own tracking by closing the wrong tab."""

    __tablename__ = "external_issue_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    issue_id: Mapped[str] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    provider: Mapped[str] = mapped_column(String(16))  # "github" | "jira"
    external_id: Mapped[str] = mapped_column(String(300))  # "owner/repo#5" | "PROJ-123"
    external_url: Mapped[str] = mapped_column(Text)
    external_status: Mapped[str] = mapped_column(String(16), default="open")  # sync metadata only
    # Week 66 (plan §49): the group the ticket was filed for (every member has a link to the same
    # ticket), what the ticket last said, and a digest of the fields Bulwark last pushed, so a sync
    # writes only when something it owns changed.
    group_id: Mapped[str | None] = mapped_column(
        ForeignKey("issue_groups.id", ondelete="SET NULL"), nullable=True
    )
    raw_status: Mapped[str | None] = mapped_column(String(100), nullable=True)
    external_assignee: Mapped[str | None] = mapped_column(String(200), nullable=True)
    synced_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    pushed_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (
        UniqueConstraint("issue_id", "provider", name="uq_external_links_issue_provider"),
        Index("ix_external_links_org_provider_external_id", "org_id", "provider", "external_id"),
    )


class EngagementTest(Base):
    """A persistent Test (plan §40 change C11, §41.2, ADR-0040): "one tool's results within an
    engagement," which stays the same row across every report uploaded into it -- the thing a
    reimport is compared against ("every later upload is compared against that Test's previous
    Occurrences"). Named `EngagementTest`, not `Test`, so pytest never tries to collect it.

    This is deliberately *not* where a CI scanner's results live: each pipeline run's per-tool
    result is still a `ToolRun` (ADR-0039), one per run, which is exactly the plan's "each run of
    your own pipeline creates one Test per scanner." A person-created Assessment or Import
    engagement has no scan to hang a ToolRun on and needs one row that outlives each upload."""

    __tablename__ = "engagement_tests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    engagement_id: Mapped[str] = mapped_column(
        ForeignKey("engagements.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    # "sarif", "nessus", ... or "universal:<mapping id>" for a saved mapping (migration 0030).
    parser: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    engagement: Mapped[Engagement] = relationship()

    __table_args__ = (UniqueConstraint("engagement_id", "name", name="uq_engagement_tests_name"),)


class ImportRecord(Base):
    """One upload into a Test, and exactly what it changed (plan §42.1, ADR-0040).

    Each import is backed by a real `Scan` row (`source_type="import"`) that owns its findings, so
    every Occurrence keeps the scan-scoped foreign keys and RLS policy the rest of the system
    already relies on; this record adds what a Scan doesn't carry -- the file's digest
    (idempotency), the four counts the import screen shows, and `changes`, the prior state of every
    Issue this import touched, which is what makes the most recent import into a Test reversible.

    `status` is "applied" or "reverted". A reverted record is kept (the audit trail of a mistaken
    upload is worth more than the row), but its Scan and findings are removed, so it no longer
    counts as the Test's previous snapshot."""

    __tablename__ = "import_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    test_id: Mapped[str] = mapped_column(
        ForeignKey("engagement_tests.id", ondelete="CASCADE"), index=True
    )
    # SET NULL, not CASCADE: retention deleting an old scan's data must not erase the record that
    # an import happened (its counts and digest are still the audit trail); a null scan_id just
    # means "its findings have been purged."
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, unique=True
    )
    parser: Mapped[str] = mapped_column(String(64))  # a parser name, or "universal:<mapping id>"
    file_name: Mapped[str | None] = mapped_column(String(300), nullable=True)
    file_digest: Mapped[str] = mapped_column(String(64))  # sha256 hex of the uploaded bytes
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    # queued -> processing -> applied | previewed | failed | duplicate; applied -> reverted.
    # "previewed" waits (with its upload kept) for a person to confirm; "duplicate" is a second
    # upload of a file that was already the Test's latest import, noticed once it reached the
    # front of the queue (the API catches the ordinary case before ever creating a record).
    status: Mapped[str] = mapped_column(String(16), default="applied")
    mode: Mapped[str] = mapped_column(String(16), default="apply")  # apply | preview
    upload_path: Mapped[str | None] = mapped_column(Text, nullable=True)  # until applied or failed
    error: Mapped[str | None] = mapped_column(Text, nullable=True)  # why a failed import failed
    # What a preview computed: counts, and the reopened/closed/detached Issue ids (ImportPreview).
    preview: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    close_missing: Mapped[bool] = mapped_column(Boolean, default=True)
    scope: Mapped[str] = mapped_column(String(16), default="test")  # test | engagement
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    unchanged_count: Mapped[int] = mapped_column(Integer, default=0)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    closed_count: Mapped[int] = mapped_column(Integer, default=0)
    # Issues this file stopped reporting that stay open because another source still reports
    # them: honest about "no longer in this file" versus "actually fixed" (ADR-0040).
    detached_count: Mapped[int] = mapped_column(Integer, default=0)
    warnings: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    # [{"issue_id", "created": bool, "prior_state", "prior_fixed_at"}, ...] -- enough to undo it.
    changes: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    reverted_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

    __table_args__ = (
        Index("ix_import_records_test_created", "test_id", "created_at"),
        Index("ix_import_records_test_digest", "test_id", "file_digest"),
    )


class DedupSetting(Base):
    """How one source's findings are matched into Issues for one project (plan §42.3, ADR-0042).

    Settings are versioned and never edited: a change adds a row with the next `version`, so the
    history of who changed what, when, and with what effect is the table itself. The setting in
    force for a (project, source) is the row with the highest version; with none, the source uses
    `fingerprint_v2`, which is what every Issue was matched by before settings existed."""

    __tablename__ = "dedup_settings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(60))  # a tool or parser name: "nessus", "zap"
    strategy: Mapped[str] = mapped_column(String(24))
    fields: Mapped[list[str]] = mapped_column(JsonType, default=list)  # for hash_fields
    version: Mapped[int] = mapped_column(Integer)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    # What applying it did to the project's existing Issues: {"merged": n, "split": n, ...}.
    effect: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)

    __table_args__ = (UniqueConstraint("asset_id", "source", "version", name="uq_dedup_settings"),)


class SlaPolicy(Base):
    """How long a project has to fix an Issue, per severity band (plan §44.1, Week 61).

    Versioned like dedup settings: a change adds a row with the next `version`, never edits one, so
    the table is its own history. The policy in force is the highest version; with none, the
    project has no SLA (the starter values are offered, not imposed). `bands` maps a severity to
    `{"days": n, "warn": n}` -- fix within `days` of first detection, "due soon" in the last `warn`
    days; a band without days has no deadline."""

    __tablename__ = "sla_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    basis: Mapped[str] = mapped_column(String(16), default="severity")
    bands: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (UniqueConstraint("asset_id", "version", name="uq_sla_policies"),)


class PriorityPolicy(Base):
    """How a project ranks its Issues (plan §44.3, Week 63): a weight per factor and the project's
    business context. Versioned like SLA policies -- a change adds a row, never edits one -- and
    each version records its own recomputation, which is also the lock: while the newest version's
    recomputation is pending or running, no new version can be saved (`core.priority.service`).
    The unique (asset, version) pair is what stops two saves racing past that check."""

    __tablename__ = "priority_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    weights: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    context: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    # pending -> running -> done | failed | superseded
    status: Mapped[str] = mapped_column(String(16), default="pending")
    total: Mapped[int] = mapped_column(Integer, default=0)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    changed: Mapped[int] = mapped_column(Integer, default=0)  # Issues whose band moved
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (UniqueConstraint("asset_id", "version", name="uq_priority_policies"),)


class RiskAcceptance(Base):
    """A decision to live with one or more Issues for a while (plan §44.2, Week 62, ADR-0046).

    Requested by one person and approved by another -- enforced on the server: the approver's
    actor must differ from the requester's, and must be a personal API token, not the shared
    deployment token. Until approved, the Issues stay open. Approval writes the existing triage
    fields on each Issue (`accepted` until `expires_at`), so the active queue, the SLA pause and the
    policy gate's 90-day rule all read it unchanged. Every state change is in the audit log.

    States: requested -> approved | rejected | withdrawn; approved -> expired (on its date, or
    "expire now") | extended (an approved extension replaced it); expired early -> approved again
    ("reinstate", within the approved dates only)."""

    __tablename__ = "risk_acceptances"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    decision: Mapped[str] = mapped_column(String(16))  # accept | mitigate | transfer | avoid
    justification: Mapped[str] = mapped_column(Text)
    controls: Mapped[str] = mapped_column(Text)
    proof_links: Mapped[list[str]] = mapped_column(JsonType, default=list)
    expires_at: Mapped[datetime] = mapped_column(UtcDateTime())
    restart_sla: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String(16), index=True)
    requested_by: Mapped[str] = mapped_column(String(200))
    requested_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    approver: Mapped[str | None] = mapped_column(String(200), nullable=True)  # who was asked
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    ended_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ended_reason: Mapped[str | None] = mapped_column(String(24), nullable=True)
    extends_id: Mapped[str | None] = mapped_column(
        ForeignKey("risk_acceptances.id", ondelete="SET NULL"), nullable=True
    )
    # Made from an Issue someone accepted alone, before four-eyes approval existed (migration 0034).
    legacy: Mapped[bool] = mapped_column(Boolean, default=False)
    # When the "expiring soon" announcement went out (Week 65, plan §45), so it goes out once.
    expiry_warned_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)


class RiskAcceptanceIssue(Base):
    """Which Issues one risk acceptance covers."""

    __tablename__ = "risk_acceptance_issues"

    acceptance_id: Mapped[str] = mapped_column(
        ForeignKey("risk_acceptances.id", ondelete="CASCADE"), primary_key=True
    )
    issue_id: Mapped[str] = mapped_column(
        ForeignKey("issues.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )


class IngestMapping(Base):
    """A saved universal-mapper mapping (plan §42.4, ADR-0043): where each field of an unsupported
    report format lives. Imported with parser `universal:<id>`.

    Versioned by insertion, like `DedupSetting`: editing a mapping adds a row with the same `name`
    and the next `version`, and never changes an earlier one. An import names the exact row it was
    parsed with, so what read a past import can always be shown, even after the mapping changed."""

    __tablename__ = "ingest_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    name: Mapped[str] = mapped_column(String(200))
    version: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(40))  # the tool name findings are reported by
    format: Mapped[str] = mapped_column(String(8))  # json | csv | xml
    spec: Mapped[dict[str, Any]] = mapped_column(JsonType)  # MappingSpec.to_dict()
    # Who wrote the first draft: "heuristic", "model:<name>", or null for a person from scratch.
    # Recorded, not trusted: a person confirmed every field before this row existed.
    proposed_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    sample_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (
        UniqueConstraint("org_id", "name", "version", name="uq_ingest_mappings_version"),
    )


class ManualFinding(Base):
    """A finding a person recorded (plan §43.2, ADR-0044): what a pen tester or code reviewer found
    that no scanner did. It enters through the same ingest path as everything else (source
    `manual`, ADR-0040) and becomes an ordinary Issue; this row keeps what the canonical Finding
    has no place for -- the CVSS 4.0 vector next to its score, the steps, impact and recommendation
    as written, where it was found, and the automated finding it turned out to match, if any."""

    __tablename__ = "manual_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    test_id: Mapped[str] = mapped_column(
        ForeignKey("engagement_tests.id", ondelete="CASCADE"), index=True
    )
    # CASCADE: undoing the import that created the Issue (the most recent one into the Test can be
    # reverted, ADR-0040) takes the manual record with it, rather than leaving one pointing nowhere.
    issue_id: Mapped[str] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    import_id: Mapped[str | None] = mapped_column(
        ForeignKey("import_records.id", ondelete="SET NULL"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(300))
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    cvss_vector: Mapped[str | None] = mapped_column(String(300), nullable=True)  # CVSS:4.0/...
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    location_kind: Mapped[str] = mapped_column(String(8))  # route | file
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    route: Mapped[str | None] = mapped_column(String(500), nullable=True)
    host: Mapped[str | None] = mapped_column(String(300), nullable=True)
    path: Mapped[str | None] = mapped_column(Text, nullable=True)
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    steps: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list[str]] = mapped_column(JsonType, default=list)
    # An automated Issue on the same handler with a related CWE (`core.dast.correlate`), whose taint
    # path this finding carries as evidence. No FK: it is a pointer to another source's Issue that
    # must not cascade this record away if that Issue is merged or purged.
    related_issue_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    related_source: Mapped[str | None] = mapped_column(String(60), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class EvidenceAttachment(Base):
    """A screenshot or HTTP capture attached to a manual finding (plan §43.2, threat T24). Stored
    in the database -- so the same row-level security as everything else applies to it -- and
    envelope-encrypted with a fresh data key when OpenBao is configured (`encrypted`,
    `wrapped_dek`). Never rendered inline: served only as a download through a short-lived signed
    link, with the type the bytes actually are (`sniffed_type`) recorded beside the type the
    uploader claimed."""

    __tablename__ = "evidence_attachments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    manual_finding_id: Mapped[str | None] = mapped_column(
        ForeignKey("manual_findings.id", ondelete="CASCADE"), index=True, nullable=True
    )
    # Proof for a risk acceptance (Week 62) uses the same storage: exactly one owner is set.
    risk_acceptance_id: Mapped[str | None] = mapped_column(
        ForeignKey("risk_acceptances.id", ondelete="CASCADE"), index=True, nullable=True
    )
    # ...and so do files on an Issue note (Week 64, plan §49).
    note_id: Mapped[str | None] = mapped_column(
        ForeignKey("issue_notes.id", ondelete="CASCADE"), index=True, nullable=True
    )
    file_name: Mapped[str] = mapped_column(String(255))
    declared_type: Mapped[str | None] = mapped_column(String(120), nullable=True)
    sniffed_type: Mapped[str] = mapped_column(String(60))
    active_content: Mapped[bool] = mapped_column(Boolean, default=False)  # HTML, SVG, XML
    size_bytes: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    data: Mapped[bytes] = mapped_column(LargeBinary)
    encrypted: Mapped[bool] = mapped_column(Boolean, default=False)
    wrapped_dek: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class RetestRun(Base):
    """A targeted retest (plan §43.3): one tool re-run for one rule against one location, on a
    fresh checkout of the project -- or one DAST template against one URL of a verified target. It
    never touches the scan history; its result decides the Issue's retest."""

    __tablename__ = "retest_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    issue_id: Mapped[str] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # rule | dast
    tool: Mapped[str] = mapped_column(String(64))
    rule: Mapped[str] = mapped_column(String(300))
    location: Mapped[str] = mapped_column(Text)  # a file path, or a URL
    source_ref: Mapped[str] = mapped_column(Text)  # what was checked out or requested
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed
    result: Mapped[str | None] = mapped_column(String(16), nullable=True)  # still_present|gone
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    started_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)


class IssueNote(Base):
    """A note on an Issue (plan §49): threaded one level deep (`parent_id`), with @mentions
    resolved to the organization's API token names at writing time. The body is plain text; the
    web app never renders it as HTML. Deleting keeps the row (its replies stay readable) and blanks
    the body."""

    __tablename__ = "issue_notes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    issue_id: Mapped[str] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    parent_id: Mapped[str | None] = mapped_column(
        ForeignKey("issue_notes.id", ondelete="CASCADE"), nullable=True, index=True
    )
    body: Mapped[str] = mapped_column(Text)
    author: Mapped[str] = mapped_column(String(200))
    mentions: Mapped[list[str]] = mapped_column(JsonType, default=list)  # actors ("token:<id>")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    edited_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)


class Tag(Base):
    """A tag on a portfolio, a project or an Issue (plan §49). Tags inherit downward: an Issue's
    tags are its own plus its project's plus the project's portfolio's (`core.collab.tags`)."""

    __tablename__ = "tags"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    target_type: Mapped[str] = mapped_column(String(16))  # portfolio | project | issue
    target_id: Mapped[str] = mapped_column(String(36), index=True)
    name: Mapped[str] = mapped_column(String(50))
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (UniqueConstraint("target_type", "target_id", "name", name="uq_tags"),)


class Connector(Base):
    """A scheduled pull from (or push to) another system (plan §42.5, ADR-0045): GitHub code
    scanning or Dependabot, a GitLab vulnerability report, or a DefectDojo product. Pulls land in
    `test_id` through the ingest path; health is kept here, because the failure that matters most
    is the quiet one -- a connection that authenticates and fetches nothing.

    `config` holds no secret. A credential lives in OpenBao's KV store when it is configured
    (`credential_store="openbao"`); otherwise in `credential`, unencrypted, and the API says so.
    The GitHub kinds store none: they mint a short-lived token from the GitHub App on each pull."""

    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    name: Mapped[str] = mapped_column(String(200))
    config: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=360)
    # An empty pull after a non-empty one closes nothing unless this is set: "everything was fixed
    # at once" and "the token lost access" look the same from here (ADR-0045).
    close_on_empty: Mapped[bool] = mapped_column(Boolean, default=False)
    credential_store: Mapped[str] = mapped_column(
        String(16), default="none"
    )  # none|openbao|database
    credential: Mapped[str | None] = mapped_column(Text, nullable=True)
    test_id: Mapped[str | None] = mapped_column(
        ForeignKey("engagement_tests.id", ondelete="SET NULL"), nullable=True
    )
    state: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)  # e.g. DefectDojo test id
    # never_run | ok | empty | failing | disabled
    status: Mapped[str] = mapped_column(String(16), default="never_run", index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_items: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_items_seen: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class ConnectorRun(Base):
    """One pull or push, and what came of it -- the history behind a connector's health."""

    __tablename__ = "connector_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    connector_id: Mapped[str] = mapped_column(
        ForeignKey("connectors.id", ondelete="CASCADE"), index=True
    )
    started_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16))  # ok | empty | failed
    items: Mapped[int] = mapped_column(Integer, default=0)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    import_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    counts: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    warnings: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class OutboxEvent(Base):
    """A domain event waiting to be announced (plan §41.1): "write each event to an outbox table in
    the same transaction as the change that caused it, and publish from there. A crash between
    'saved' and 'announced' then can't lose an event." `dispatched_at` is null until a dispatcher
    has handed it to every subscriber; the integer primary key gives dispatch a stable order."""

    __tablename__ = "outbox_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), default=DEFAULT_ORG_ID, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True)  # issue.created, scan.completed
    payload: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    dispatched_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True, index=True)


class AutomationRule(Base):
    """A rule (plan §45, Week 65): WHEN a trigger fires, IF a Rego condition holds, THEN actions.
    `asset_id` null means every project in the organization. A deleted rule keeps its row
    (`deleted_at`) so its run history still says what ran. `version` goes up on every change, and
    each run records the version it ran, so the audit log can say which rule text did what."""

    __tablename__ = "automation_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    trigger: Mapped[str] = mapped_column(String(40), index=True)
    trigger_params: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    condition: Mapped[str] = mapped_column(Text, default="")  # Rego rule body; empty: always
    actions: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list)
    confirm_over: Mapped[int] = mapped_column(Integer, default=25)
    version: Mapped[int] = mapped_column(Integer, default=1)
    template: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    updated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    last_fired_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)


class RuleRun(Base):
    """One firing of a rule for one cause (a scan, an import, one event, a schedule tick, a quiet
    project). `status`: running (acting now), applied, held (more Issues than the rule's
    confirmation threshold, waiting
    for an Admin), confirmed or dismissed (an Admin decided a held run), depth_limited (a chain of
    rules too deep), failed. `subject_ids` are the Issues (or, for a project trigger, the projects)
    it acted on or would act on; `results` says what each action did."""

    __tablename__ = "rule_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    rule_id: Mapped[str] = mapped_column(
        ForeignKey("automation_rules.id", ondelete="CASCADE"), index=True
    )
    rule_version: Mapped[int] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(String(40))
    cause: Mapped[str] = mapped_column(String(160))
    event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24), index=True)
    subject_ids: Mapped[list[str]] = mapped_column(JsonType, default=list)
    # "<event id>:<subject id>" for each thing it handled ("-:<subject>" from the sweep), so a
    # redelivered batch is recognised and never acted on twice.
    event_keys: Mapped[list[str]] = mapped_column(JsonType, default=list)
    results: Mapped[list[dict[str, Any]]] = mapped_column(JsonType, default=list)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    decided_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

    __table_args__ = (Index("ix_rule_runs_cause", "rule_id", "cause"),)


class IssueGroup(Base):
    """Issues one ticket tracks together (plan §41.2, §49: "issue groups map to one ticket"), within
    one project."""

    __tablename__ = "issue_groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (UniqueConstraint("asset_id", "name", name="uq_issue_groups_asset_name"),)


class TicketConfig(Base):
    """Where a project's tickets go (plan §49): Jira (`target` is the project key) or GitHub Issues
    (`target` is owner/repo), with the organization's stored credentials. `status_source` says which
    side owns the status -- "ticket" (the default: the ticket's status maps onto Bulwark through
    `status_map`, and Bulwark only comments) or "platform" (Bulwark closes and reopens the ticket,
    and ignores what the ticket says). Severity, title and description always come from Bulwark."""

    __tablename__ = "ticket_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), unique=True)
    provider: Mapped[str] = mapped_column(String(16))  # jira | github
    target: Mapped[str] = mapped_column(String(200))
    issue_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_source: Mapped[str] = mapped_column(String(16), default="ticket")
    status_map: Mapped[dict[str, str]] = mapped_column(JsonType, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)


class Notification(Base):
    """One thing worth telling one person (plan §49), or the team channels (`recipient` "team").
    `in_app` is whether it shows in the inbox; `email_state` is null (no email), "pending" (in the
    next digest), "sent", or "skipped" (no address or no mail server)."""

    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    recipient: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(64))
    event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    title: Mapped[str] = mapped_column(Text)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    link: Mapped[str | None] = mapped_column(Text, nullable=True)
    issue_id: Mapped[str | None] = mapped_column(
        ForeignKey("issues.id", ondelete="CASCADE"), nullable=True
    )
    actor: Mapped[str | None] = mapped_column(String(200), nullable=True)
    in_app: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)
    read_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    email_state: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    emailed_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)

    __table_args__ = (
        UniqueConstraint("recipient", "event_id", "kind", name="uq_notifications_event"),
        Index("ix_notifications_recipient", "org_id", "recipient"),
    )


class IssueWatcher(Base):
    """Who follows an Issue (plan §49): its assignee, people who wrote notes on it or were
    mentioned in one, whoever asked for its retest, and anyone who chose to."""

    __tablename__ = "issue_watchers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    issue_id: Mapped[str] = mapped_column(ForeignKey("issues.id", ondelete="CASCADE"), index=True)
    actor: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(String(24))
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (UniqueConstraint("issue_id", "actor", name="uq_issue_watchers"),)


class NotificationPrefs(Base):
    """One person's notification settings (or, with `owner` "team", the organization's team
    channels'): for each kind of event, each channel's mode -- off, instant or digest."""

    __tablename__ = "notification_prefs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(ForeignKey("organizations.id"), index=True)
    owner: Mapped[str] = mapped_column(String(200))
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    digest_hour: Mapped[int] = mapped_column(Integer, default=8)
    prefs: Mapped[dict[str, dict[str, str]]] = mapped_column(JsonType, default=dict)
    last_digest_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=_now)

    __table_args__ = (UniqueConstraint("org_id", "owner", name="uq_notification_prefs_owner"),)
