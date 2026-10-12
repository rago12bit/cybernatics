"""FastAPI service: scan lifecycle + findings + live progress (design doc §3, API gateway)."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    WebSocket,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.websockets import WebSocketDisconnect
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from api.acceptance import register_acceptance_routes
from api.advisories import register_advisory_routes
from api.calendar import register_calendar_routes
from api.collab import register_collab_routes
from api.compliance import register_compliance_routes
from api.components import register_component_routes
from api.connectors import register_connector_routes
from api.dashboards import register_dashboard_routes
from api.dedup import register_dedup_routes
from api.deps import (
    AppState,
    AuthContext,
    EventSubscriber,
    current_org,
    db,
    require_auth,
    require_scope,
    state,
    token_ok,
)
from api.engagements import register_engagement_routes
from api.identity import register_identity_routes
from api.ingest import register_ingest_routes
from api.issues import register_issue_routes
from api.manual import register_manual_routes
from api.mappings import register_mapping_routes
from api.metrics import register_metric_routes
from api.notify import register_notify_routes
from api.priority import register_priority_routes
from api.reports import register_report_routes
from api.retest import register_retest_routes
from api.rules import register_rules_routes
from api.schemas import (
    AssetSummary,
    AssetVerificationView,
    AttackPathEdgeView,
    AttackPathNodeView,
    AttackPathView,
    BulkTriageRequest,
    BulkTriageResult,
    CitationView,
    ComparedIssue,
    ConversationView,
    CostSummaryRow,
    CostSummaryView,
    DependenciesView,
    FeedsStatus,
    FindingsPage,
    GenerateHypothesesResult,
    GuidanceView,
    HypothesisView,
    IntegrationSettingsView,
    IssueHistoryEvent,
    IssueView,
    MessageView,
    PluginView,
    PostMessageRequest,
    ProjectOverview,
    PromoteHypothesisResult,
    RegisterWebAssetRequest,
    RemediationView,
    RetentionSettingsView,
    SaveIntegrationSettingsRequest,
    SaveRetentionSettingsRequest,
    SaveThreatModelRequest,
    ScanComparisonSide,
    ScanComparisonView,
    ScanCostView,
    ScanCreated,
    ScannedTool,
    ScanRequest,
    ScanSummary,
    ScanView,
    SetPluginAllowedRequest,
    SetWebAssetSourceRequest,
    StartConversationRequest,
    StartDastCampaignRequest,
    StrideRowView,
    SuggestionRequest,
    ThreatModelView,
    ToolStatus,
    TrendPoint,
    TriageAssistantView,
    TriageRequest,
    VerifiedFixRequest,
    VerifiedFixStarted,
    VerifiedFixView,
)
from api.scim import register_scim_routes
from api.sla import register_sla_routes
from api.sso import register_sso_routes
from api.tickets import register_ticket_routes
from api.vex import register_vex_routes
from core.collab.tags import TagError
from core.collab.tags import issue_clause as tag_clause
from core.config import Settings
from core.dast import campaign as campaign_rules
from core.dast import ownership
from core.export import FORMATS, ReportData, render
from core.gitfetch import GitUrlError, validate_git_url
from core.github_app import parse_pull_request_event, verify_signature
from core.integrations.ssrf import WebhookUrlError, validate_webhook_url
from core.llm import budget as llm_budget
from core.llm import cache as llm_cache
from core.llm.client import LLMConfig
from core.llm.limits import LimitExceeded, UsageLimiter
from core.llm.prompt import CodeContext
from core.llm.service import static_suggestion
from core.models import finding_from_dict
from core.observability import bind_scan, configure_logging, cost, setup_tracing
from core.persistence import repo
from core.persistence.models import FindingRow, GithubInstallation, IssueRow, Scan
from core.plugins.registry import discover_plugins
from core.plugins.signing import PluginSignatureError, verify_plugin_image
from core.priority.engine import BAND_NAMES as PRIORITY_BANDS
from core.rag.retrieve import context_for
from core.rag.store import KnowledgeBase
from core.risk import is_stale, read_meta
from core.scan import ADAPTERS, DEFAULT_TOOLS, HOSTED_DEFAULT_TOOLS
from core.sla import policy as sla_policy
from core.sla import service as sla_service
from core.tenancy import DEFAULT_ORG_ID, set_session_org
from core.vex import service as vex_service

log = logging.getLogger(__name__)

# Week 62 (plan §44.2): accepting a risk needs a second person. Triage still marks "not a risk"
# and reopens; acceptance goes through a request that someone else approves.
ACCEPT_NEEDS_APPROVAL = (
    "accepting a risk needs someone else's approval: request a risk acceptance "
    "(POST /v2/projects/{project_id}/risk-acceptances)"
)
_SCAN_IN_PATH = re.compile(r"^/scans/([0-9a-f-]{36})(?:/|$)")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz")
MIN_TOKEN_LEN = 16


def _tools(requested: list[str] | None, s: Session, org: str, hosted: bool = False) -> list[str]:
    """Validates against built-ins plus every *discovered* plugin tool name (Week 51 task 1, plan
    §23) -- a plugin that isn't yet allowlisted for this org is still a recognized tool name (a
    clear "not allowlisted" error, not a confusing "unknown tool"), but is rejected here rather than
    silently queued to fail later inside the worker.

    `hosted` (Settings.hosted_mode, ADR-0038) swaps the no-tools-requested default from
    DEFAULT_TOOLS to HOSTED_DEFAULT_TOOLS (Opengrep instead of Semgrep) and refuses an *explicit*
    request for "semgrep" outright -- Semgrep's community/Pro rules are licensed for internal
    business use only (ADR-006), which a hosted deployment offering scans to other people is not."""
    names = requested or list(HOSTED_DEFAULT_TOOLS if hosted else DEFAULT_TOOLS)
    if hosted and "semgrep" in names:
        raise HTTPException(
            422,
            "semgrep is not available in hosted mode (its rules are licensed for internal use "
            "only, ADR-006); use 'opengrep' instead (ADR-0038)",
        )
    plugins = discover_plugins()
    valid = set(ADAPTERS) | set(plugins)
    unknown = [t for t in names if t not in valid]
    if unknown:
        raise HTTPException(422, f"unknown tool(s): {', '.join(unknown)}; valid: {sorted(valid)}")
    not_allowed = [t for t in names if t in plugins and not repo.is_plugin_allowed(s, org, t)]
    if not_allowed:
        raise HTTPException(
            422, f"plugin tool(s) not allowlisted for this organization: {', '.join(not_allowed)}"
        )
    return list(dict.fromkeys(names))


def _get_scan(s: Session, scan_id: str, org_id: str) -> Scan:
    """Every client-facing lookup goes through here, and here alone checks the org (ADR-0013): once
    this returns, every downstream query scoped by `scan.id` (findings, tool runs) is already safe
    without its own org filter — a scan in a different org is invisible, not just unauthorized, so
    this is a 404 and never a 403."""
    scan = repo.get_scan(s, scan_id, org_id=org_id) if _UUID.match(scan_id) else None
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


def _get_asset(s: Session, asset_id: str, org_id: str) -> Any:
    """Same 404-not-403 pattern as `_get_scan` (ADR-0013)."""
    asset = repo.get_asset(s, asset_id, org_id=org_id) if _UUID.match(asset_id) else None
    if asset is None:
        raise HTTPException(404, "project not found")
    return asset


def _get_issue(s: Session, issue_id: str, org_id: str) -> Any:
    """Same 404-not-403 pattern as `_get_scan`/`_get_asset` (ADR-0013)."""
    issue = repo.get_issue(s, issue_id, org_id=org_id) if _UUID.match(issue_id) else None
    if issue is None:
        raise HTTPException(404, "issue not found")
    return issue


def _issue_view(row: Any) -> IssueView:
    return IssueView(
        id=row.id, state=row.state, triage_status=row.triage_status,
        triage_reason=row.triage_reason, triage_expires_at=row.triage_expires_at,
        triage_justification=row.triage_justification,
    )  # fmt: skip


def _all_findings(s: Session, scan_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    while True:
        page = repo.query_findings(s, scan_id, sort="risk", limit=500, offset=len(out))
        out.extend(page.items)
        if not page.items or len(out) >= page.total:
            return out


def _find(s: Session, scan_id: str, org_id: str, finding_id: str) -> Any:
    _get_scan(s, scan_id, org_id)
    row = s.scalar(
        select(FindingRow).where(FindingRow.scan_id == scan_id, FindingRow.finding_id == finding_id)
    )
    if row is None:
        raise HTTPException(404, "finding not found in this scan")
    return finding_from_dict(row.data)


def _kb(s: Session) -> KnowledgeBase:
    try:
        return KnowledgeBase(s)
    except RuntimeError as exc:
        raise HTTPException(
            503, "the remediation knowledge base is not loaded (run `bulwark kb load`)"
        ) from exc


def _code_of(f: Any) -> CodeContext | None:
    """The code we still have: the scanner's snippet (the scan workspace is deleted afterwards)."""
    sn = f.location.snippet
    if not sn.strip() or "[snippet withheld" in sn or "[secret redacted]" in sn:
        return None
    return CodeContext(sn, f.location.start_line)


def _view(s: Session, scan: Scan) -> ScanView:
    tool_status = {
        r.tool: ToolStatus(
            status=r.status,
            findings=r.findings_count,
            exit_code=r.exit_code,
            duration_seconds=r.duration_seconds,
            error=r.error,
            raw_artifact=(
                "available" if r.raw_object_key else ("withheld" if r.raw_withheld_reason else None)
            ),
        )
        for r in scan.tool_runs
    }
    counts = repo.severity_counts(s, scan.id)
    raw = sum(r.findings_count for r in scan.tool_runs)
    unique = sum(counts.values())
    issues = repo.issue_counts(s, scan.id)
    return ScanView(
        id=scan.id,
        status=scan.status,
        source_type=scan.source_type,
        source_label=scan.source_label,
        tools=list(scan.tools),
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error=scan.error,
        tool_status=tool_status,
        severity_counts=counts,
        raw_findings=raw,
        unique_findings=unique,
        dedup_rate=round(1 - unique / raw, 3) if raw and unique <= raw else 0.0,
        issue_counts=issues,
    )


def _dispatch(st: AppState, s: Session, scan: Scan) -> None:
    """Queue the job; if the queue is unreachable, fail the scan cleanly instead of orphaning it."""
    try:
        st.enqueue(scan.id, scan.org_id)
    except Exception as exc:  # noqa: BLE001 - broker errors vary by transport
        log.exception("could not enqueue scan %s", scan.id)
        repo.finish_scan(s, scan.id, "failed", "could not queue the scan; try again shortly")
        if scan.source_type == "archive":
            Path(scan.source_ref).unlink(missing_ok=True)
        raise HTTPException(503, "scan queue unavailable; the scan was not started") from exc


_DOWNLOAD_PATH = re.compile(r"^/v2/attachments/[0-9a-f-]{36}/download$")


def _host_of(origin: str) -> str:
    """'https://files.example.com' -> 'files.example.com' (with the port, when there is one)."""
    from urllib.parse import urlsplit

    return urlsplit(origin).netloc.lower() if origin else ""


def create_app(app_state: AppState) -> FastAPI:
    if len(app_state.settings.api_token) < MIN_TOKEN_LEN:
        raise RuntimeError(
            f"BULWARK_API_TOKEN must be set (>= {MIN_TOKEN_LEN} chars); refusing to start"
        )
    app = FastAPI(
        title="Bulwark API",
        version="0.1.0",
        description="Unified security scanning: submit a scan, watch progress, read findings.",
    )
    app.state.bulwark = app_state

    # Registered before CORSMiddleware, so it runs inside it: a route that crashes still gets the
    # CORS headers. Without them the browser could not read the 500 at all, and the web app told the
    # user it "cannot reach the Bulwark API" when the API had answered.
    @app.middleware("http")
    async def unhandled_error(request: Request, call_next: Any) -> Response:
        try:
            return await call_next(request)  # type: ignore[no-any-return]
        except Exception:
            log.exception("request crashed", extra={"method": request.method})
            return JSONResponse(
                status_code=500,
                content={"detail": "Something went wrong on the server. It has been logged."},
            )

    # Explicit origin allowlist (never "*"): only the configured UI origins may call the API.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app_state.settings.cors_origins),
        # Every method a route uses: the web app saves with PUT, PATCH and DELETE too (settings,
        # threat model, SLA, connectors). With GET and POST only, a browser on another origin --
        # the default, web and API on different ports -- had every such save refused at preflight.
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Bulwark-CSRF"],
        # Week 75: the web app signs in with a session cookie, so its requests carry credentials.
        # Safe only because the origins above are an explicit list (never "*").
        allow_credentials=True,
    )

    attachments_host = _host_of(app_state.settings.attachments_origin)

    @app.middleware("http")
    async def attachments_origin(request: Request, call_next: Any) -> Response:
        """The attachments origin serves signed downloads and nothing else, and when one is set, the
        API's own host serves no downloads (plan §52, threat T24): a file that runs script, opened
        anyway, lands on a host with no cookies, no token and no API behind it."""
        if not attachments_host:
            return await call_next(request)  # type: ignore[no-any-return]
        on_files_host = (request.headers.get("host") or "").lower() == attachments_host
        is_download = request.method in ("GET", "HEAD") and bool(
            _DOWNLOAD_PATH.match(request.url.path)
        )
        if on_files_host != is_download and request.url.path != "/healthz":
            return Response(status_code=404, headers={"Cache-Control": "no-store"})
        response: Response = await call_next(request)
        if on_files_host:
            del response.headers["set-cookie"]
        return response

    def _startup() -> None:
        configure_logging()  # JSON lines with scan_id; BULWARK_LOG_FORMAT=text for humans
        setup_tracing("bulwark-api")

    app.router.add_event_handler("startup", _startup)

    @app.middleware("http")
    async def access_log(request: Request, call_next: Any) -> Response:
        """One structured line per request, tagged with the scan id when the path names one.

        Logs the route TEMPLATE (`/scans/{scan_id}`), never the raw path or query string (which can
        carry search text); the scan id is validated as a UUID before it is trusted.
        """
        if request.url.path == "/healthz":
            return await call_next(request)  # type: ignore[no-any-return]
        m = _SCAN_IN_PATH.match(request.url.path)
        scan_id = m.group(1) if m and _UUID.match(m.group(1)) else None
        start = time.monotonic()
        with bind_scan(scan_id) if scan_id else contextlib.nullcontext():
            try:
                response: Response = await call_next(request)
            except Exception:
                log.exception("request crashed", extra={"method": request.method})
                raise
            route = request.scope.get("route")
            log.info(
                "request",
                extra={"method": request.method, "route": getattr(route, "path", "unmatched"),
                       "status": response.status_code,
                       "duration_ms": round((time.monotonic() - start) * 1000, 1)},
            )  # fmt: skip
        return response

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/scans",
        status_code=202,
        response_model=ScanCreated,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def create_scan(
        body: ScanRequest,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ScanCreated:
        tools = _tools(body.tools, s, org, hosted=st.settings.hosted_mode)
        try:
            validate_git_url(body.source.url)  # fast feedback; re-validated again at clone time
        except GitUrlError as exc:
            raise HTTPException(422, str(exc)) from exc
        scan = repo.create_scan(
            s, source_type="git", source_ref=body.source.url,
            source_label=body.source.url, tools=tools, org_id=org,
        )  # fmt: skip
        _dispatch(st, s, scan)
        return ScanCreated(id=scan.id, status=scan.status)

    @app.post(
        "/scans/upload",
        status_code=202,
        response_model=ScanCreated,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    async def upload_scan(
        archive: UploadFile = File(...),
        tools: str | None = Form(
            default=None,
            description="Comma-separated; defaults to bandit, semgrep, gitleaks, "
            "trivy, osv-scanner.",
        ),
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ScanCreated:
        name = Path(archive.filename or "").name  # never trust client paths
        if not name.lower().endswith(_ARCHIVE_EXT):
            raise HTTPException(422, f"archive must end with one of {_ARCHIVE_EXT}")
        wanted = _tools(
            [t.strip() for t in tools.split(",") if t.strip()] if tools else None, s, org,
            hosted=st.settings.hosted_mode,
        )  # fmt: skip
        upload_dir = st.settings.upload_dir
        upload_dir.mkdir(parents=True, exist_ok=True)
        dest = upload_dir / f"{uuid.uuid4().hex}{Path(name).suffix}"  # server-chosen filename
        written = 0
        try:
            with open(dest, "wb") as out:
                while chunk := await archive.read(1024 * 1024):
                    written += len(chunk)
                    if written > st.settings.max_upload_bytes:
                        raise HTTPException(413, "archive exceeds the maximum upload size")
                    out.write(chunk)
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
        scan = repo.create_scan(
            s, source_type="archive", source_ref=str(dest), source_label=name, tools=wanted,
            org_id=org,
        )  # fmt: skip
        _dispatch(st, s, scan)
        return ScanCreated(id=scan.id, status=scan.status)

    @app.post("/integrations/github/webhook", include_in_schema=False)
    async def github_webhook(request: Request, st: AppState = Depends(state)) -> dict[str, str]:
        """GitHub App webhook receiver (Week 30, ADR-0017). Not `Depends(require_auth)`: a webhook
        carries no Bulwark bearer token, only GitHub's own HMAC signature -- a *different* trust
        mechanism, checked explicitly below rather than reused from the rest of the API. Also not
        `Depends(db)`: that resolves org context from the `X-Bulwark-Org` header, which a GitHub
        webhook never sends -- org context here comes from the installation instead (see
        `core.tenancy.set_session_org`'s docstring).
        """
        if not st.settings.github_webhook_secret:
            raise HTTPException(404, "the GitHub App integration is not configured on this server")
        body = await request.body()
        if not verify_signature(
            body, request.headers.get("X-Hub-Signature-256"), st.settings.github_webhook_secret
        ):
            raise HTTPException(401, "invalid webhook signature")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, "invalid JSON") from exc
        event = request.headers.get("X-GitHub-Event", "")

        if event == "ping":
            return {"status": "pong"}

        with st.sessions() as s:
            if event == "installation":
                inst = payload.get("installation") or {}
                inst_id = str(inst.get("id") or "")
                if payload.get("action") == "created" and inst_id:
                    login = str((inst.get("account") or {}).get("login") or "")
                    row = repo.get_or_create_installation(
                        s, installation_id=inst_id, account_login=login
                    )
                    repo.append_audit_entry(
                        s, actor="webhook:github", action="installation.created",
                        target=inst_id, payload={"account_login": login, "org_id": row.org_id},
                    )  # fmt: skip
                elif payload.get("action") == "deleted" and inst_id:
                    repo.delete_installation(s, inst_id)
                    repo.append_audit_entry(
                        s, actor="webhook:github", action="installation.deleted",
                        target=inst_id, payload={},
                    )  # fmt: skip
                return {"status": "ok"}

            if event == "pull_request":
                pr = parse_pull_request_event(payload)
                if pr is None:
                    return {"status": "ignored"}
                installation = repo.get_or_create_installation(
                    s, installation_id=pr.installation_id, account_login=pr.account_login
                )
                set_session_org(s, installation.org_id)  # only NOW is the session org-scoped
                try:
                    validate_git_url(pr.clone_url)
                except GitUrlError:
                    return {"status": "ignored"}  # not a repo we're configured to clone from
                scan = repo.create_scan(
                    s, source_type="git", source_ref=pr.clone_url,
                    source_label=f"{pr.repo_full_name}#{pr.pr_number}", asset_label=pr.clone_url,
                    tools=list(HOSTED_DEFAULT_TOOLS if st.settings.hosted_mode else DEFAULT_TOOLS),
                    org_id=installation.org_id, ref=pr.ref,
                    github_repo=pr.repo_full_name, github_pr_number=pr.pr_number,
                    github_installation_id=pr.installation_id, github_head_sha=pr.head_sha,
                )  # fmt: skip
                _dispatch(st, s, scan)
                return {"status": "queued", "scan_id": scan.id}

            if event == "issue_comment":
                # `/fix` (Week 76, plan §50): core.fixagent.pr_fix checks everything else.
                from core.fixagent import pr_fix
                from core.github_app import installation_token

                cmt = pr_fix.parse_comment_event(payload)
                if cmt is None:
                    return {"status": "ignored"}
                known = s.get(GithubInstallation, cmt.installation_id)
                if known is None or not (
                    st.settings.github_app_id and st.settings.github_app_private_key
                ):
                    return {"status": "ignored"}  # never creates an organization, unlike a PR
                settings = st.settings
                gh = pr_fix.GitHub(
                    lambda: installation_token(
                        cmt.installation_id, settings.github_app_id,
                        settings.github_app_private_key,
                    )
                )  # fmt: skip
                outcome = await pr_fix.handle_comment(
                    s, cmt, known.org_id, gh, usd_per_1k=st.settings.llm_cost_per_1k_tokens_usd
                )
                return {"status": outcome}

        return {"status": "ignored"}

    @app.get(
        "/scans",
        response_model=list[ScanSummary],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_scans(
        limit: int = Query(default=20, ge=1, le=50),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[ScanSummary]:
        out: list[ScanSummary] = []
        for scan in repo.list_scans(s, limit, org_id=org):
            counts = repo.severity_counts(s, scan.id)
            out.append(
                ScanSummary(
                    id=scan.id, status=scan.status, source_type=scan.source_type,
                    source_label=scan.source_label, created_at=scan.created_at,
                    finished_at=scan.finished_at, unique_findings=sum(counts.values()),
                    severity_counts=counts,
                )
            )  # fmt: skip
        return out

    @app.get(
        "/assets",
        response_model=list[AssetSummary],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_assets(
        limit: int = Query(default=50, ge=1, le=100),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[AssetSummary]:
        """Projects (plan §27): one row per distinct repository, most recently scanned first."""
        out: list[AssetSummary] = []
        for asset in repo.list_assets(s, org_id=org, limit=limit):
            latest = repo.latest_scan_for_asset(s, asset.id, org_id=org)
            open_count = 0
            if latest is not None:
                open_count = sum(repo.issue_counts(s, latest.id).values())
            out.append(
                AssetSummary(
                    id=asset.id, label=asset.label, source_type=asset.source_type,
                    last_scanned_at=asset.last_scanned_at,
                    latest_scan_id=latest.id if latest else None,
                    latest_scan_status=latest.status if latest else None,
                    open_issue_count=open_count,
                )
            )  # fmt: skip
        return out

    @app.get(
        "/assets/{asset_id}/overview",
        response_model=ProjectOverview,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_asset_overview(
        asset_id: str,
        fix_first_limit: int = Query(default=10, ge=1, le=25),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ProjectOverview:
        """Plan §28.1's project overview: verdict, fix-first queue, since-previous-scan deltas,
        the open-issue trend, and what the latest scan did (and didn't) cover. See
        core/persistence/repo.py's asset-overview functions and docs/v2-week33-verification.md for
        exactly how each field is derived from existing scan/issue data."""
        asset = _get_asset(s, asset_id, org)
        latest = repo.latest_scan_for_asset(s, asset.id, org_id=org)

        summary = AssetSummary(
            id=asset.id, label=asset.label, source_type=asset.source_type,
            last_scanned_at=asset.last_scanned_at,
            latest_scan_id=latest.id if latest else None,
            latest_scan_status=latest.status if latest else None,
            open_issue_count=sum(repo.issue_counts(s, latest.id).values()) if latest else 0,
        )  # fmt: skip

        if latest is None:
            return ProjectOverview(
                asset=summary, verdict_count=0, fix_first=[], more_at_lower_risk=0,
                since_previous_scan={"fixed": 0, "new": 0, "returned": 0}, trend=[], scanned=[],
                latest_scan_id=None, latest_scan_finished_at=None,
            )  # fmt: skip

        # An Issue a retest confirmed fixed since this scan (Week 64) leaves the queue, as it leaves
        # the issues table: the scan's own rows still list it until the next scan.
        retested_fixed = set(
            s.scalars(
                select(FindingRow.issue_id)
                .join(IssueRow, IssueRow.id == FindingRow.issue_id)
                .where(FindingRow.scan_id == latest.id, IssueRow.state == "fixed")
            )
        )
        page = repo.query_findings(
            s, latest.id, sort="risk", limit=fix_first_limit + len(retested_fixed)
        )
        # Calm by default (§29.2): a critical/high finding only counts toward the "at real risk"
        # verdict while it's reachable (or reachability is unknown) -- a finding whose own scoring
        # says it isn't reachable doesn't inflate the headline, even though it still appears further
        # down the fix-first list with its "not reachable" tag.
        fix_first = [
            f for f in page.items if not (f.get("issue") and f["issue"]["id"] in retested_fixed)
        ][:fix_first_limit]
        verdict_count = sum(
            1
            for f in fix_first
            if f.get("scoring", {}).get("normalized_severity") in ("CRITICAL", "HIGH")
            and f.get("scoring", {}).get("reachable") is not False
        )
        total_open = sum(repo.issue_counts(s, latest.id).values())

        previous = repo.previous_scan_for_asset(s, asset.id, latest, org_id=org)
        since = repo.since_previous_scan_counts(s, asset.id, latest.id, previous)
        trend = [
            TrendPoint(
                scan_id=p["scan_id"], finished_at=p["finished_at"], open_count=p["open_count"]
            )
            for p in repo.open_issue_trend(s, asset.id, org_id=org)
        ]
        scanned = [
            ScannedTool(tool=tr.tool, status=tr.status, findings=tr.findings_count)
            for tr in latest.tool_runs
        ]

        return ProjectOverview(
            asset=summary,
            verdict_count=verdict_count,
            fix_first=fix_first,
            more_at_lower_risk=max(total_open - len(retested_fixed) - len(fix_first), 0),
            since_previous_scan=since,
            trend=trend,
            scanned=scanned,
            latest_scan_id=latest.id,
            latest_scan_finished_at=latest.finished_at,
        )

    def _verification_view(
        asset: Any, verification: Any, s: Session | None = None, org: str | None = None
    ) -> AssetVerificationView:
        source = (
            repo.get_asset(s, asset.linked_source_asset_id, org_id=org)
            if s is not None and asset.linked_source_asset_id
            else None
        )
        record_name = record_value = well_known_url = file_content = None
        if verification.method == "dns_txt":
            record_name = ownership.dns_record_name(asset.key)
            record_value = ownership.dns_expected_value(verification.token)
        else:
            well_known_url = ownership.well_known_url(asset.key)
            file_content = verification.token
        return AssetVerificationView(
            asset_id=asset.id,
            domain=asset.key,
            method=verification.method,
            status=verification.status,
            record_name=record_name,
            record_value=record_value,
            well_known_url=well_known_url,
            file_content=file_content,
            created_at=verification.created_at,
            verified_at=verification.verified_at,
            last_checked_at=verification.last_checked_at,
            last_error=verification.last_error,
            source_asset_id=asset.linked_source_asset_id,
            source_label=source.label if source is not None else None,
        )

    @app.post(
        "/assets/web",
        response_model=AssetVerificationView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def register_web_asset(
        body: RegisterWebAssetRequest, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> AssetVerificationView:
        """Register a web/DAST target (plan §22.4). Returns the proof-of-control instructions for
        the chosen method; no campaign (Week 49 task 3) can run against this asset until `POST
        /assets/{id}/verify` passes against a live DNS/HTTP check, not merely this call."""
        domain = body.domain.strip().lower()
        try:
            asset, verification = repo.register_web_asset(
                s, domain=domain, method=body.method, org_id=org,
                source_asset_id=body.source_asset_id,
            )  # fmt: skip
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return _verification_view(asset, verification, s, org)

    @app.put(
        "/assets/{asset_id}/source",
        response_model=AssetVerificationView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def set_web_asset_source(
        asset_id: str,
        body: SetWebAssetSourceRequest,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> AssetVerificationView:
        """Link a registered web target to its code project, change the link, or remove it (plan
        §22.4): a later DAST finding on a route is then checked against that route's code. Unlike
        registering again, this keeps the target's ownership verification."""
        asset = _get_asset(s, asset_id, org)
        try:
            repo.set_web_asset_source(s, asset, body.source_asset_id, org_id=org, actor=auth.actor)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        verification = repo.get_asset_verification(s, asset.id, org_id=org)
        if verification is None:
            raise HTTPException(404, "this asset has no ownership verification on record")
        return _verification_view(asset, verification, s, org)

    @app.get(
        "/assets/{asset_id}/verification",
        response_model=AssetVerificationView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_asset_verification(
        asset_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> AssetVerificationView:
        asset = _get_asset(s, asset_id, org)
        verification = repo.get_asset_verification(s, asset.id, org_id=org)
        if verification is None:
            raise HTTPException(404, "this asset has no ownership verification on record")
        return _verification_view(asset, verification, s, org)

    @app.post(
        "/assets/{asset_id}/verify",
        response_model=AssetVerificationView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def verify_asset_endpoint(
        asset_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> AssetVerificationView:
        """Runs a real, live DNS/HTTP check right now and persists the result -- never trusts a
        previously-stored "verified" status, since ownership can lapse any time after it passed."""
        asset = _get_asset(s, asset_id, org)
        verification = repo.get_asset_verification(s, asset.id, org_id=org)
        if verification is None:
            raise HTTPException(404, "this asset has no ownership verification on record")
        outcome = ownership.verify(
            verification.method,
            asset.key,
            verification.token,
            resolver=ownership.DnsPythonResolver(),
            fetcher=ownership.HttpxFetcher(),
        )
        verification = repo.record_verification_check(
            s, verification, ok=outcome.ok, error=outcome.error
        )
        return _verification_view(asset, verification, s, org)

    @app.post(
        "/assets/{asset_id}/campaigns",
        response_model=ScanCreated,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def start_dast_campaign(
        asset_id: str,
        body: StartDastCampaignRequest,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ScanCreated:
        """Start a DAST campaign (plan §22.4): gated on a LIVE ownership check right now (never a
        cached "verified" status) and, for an active campaign, the rate limit -- both checked before
        a Scan row is even created, so an unverified or rate-limited attempt never shows up as a
        queued campaign waiting to run and fail."""
        asset = _get_asset(s, asset_id, org)
        verification = repo.get_asset_verification(s, asset.id, org_id=org)
        if verification is None:
            raise HTTPException(422, "this asset has no ownership verification on record")
        outcome = ownership.verify(
            verification.method,
            asset.key,
            verification.token,
            resolver=ownership.DnsPythonResolver(),
            fetcher=ownership.HttpxFetcher(),
        )
        repo.record_verification_check(s, verification, ok=outcome.ok, error=outcome.error)
        if not outcome.ok:
            raise HTTPException(422, f"ownership verification failed: {outcome.error}")
        if body.mode == "active":
            last_active = repo.last_active_campaign_started_at(s, asset.id, org_id=org)
            limit = campaign_rules.check_active_scan_rate_limit(last_active)
            if not limit.allowed:
                hours = (limit.retry_after.total_seconds() / 3600) if limit.retry_after else 0
                raise HTTPException(429, f"active scan rate limit: try again in {hours:.1f}h")
        scan = repo.create_dast_campaign(s, asset=asset, mode=body.mode, org_id=org)
        repo.append_audit_entry(
            s, actor=f"api:{org}", action="dast.campaign.started", target=scan.id,
            payload={"asset_id": asset.id, "mode": body.mode},
        )  # fmt: skip
        st.enqueue_dast_campaign(scan.id, org)
        return ScanCreated(id=scan.id, status=scan.status)

    @app.get(
        "/assets/{asset_id}/campaigns",
        response_model=list[ScanSummary],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_dast_campaigns(
        asset_id: str,
        limit: int = Query(default=20, ge=1, le=50),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[ScanSummary]:
        asset = _get_asset(s, asset_id, org)
        out: list[ScanSummary] = []
        for scan in repo.list_dast_campaigns(s, asset.id, org_id=org, limit=limit):
            counts = repo.severity_counts(s, scan.id)
            out.append(
                ScanSummary(
                    id=scan.id, status=scan.status, source_type=scan.source_type,
                    source_label=scan.source_label, created_at=scan.created_at,
                    finished_at=scan.finished_at, unique_findings=sum(counts.values()),
                    severity_counts=counts,
                )
            )  # fmt: skip
        return out

    @app.get(
        "/assets/{asset_id}/issues",
        response_model=FindingsPage,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_issues(
        asset_id: str,
        severity: list[str] | None = Query(default=None),
        category: list[str] | None = Query(default=None),
        triage: list[str] | None = Query(
            default=None,
            description="Filter TO these triage statuses (e.g. accepted, not_a_risk). Omitted: "
            "the active queue -- untouched issues, plus any accepted issue past its expiry.",
        ),
        sla: list[str] | None = Query(
            default=None,
            description="Filter to these SLA states: on_track, due_soon, breached (plan §44.1). "
            "Nothing matches when the project has no SLA policy.",
        ),
        priority: list[str] | None = Query(
            default=None,
            description="Filter to these priority bands: P1, P2, P3, P4 (plan §44.3).",
        ),
        tag: list[str] | None = Query(
            default=None,
            description="Filter to Issues with any of these tags, set on the Issue, its project or "
            "its portfolio (plan §49).",
        ),
        sort: str = Query(default="risk", pattern="^(severity|path|risk)$"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> FindingsPage:
        """Plan §28.3's issues table: the asset's currently-open issues (its latest scan's
        findings and each Test's latest applied import -- `repo.open_snapshot_scan_ids` --
        joined with each one's triage state). Empty, not 404, when nothing has scanned or been
        imported yet -- mirrors `/scans/{id}/findings`'s own shape so the same frontend table
        component can render either."""
        asset = _get_asset(s, asset_id, org)
        snapshots = repo.open_snapshot_scan_ids(s, org, asset.id)
        if not snapshots:
            return FindingsPage(total=0, limit=limit, offset=offset, items=[])
        bad = sorted(set(sla or []) - set(sla_policy.OPEN_SLA))
        if bad:
            raise HTTPException(422, f"unknown SLA state: {', '.join(bad)}")
        bad = sorted({p.upper() for p in priority or []} - set(PRIORITY_BANDS))
        if bad:
            raise HTTPException(422, f"unknown priority band: {', '.join(bad)}")
        now = datetime.now(timezone.utc)
        issue_filter = (
            sla_service.clause(sla_service.policy_for(s, asset.id), sla, now) if sla else None
        )
        if priority:
            by_band = func.coalesce(IssueRow.priority_override, IssueRow.priority_band).in_(
                [p.upper() for p in priority]
            )
            issue_filter = by_band if issue_filter is None else and_(issue_filter, by_band)
        if tag:
            try:
                by_tag = tag_clause(tag)
            except TagError as exc:
                raise HTTPException(422, str(exc)) from exc
            issue_filter = by_tag if issue_filter is None else and_(issue_filter, by_tag)
        page = repo.list_asset_issues(
            s, asset.id, snapshots, severities=severity, categories=category, triage=triage,
            issue_filter=issue_filter, sort=sort, limit=limit, offset=offset,
        )  # fmt: skip
        sla_service.annotate(s, asset.id, page.items, now)
        return FindingsPage(total=page.total, limit=limit, offset=offset, items=page.items)

    @app.get(
        "/assets/{asset_id}/dependencies",
        response_model=DependenciesView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_dependencies(
        asset_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> DependenciesView:
        """Plan §20.5's Dependencies screen: the asset's latest scan's SBOM (`syft` in its
        `tools`), if any. Empty, not 404, when no scan has opted into it yet -- same shape as
        `/assets/{id}/issues`."""
        asset = _get_asset(s, asset_id, org)
        latest = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if latest is None or not latest.sbom_summary:
            return DependenciesView(scan_id=latest.id if latest else None)
        summary = latest.sbom_summary
        return DependenciesView(
            scan_id=latest.id,
            generated_at=latest.finished_at,
            components=summary.get("components", 0),
            ecosystems=summary.get("ecosystems", {}),
            packages=summary.get("packages", []),
        )

    @app.get(
        "/assets/{asset_id}/issues/{issue_id}",
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_one_issue(
        asset_id: str, issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        """The one issue's own detail screen (plan §28.3): the same Finding shape as a row in the
        issues table, fetched on its own rather than paging through the whole list."""
        asset = _get_asset(s, asset_id, org)
        _get_issue(s, issue_id, org)
        latest = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        finding = repo.get_issue_finding(s, issue_id, latest.id) if latest else None
        if finding is None:
            # Not in the latest scan: an issue only an import or a person reported (or one a scan
            # no longer sees) is shown as it was last reported, rather than as "not found".
            elsewhere = repo.latest_occurrence_scan_id(s, issue_id)
            finding = repo.get_issue_finding(s, issue_id, elsewhere) if elsewhere else None
        if finding is None:
            raise HTTPException(404, "issue not found")
        sla_service.annotate(s, asset.id, [finding])
        return finding

    @app.post(
        "/assets/{asset_id}/issues/{issue_id}/triage",
        response_model=IssueView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def triage_one_issue(
        asset_id: str,
        issue_id: str,
        body: TriageRequest,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> IssueView:
        """Mark not-a-risk (needs a reason) or accept risk (needs an expiry), or reopen either
        decision -- plan §28.3: "Both write to the audit log." `asset_id` in the path is a
        readability/routing convenience (matches the frontend's URLs); the org check that actually
        matters is `_get_asset` below, before the issue lookup even runs."""
        _get_asset(s, asset_id, org)
        if body.action == "accepted":
            raise HTTPException(409, ACCEPT_NEEDS_APPROVAL)
        try:
            row = repo.triage_issue(
                s, issue_id, org_id=org, action=body.action, reason=body.reason,
                expires_at=body.expires_at, actor=auth.actor, justification=body.justification,
            )  # fmt: skip
        except LookupError as exc:
            raise HTTPException(404, "issue not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if body.action == "reopen":
            vex_service.on_issue_reopened(s, org, row, actor=auth.actor)
        return _issue_view(row)

    @app.post(
        "/assets/{asset_id}/issues/bulk-triage",
        response_model=BulkTriageResult,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def bulk_triage_issues(
        asset_id: str,
        body: BulkTriageRequest,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> BulkTriageResult:
        """Same rule per issue as the single-issue endpoint, applied to a batch: one issue failing
        (not found in this org, or a bad request for that action) doesn't abort the rest -- each
        success still gets its own audit entry, exactly as if triaged one at a time."""
        _get_asset(s, asset_id, org)
        if body.action == "accepted":
            raise HTTPException(409, ACCEPT_NEEDS_APPROVAL)
        updated: list[str] = []
        failed: list[dict[str, str]] = []
        for issue_id in body.issue_ids:
            try:
                row = repo.triage_issue(
                    s, issue_id, org_id=org, action=body.action, reason=body.reason,
                    expires_at=body.expires_at, actor=auth.actor,
                    justification=body.justification,
                )  # fmt: skip
                if body.action == "reopen":
                    vex_service.on_issue_reopened(s, org, row, actor=auth.actor)
                updated.append(issue_id)
            except LookupError:
                failed.append({"issue_id": issue_id, "error": "not found"})
            except ValueError as exc:
                failed.append({"issue_id": issue_id, "error": str(exc)})
        return BulkTriageResult(updated=updated, failed=failed)

    @app.get(
        "/assets/{asset_id}/issues/{issue_id}/history",
        response_model=list[IssueHistoryEvent],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_issue_history(
        asset_id: str, issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[IssueHistoryEvent]:
        _get_asset(s, asset_id, org)
        _get_issue(s, issue_id, org)
        return [
            IssueHistoryEvent(at=e["at"], label=e["label"]) for e in repo.issue_history(s, issue_id)
        ]

    @app.get(
        "/scans/{scan_id}/guidance",
        response_model=GuidanceView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_guidance(
        scan_id: str,
        finding_id: str = Query(min_length=1, max_length=500),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> GuidanceView:
        """Reference guidance (CWE + OWASP) and any cached AI suggestion. Calls no model."""
        f = _find(s, scan_id, org, finding_id)
        kb = _kb(s)
        static = static_suggestion(f, context_for(f, kb), "reference guidance")
        client = app_state.llm
        ai = llm_cache.lookup(s, f, client.model) if client else None
        return GuidanceView(
            finding_id=finding_id,
            static=RemediationView(**asdict(static)),
            ai=RemediationView(**asdict(ai)) if ai else None,
            ai_enabled=client is not None,
            model=client.model if client else None,
        )

    @app.post(
        "/scans/{scan_id}/suggestion",
        response_model=RemediationView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def create_suggestion(
        scan_id: str,
        body: SuggestionRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> RemediationView:
        """Generate (or fetch cached) an AI suggestion. Sends data to the model provider."""
        client = app_state.llm
        if client is None:
            raise HTTPException(409, "AI suggestions are not enabled on this server")
        scan = _get_scan(s, scan_id, org)
        f = _find(s, scan_id, org, body.finding_id)
        kb = _kb(s)

        def before_call() -> None:
            app_state.limiter.acquire()
            llm_budget.check(s, scan, app_state.llm_budget)

        try:
            res = llm_cache.suggest_cached(f, kb, client, s, _code_of(f), before_call=before_call)
        except LimitExceeded as exc:
            raise HTTPException(
                429, str(exc), headers={"Retry-After": str(exc.retry_after)}
            ) from exc
        except llm_budget.BudgetExceeded as exc:
            raise HTTPException(429, str(exc)) from exc
        if res.source == "ai" and not res.from_cache:
            llm_budget.record(s, scan, res.tokens_used)
        return RemediationView(**asdict(res))

    @app.post(
        "/assets/{asset_id}/issues/{issue_id}/verified-fix",
        response_model=VerifiedFixStarted,
        dependencies=[Depends(require_scope("fixes:write"))],
    )
    async def start_verified_fix(
        asset_id: str,
        issue_id: str,
        body: VerifiedFixRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> VerifiedFixStarted:
        """Start the verified-fix agent for one issue (plan §21.2): propose a patch, verify it
        (rerun the rule, rerun scanners, optionally the project's own tests), then wait for a human
        to approve or reject before a pull request is ever opened. Runs as a Temporal workflow --
        `409` if Temporal is unreachable, `429` over this organization's concurrency cap
        (ADR-0015)."""
        from core.fixagent.start import FixStartError
        from core.fixagent.start import start as start_fix

        asset = _get_asset(s, asset_id, org)
        _get_issue(s, issue_id, org)
        try:
            started = await start_fix(
                s, org, asset, issue_id, run_tests=body.run_tests, test_image=body.test_image,
                test_command=body.test_command,
            )  # fmt: skip
        except FixStartError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        return VerifiedFixStarted(run_id=started.run_id, workflow_id=started.workflow_id)

    @app.get(
        "/assets/{asset_id}/issues/{issue_id}/verified-fix",
        response_model=VerifiedFixView,
        dependencies=[Depends(require_scope("fixes:read"))],
    )
    def get_verified_fix(
        asset_id: str, issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> VerifiedFixView:
        from core.fixagent import store as fixagent_store

        _get_asset(s, asset_id, org)
        _get_issue(s, issue_id, org)
        run = fixagent_store.latest_run_for_issue(s, issue_id, org_id=org)
        if run is None:
            raise HTTPException(404, "no verified-fix run for this issue")
        return VerifiedFixView(
            run_id=run.id, issue_id=issue_id, status=run.status, attempts=run.attempts,
            latest_patch=run.latest_patch, verification_record=run.verification_record,
            ended_reason=run.ended_reason, pr_url=run.pr_url, created_at=run.created_at,
            updated_at=run.updated_at,
        )  # fmt: skip

    @app.post(
        "/assets/{asset_id}/issues/{issue_id}/verified-fix/approve",
        dependencies=[Depends(require_scope("fixes:write"))],
    )
    async def approve_verified_fix(
        asset_id: str, issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, str]:
        """A human approving the proposed patch (plan §21.2: never auto-merge). Only meaningful
        while the run is `awaiting_approval`; signalling any other state is harmless (Temporal
        just records a signal an already-finished workflow never reads)."""
        from core.fixagent import client as fixagent_client
        from core.fixagent import store as fixagent_store

        _get_asset(s, asset_id, org)
        _get_issue(s, issue_id, org)
        run = fixagent_store.latest_run_for_issue(s, issue_id, org_id=org)
        if run is None or run.status != "awaiting_approval":
            raise HTTPException(409, "no verified-fix run is awaiting approval for this issue")
        await fixagent_client.approve(run.workflow_id)
        return {"status": "approved"}

    @app.post(
        "/assets/{asset_id}/issues/{issue_id}/verified-fix/reject",
        dependencies=[Depends(require_scope("fixes:write"))],
    )
    async def reject_verified_fix(
        asset_id: str, issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, str]:
        from core.fixagent import client as fixagent_client
        from core.fixagent import store as fixagent_store

        _get_asset(s, asset_id, org)
        _get_issue(s, issue_id, org)
        run = fixagent_store.latest_run_for_issue(s, issue_id, org_id=org)
        if run is None or run.status != "awaiting_approval":
            raise HTTPException(409, "no verified-fix run is awaiting approval for this issue")
        await fixagent_client.reject(run.workflow_id)
        return {"status": "rejected"}

    def _triage_view(row: Any) -> TriageAssistantView:
        return TriageAssistantView(
            verdict=row.assistant_verdict,
            confidence=row.assistant_verdict_confidence,
            rationale=row.assistant_verdict_rationale,
            supporting_lines=list(row.assistant_verdict_lines or []),
            model=row.assistant_verdict_model,
            generated_at=row.assistant_verdict_at,
        )

    @app.post(
        "/assets/{asset_id}/issues/{issue_id}/triage-assistant",
        response_model=TriageAssistantView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def create_triage_assessment(
        asset_id: str, issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> TriageAssistantView:
        """Ask the triage assistant for a verdict on one issue (plan §21.3): reads the taint path
        and surrounding code from its latest occurrence and returns an advisory verdict. Stored so
        `core.risk.score` can use it as one ranking input on this asset's later scans -- never
        changes `triage_status` or anything else about the issue; a person still decides that."""
        client = app_state.llm_triage
        if client is None:
            raise HTTPException(409, "the triage assistant is not enabled on this server")
        asset = _get_asset(s, asset_id, org)
        _get_issue(s, issue_id, org)
        scan = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if scan is None:
            raise HTTPException(409, "no completed scan for this asset")
        finding_doc = repo.get_issue_finding(s, issue_id, scan.id)
        if finding_doc is None:
            raise HTTPException(409, "this issue has no occurrence in the latest scan")
        finding = finding_from_dict(
            {k: v for k, v in finding_doc.items() if k not in ("scan_id", "issue")}
        )
        try:
            app_state.limiter.acquire()
            llm_budget.check(s, scan, app_state.llm_budget)
        except LimitExceeded as exc:
            raise HTTPException(
                429, str(exc), headers={"Retry-After": str(exc.retry_after)}
            ) from exc
        except llm_budget.BudgetExceeded as exc:
            raise HTTPException(429, str(exc)) from exc

        from core.triage_assistant import service as triage_service

        assessment = triage_service.assess(finding, client, _code_of(finding))
        if assessment is None:
            raise HTTPException(
                503, "the triage assistant could not produce a usable verdict for this finding"
            )
        llm_budget.record(s, scan, assessment.tokens_used)
        row = repo.set_assistant_verdict(
            s,
            issue_id,
            verdict=assessment.verdict.verdict,
            confidence=assessment.verdict.confidence,
            rationale=assessment.verdict.rationale,
            lines=list(assessment.verdict.supporting_lines),
            model=assessment.model,
        )
        return _triage_view(row)

    @app.get(
        "/assets/{asset_id}/issues/{issue_id}/triage-assistant",
        response_model=TriageAssistantView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_triage_assessment(
        asset_id: str, issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> TriageAssistantView:
        _get_asset(s, asset_id, org)
        issue = _get_issue(s, issue_id, org)
        if issue.assistant_verdict is None:
            raise HTTPException(404, "no triage-assistant verdict for this issue yet")
        return _triage_view(issue)

    def _hypothesis_view(row: Any) -> HypothesisView:
        return HypothesisView(
            id=row.id, route_method=row.route_method, route_path=row.route_path, file=row.file,
            line=row.line, evidence=row.evidence, suggested_check=row.suggested_check,
            confidence=row.confidence, model=row.model, status=row.status,
            promoted_issue_id=row.promoted_issue_id, created_at=row.created_at,
        )  # fmt: skip

    @app.post(
        "/assets/{asset_id}/hypotheses/generate",
        response_model=GenerateHypothesesResult,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def generate_hypotheses(
        asset_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> GenerateHypothesesResult:
        """Generate Hypotheses-lane candidates for one asset (plan §21.4): re-checks out its latest
        scan's source, finds every route with no recognized auth marker in a file where a sibling
        route has one (`core.hypotheses.facts`, deterministic, no model), and asks the model to
        decide which of those are worth a person's time. Off by default: `409` when no model is
        routed for `Task.HYPOTHESES` (the same on/off switch the gateway gives every task)."""
        client = app_state.llm_hypotheses
        if client is None:
            raise HTTPException(409, "the Hypotheses lane is not enabled on this server")
        asset = _get_asset(s, asset_id, org)
        scan = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if scan is None:
            raise HTTPException(409, "no completed scan for this asset")
        if scan.source_type != "git":
            raise HTTPException(
                409, "the Hypotheses lane needs a git source to re-check out the code from"
            )

        import shutil
        import tempfile
        from pathlib import Path

        from core.gitfetch import GitUrlError
        from core.gitfetch import clone_repo as git_clone_repo
        from core.hypotheses.service import generate_for_checkout

        app_state.limiter.acquire()
        checkout = Path(tempfile.mkdtemp(prefix="bulwark-hypotheses-"))
        try:
            try:
                git_clone_repo(scan.source_ref, checkout, ref=scan.ref)
            except GitUrlError as exc:
                raise HTTPException(422, f"could not check out the repository: {exc}") from exc
            surfaced = generate_for_checkout(checkout, client)
        finally:
            shutil.rmtree(checkout, ignore_errors=True)

        tokens = sum(assessment.tokens_used for _, assessment in surfaced)
        if tokens:
            llm_budget.record(s, scan, tokens)
        rows = [
            repo.create_hypothesis(
                s, asset.id, method=candidate.route.method or "", path=candidate.route.path,
                file=candidate.file, line=candidate.line, evidence=assessment.result.evidence,
                suggested_check=assessment.result.suggested_check,
                confidence=assessment.result.confidence, snippet=assessment.snippet,
                model=assessment.model,
            )  # fmt: skip
            for candidate, assessment in surfaced
        ]
        return GenerateHypothesesResult(
            generated=len(rows), hypotheses=[_hypothesis_view(r) for r in rows]
        )

    @app.get(
        "/assets/{asset_id}/hypotheses",
        response_model=list[HypothesisView],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_hypotheses_endpoint(
        asset_id: str,
        status: str | None = Query(default=None, description="Filter to open|promoted|dismissed."),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[HypothesisView]:
        _get_asset(s, asset_id, org)
        return [_hypothesis_view(r) for r in repo.list_hypotheses(s, asset_id, status=status)]

    @app.post(
        "/assets/{asset_id}/hypotheses/{hypothesis_id}/promote",
        response_model=PromoteHypothesisResult,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def promote_hypothesis_endpoint(
        asset_id: str,
        hypothesis_id: str,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> PromoteHypothesisResult:
        """A human confirming a hypothesis (plan §21.4): creates a real Issue, `source=
        "llm-confirmed"`. Never automatic -- this is the one and only way that value is ever set."""
        _get_asset(s, asset_id, org)
        hyp = repo.get_hypothesis(s, hypothesis_id, org_id=org)
        if hyp is None or hyp.asset_id != asset_id:
            raise HTTPException(404, "hypothesis not found")
        try:
            issue = repo.promote_hypothesis(s, hypothesis_id, actor=auth.actor)
        except (LookupError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        return PromoteHypothesisResult(issue_id=issue.id)

    @app.post(
        "/assets/{asset_id}/hypotheses/{hypothesis_id}/dismiss",
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def dismiss_hypothesis_endpoint(
        asset_id: str,
        hypothesis_id: str,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> dict[str, str]:
        _get_asset(s, asset_id, org)
        hyp = repo.get_hypothesis(s, hypothesis_id, org_id=org)
        if hyp is None or hyp.asset_id != asset_id:
            raise HTTPException(404, "hypothesis not found")
        try:
            repo.dismiss_hypothesis(s, hypothesis_id, actor=auth.actor)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"status": "dismissed"}

    def _threat_model_view(row: Any) -> ThreatModelView:
        return ThreatModelView(
            asset_id=row.asset_id, mermaid=row.mermaid,
            stride=[StrideRowView(**d) for d in row.stride], version=row.version,
            source=row.source, updated_at=row.updated_at, updated_by=row.updated_by,
        )  # fmt: skip

    def _checkout_graph(scan: Any) -> Any:
        """Clone a scan's source again and analyze it (threat model, attack paths). Any clone
        failure is the caller's to see -- a repository made private since it was scanned, a host
        that is down -- not a server error: IngestError, not only GitUrlError (a bad URL), which
        used to be all that was caught, so the rest answered 500."""
        from core.attackpath.checkout import build_graph
        from core.ingest import IngestError

        try:
            return build_graph(scan.source_ref, scan.ref)
        except IngestError as exc:
            raise HTTPException(422, f"could not check out the repository: {exc}") from exc

    def _regenerate_threat_model(s: Session, asset: Any, org: str) -> Any:
        scan = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if scan is None:
            raise HTTPException(409, "no completed scan for this asset")
        if scan.source_type != "git":
            raise HTTPException(
                409, "the threat model needs a git source to check out the code from"
            )

        from core.threatmodel.generate import generate_threat_model

        app_state.limiter.acquire()
        draft = generate_threat_model(_checkout_graph(scan))
        stride_dicts = [
            {
                "element": r.element, "element_kind": r.element_kind.value,
                "category": r.category, "prompt": r.prompt,
            }  # fmt: skip
            for r in draft.stride
        ]
        return repo.save_threat_model(
            s, asset.id, draft.mermaid, stride_dicts, source="generated", actor=None
        )

    @app.get(
        "/assets/{asset_id}/threat-model",
        response_model=ThreatModelView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_threat_model_endpoint(
        asset_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ThreatModelView:
        """The project's threat-model draft (plan §21.7). Auto-generated from the latest scan on
        first access -- deterministic, no model call, so there is no cost gate to ask for first.
        Once a person edits it or explicitly regenerates, that becomes the current row and stays
        until the next explicit regenerate."""
        asset = _get_asset(s, asset_id, org)
        existing = repo.get_threat_model(s, asset.id)
        if existing is not None:
            return _threat_model_view(existing)
        return _threat_model_view(_regenerate_threat_model(s, asset, org))

    @app.post(
        "/assets/{asset_id}/threat-model/regenerate",
        response_model=ThreatModelView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def regenerate_threat_model_endpoint(
        asset_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ThreatModelView:
        """Discards the current draft, including any edits, and regenerates from the latest scan."""
        asset = _get_asset(s, asset_id, org)
        return _threat_model_view(_regenerate_threat_model(s, asset, org))

    @app.put(
        "/assets/{asset_id}/threat-model",
        response_model=ThreatModelView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def save_threat_model_endpoint(
        asset_id: str,
        body: SaveThreatModelRequest,
        auth: AuthContext = Depends(require_auth),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ThreatModelView:
        """A person's own edit to the diagram/table -- stored as-is, source="edited". Never
        validated against the code: there is nothing to validate a person's own review notes
        against."""
        asset = _get_asset(s, asset_id, org)
        stride_dicts = [r.model_dump() for r in body.stride]
        row = repo.save_threat_model(
            s, asset.id, body.mermaid, stride_dicts, source="edited", actor=auth.actor
        )
        return _threat_model_view(row)

    @app.get(
        "/settings/retention",
        response_model=RetentionSettingsView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_retention_settings_endpoint(
        s: Session = Depends(db), org: str = Depends(current_org)
    ) -> RetentionSettingsView:
        """How long this organization keeps a scan's encrypted artifacts before crypto-shredding
        them (plan §22.2). Always returns a value -- the plan's own default (7 days) when this org
        has never set its own, never a 404."""
        return RetentionSettingsView(org_id=org, retention_days=repo.get_retention_days(s, org))

    @app.put(
        "/settings/retention",
        response_model=RetentionSettingsView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def save_retention_settings_endpoint(
        body: SaveRetentionSettingsRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> RetentionSettingsView:
        row = repo.set_retention_days(s, org, body.retention_days)
        return RetentionSettingsView(org_id=row.org_id, retention_days=row.retention_days)

    def _plugin_view(manifest: Any, allowed: bool) -> PluginView:
        return PluginView(
            name=manifest.plugin_name,
            package_name=manifest.package_name,
            package_version=manifest.package_version,
            image=manifest.adapter.spec.image,
            certificate_identity=manifest.certificate_identity,
            certificate_oidc_issuer=manifest.certificate_oidc_issuer,
            allowed=allowed,
        )

    @app.get(
        "/plugins",
        response_model=list[PluginView],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_plugins_endpoint(
        s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[PluginView]:
        """Every plugin discovered via the `bulwark.scanner_adapters` entry point (Week 51 task 1,
        plan §23), whether or not this organization has allowlisted it yet. `allowed` is this org's
        allowlist row right now -- `core.plugins.signing` still re-verifies the image's Sigstore
        signature at the moment a scan actually uses it, so `allowed=True` is not itself a guarantee
        the plugin will run successfully."""
        plugins = discover_plugins()
        return [
            _plugin_view(m, repo.is_plugin_allowed(s, org, name))
            for name, m in sorted(plugins.items())
        ]

    @app.put(
        "/plugins/{plugin_name}/allowlist",
        response_model=PluginView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def set_plugin_allowed_endpoint(
        plugin_name: str,
        body: SetPluginAllowedRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> PluginView:
        """Trusting a plugin is security-relevant (it will run inside the same sandbox as a built-in
        scanner) -- recorded in the audit log by `core.persistence.repo.set_plugin_allowed` itself.
        Turning a plugin ON re-verifies its Sigstore signature synchronously, right now, so a bad
        publisher identity or an unsigned image fails loudly at the moment someone tries to trust it
        rather than silently at the next scan that happens to request it; turning one off never
        needs that check."""
        manifest = discover_plugins().get(plugin_name)
        if manifest is None:
            raise HTTPException(404, "plugin not found")
        if body.enabled:
            try:
                verify_plugin_image(
                    manifest.adapter.spec.image,
                    manifest.certificate_identity,
                    manifest.certificate_oidc_issuer,
                )
            except PluginSignatureError as exc:
                raise HTTPException(422, f"cannot allow {plugin_name}: {exc}") from exc
        repo.set_plugin_allowed(s, org, plugin_name, enabled=body.enabled, allowed_by=auth.actor)
        return _plugin_view(manifest, body.enabled)

    def _integration_settings_view(org: str, row: Any) -> IntegrationSettingsView:
        row = row or SimpleNamespace(
            slack_webhook_url=None, discord_webhook_url=None, outbound_webhook_url=None,
            outbound_webhook_secret=None, github_token=None, github_issues_repo=None,
            jira_base_url=None, jira_project_key=None, teams_webhook_url=None,
        )  # fmt: skip
        outbound_ok = bool(row.outbound_webhook_url and row.outbound_webhook_secret)
        github_ok = bool(row.github_token and row.github_issues_repo)
        jira_ok = bool(row.jira_base_url and row.jira_project_key)
        return IntegrationSettingsView(
            org_id=org,
            slack_configured=bool(row.slack_webhook_url),
            discord_configured=bool(row.discord_webhook_url),
            outbound_webhook_configured=outbound_ok,
            github_configured=github_ok,
            github_issues_repo=row.github_issues_repo,
            jira_configured=jira_ok,
            jira_base_url=row.jira_base_url,
            jira_project_key=row.jira_project_key,
            teams_configured=bool(row.teams_webhook_url),
        )

    @app.get(
        "/settings/integrations",
        response_model=IntegrationSettingsView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_integration_settings_endpoint(
        s: Session = Depends(db), org: str = Depends(current_org)
    ) -> IntegrationSettingsView:
        """Week 51 task 2, plan §23. Never a 404 -- an org with nothing configured just shows every
        integration as not configured, the same "always a value, never a missing-row error" posture
        `GET /settings/retention` already has."""
        return _integration_settings_view(org, repo.get_integration_settings(s, org))

    @app.put(
        "/settings/integrations",
        response_model=IntegrationSettingsView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def save_integration_settings_endpoint(
        body: SaveIntegrationSettingsRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> IntegrationSettingsView:
        for field_name, value in (
            ("slack_webhook_url", body.slack_webhook_url),
            ("discord_webhook_url", body.discord_webhook_url),
            ("outbound_webhook_url", body.outbound_webhook_url),
            ("teams_webhook_url", body.teams_webhook_url),
            # Week 66: ticket sync calls Jira on a schedule, so its address gets the same guard.
            ("jira_base_url", body.jira_base_url),
        ):
            if value:
                try:
                    validate_webhook_url(value)
                except WebhookUrlError as exc:
                    raise HTTPException(422, f"{field_name}: {exc}") from exc
        row = repo.set_integration_settings(s, org, actor=auth.actor, **body.model_dump())
        return _integration_settings_view(org, row)

    @app.post("/integrations/github-issues/webhook/{org_id}", include_in_schema=False)
    async def github_issues_webhook(
        org_id: str, request: Request, st: AppState = Depends(state)
    ) -> dict[str, str]:
        """Inbound half of GitHub Issues two-way sync (Week 51 task 2, plan §23): a repo-level
        webhook the operator configures on their own GitHub repository (Settings -> Webhooks),
        pointed at this URL with the same secret stored as `github_webhook_secret` -- deliberately
        separate from the GitHub *App* webhook (`/integrations/github/webhook`) and its deployment-
        wide secret, since this integration needs no App installation at all (see
        `core.integrations.github_issues`'s own docstring)."""
        body = await request.body()
        with st.sessions() as s:
            set_session_org(s, org_id)
            settings = repo.get_integration_settings(s, org_id)
            if settings is None or not settings.github_webhook_secret:
                raise HTTPException(404, "not configured")
            if not verify_signature(
                body, request.headers.get("X-Hub-Signature-256"), settings.github_webhook_secret
            ):
                raise HTTPException(401, "invalid webhook signature")
            if request.headers.get("X-GitHub-Event") != "issues":
                return {"status": "ignored"}
            try:
                payload = json.loads(body)
            except json.JSONDecodeError as exc:
                raise HTTPException(422, "invalid JSON") from exc
            action = payload.get("action")
            if action not in ("closed", "reopened", "assigned", "unassigned"):
                return {"status": "ignored"}
            issue = payload.get("issue") or {}
            repo_full_name = (payload.get("repository") or {}).get("full_name")
            number = issue.get("number")
            if not repo_full_name or number is None:
                return {"status": "ignored"}
            link = repo.get_external_link_by_external_id(
                s, org_id, "github", f"{repo_full_name}#{number}"
            )
            if link is None:
                return {"status": "ignored"}
            # Sync metadata only -- see ExternalIssueLinkRow's own docstring for why this never
            # touches IssueRow.state. Week 66: the project's status map decides what a change
            # means (at most "ready for retest"), through `core.tickets.sync`.
            from core.integrations.github_issues import IssueState
            from core.tickets.sync import Remote, apply_remote

            gh = IssueState(
                state=str(issue.get("state") or ("closed" if action == "closed" else "open")),
                state_reason=issue.get("state_reason"),
                assignee=(issue.get("assignee") or {}).get("login"), labels=(),
            )  # fmt: skip
            repo.set_external_link_status(s, link.id, "closed" if gh.state == "closed" else "open")
            apply_remote(s, org_id, "github", link.external_id,
                         Remote(gh.status, gh.state == "closed", None, gh.assignee))  # fmt: skip
        return {"status": "ok"}

    @app.post("/integrations/jira/webhook/{org_id}/{secret}", include_in_schema=False)
    async def jira_webhook(
        org_id: str, secret: str, request: Request, st: AppState = Depends(state)
    ) -> dict[str, str]:
        """Inbound half of Jira two-way sync. Jira Cloud's own webhooks carry no HMAC signature of
        any kind (unlike GitHub's) -- a shared secret embedded in the URL path the operator pastes
        into Jira's own WebHooks admin screen is the standard way to secure a webhook receiver for a
        sender that doesn't sign its requests."""
        with st.sessions() as s:
            set_session_org(s, org_id)
            settings = repo.get_integration_settings(s, org_id)
            if settings is None or not settings.jira_webhook_secret:
                raise HTTPException(404, "not configured")
            if not hmac.compare_digest(secret, settings.jira_webhook_secret):
                raise HTTPException(401, "invalid secret")
            body = await request.body()
            try:
                payload = json.loads(body)
            except json.JSONDecodeError as exc:
                raise HTTPException(422, "invalid JSON") from exc
            if payload.get("webhookEvent") != "jira:issue_updated":
                return {"status": "ignored"}
            issue = payload.get("issue") or {}
            key = issue.get("key")
            if not key:
                return {"status": "ignored"}
            link = repo.get_external_link_by_external_id(s, org_id, "jira", key)
            if link is None:
                return {"status": "ignored"}
            # Jira has no universal "closed" boolean -- every workflow can name its own statuses,
            # but statusCategory.key is standardized across all of them to exactly "new" |
            # "indeterminate" | "done".
            status_category = ((issue.get("fields") or {}).get("status") or {}).get(
                "statusCategory"
            ) or {}
            new_status = "closed" if status_category.get("key") == "done" else "open"
            repo.set_external_link_status(s, link.id, new_status)
            from core.tickets.sync import Remote, apply_remote

            fields = issue.get("fields") or {}
            apply_remote(s, org_id, "jira", key, Remote(
                str((fields.get("status") or {}).get("name") or ""), new_status == "closed",
                status_category.get("key"), (fields.get("assignee") or {}).get("displayName"),
            ))  # fmt: skip
        return {"status": "ok"}

    @app.get(
        "/assets/{asset_id}/attack-paths",
        response_model=list[AttackPathView],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_attack_paths_endpoint(
        asset_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[AttackPathView]:
        """Every attack path chained from this asset's current open issues, ranked highest risk
        first (plan §21.6, §28.5). Always computable without a model -- narrative generation
        (Task.ATTACK_PATH) is best-effort per path (at most the first 10, by rank) and never blocks
        the graph itself."""
        asset = _get_asset(s, asset_id, org)
        scan = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if scan is None:
            raise HTTPException(409, "no completed scan for this asset")
        if scan.source_type != "git":
            raise HTTPException(409, "attack paths need a git source to check out the code from")

        from core.attackpath.narrative import generate as generate_narrative
        from core.attackpath.service import find_attack_paths

        app_state.limiter.acquire()
        graph = _checkout_graph(scan)

        paths = find_attack_paths(s, asset.id, scan.id, graph)
        client = app_state.llm_attack_path
        tokens = 0
        views: list[AttackPathView] = []
        for i, path in enumerate(paths):
            narrative_text = None
            if client is not None and i < 10:
                narrated = generate_narrative(path, client)
                if narrated is not None:
                    narrative_text = narrated.text
                    tokens += narrated.tokens_used
            views.append(
                AttackPathView(
                    id=path.id, likelihood=path.likelihood.value, impact=path.impact.value,
                    rank_score=path.rank_score, cheapest_link=path.cheapest_link,
                    narrative=narrative_text,
                    nodes=[
                        AttackPathNodeView(
                            id=n.id, kind=n.kind.value, label=n.label, issue_id=n.issue_id,
                            detail=n.detail,
                        )
                        for n in path.nodes
                    ],
                    edges=[
                        AttackPathEdgeView(
                            kind=e.kind.value, source=e.source, target=e.target, rule_id=e.rule_id
                        )
                        for e in path.edges
                    ],
                )
            )  # fmt: skip
        if tokens:
            llm_budget.record(s, scan, tokens)
        return views

    def _message_view(row: Any) -> MessageView:
        return MessageView(
            id=row.id, role=row.role, content=row.content,
            citations=[CitationView(**c) for c in row.citations] if row.citations else None,
            created_at=row.created_at,
        )  # fmt: skip

    @app.post(
        "/assets/{asset_id}/copilot/conversations",
        response_model=ConversationView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def start_conversation(
        asset_id: str,
        body: StartConversationRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ConversationView:
        """Start a copilot conversation for one asset (plan §21.5). `409` if the copilot isn't
        enabled, there's no completed scan, or the asset isn't git-sourced -- the same checks the
        Hypotheses lane's own generate endpoint makes, since both need a real checkout."""
        if app_state.llm_copilot is None:
            raise HTTPException(409, "the copilot is not enabled on this server")
        asset = _get_asset(s, asset_id, org)
        scan = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if scan is None:
            raise HTTPException(409, "no completed scan for this asset")
        if scan.source_type != "git":
            raise HTTPException(409, "the copilot needs a git source to check out the code from")
        row = repo.create_conversation(
            s, asset.id, context_kind=body.context_kind, context_id=body.context_id
        )
        return ConversationView(
            id=row.id, asset_id=row.asset_id, context_kind=row.context_kind,
            context_id=row.context_id, created_at=row.created_at,
            last_message_at=row.last_message_at,
        )  # fmt: skip

    @app.post(
        "/assets/{asset_id}/copilot/conversations/{conversation_id}/messages",
        response_model=MessageView,
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def post_copilot_message(
        asset_id: str,
        conversation_id: str,
        body: PostMessageRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> MessageView:
        """Ask the copilot one question in an existing conversation (plan §21.5): clones the
        asset's latest scan's source on the conversation's first message (cached for later
        messages in the same conversation, core.copilot.session), then runs the tool-calling loop.
        A model that never produces a validly-cited answer within its turn budget still gets a
        stored, honest response -- never a 5xx for "the copilot couldn't find a grounded answer."
        """
        client = app_state.llm_copilot
        if client is None:
            raise HTTPException(409, "the copilot is not enabled on this server")

        from core.llm.client import AnthropicClient

        if not isinstance(client, AnthropicClient):
            raise HTTPException(
                409, "the copilot needs a hosted model backend (tool-calling isn't supported "
                "for local models -- see ADR-0027)",
            )  # fmt: skip
        asset = _get_asset(s, asset_id, org)
        conversation = repo.get_conversation(s, conversation_id, org_id=org)
        if conversation is None or conversation.asset_id != asset.id:
            raise HTTPException(404, "conversation not found")
        scan = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if scan is None:
            raise HTTPException(409, "no completed scan for this asset")
        if scan.source_type != "git":
            raise HTTPException(409, "the copilot needs a git source to check out the code from")

        from core.copilot.service import CopilotGiveUp, ask
        from core.copilot.session import default_cache
        from core.copilot.tools import CopilotContext
        from core.gitfetch import GitUrlError

        try:
            checkout, graph = default_cache().get_or_clone(
                conversation.id, scan.source_ref, scan.ref
            )
        except GitUrlError as exc:
            raise HTTPException(422, f"could not check out the repository: {exc}") from exc

        app_state.limiter.acquire()
        repo.add_message(s, conversation.id, role="user", content=body.question)
        ctx = CopilotContext(
            session=s, org_id=org, asset_id=asset.id, latest_scan_id=scan.id, checkout=checkout,
            graph=graph,
        )  # fmt: skip
        try:
            result = ask(client, ctx, body.question)
        except CopilotGiveUp:
            row = repo.add_message(
                s, conversation.id, role="assistant",
                content="I couldn't find a well-grounded answer to that.",
            )  # fmt: skip
            return _message_view(row)
        if result.tokens_used:
            llm_budget.record(s, scan, result.tokens_used)
        row = repo.add_message(
            s, conversation.id, role="assistant", content=result.answer,
            citations=result.citations, tokens_used=result.tokens_used,
        )  # fmt: skip
        return _message_view(row)

    @app.get(
        "/assets/{asset_id}/copilot/conversations/{conversation_id}/messages",
        response_model=list[MessageView],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_copilot_messages(
        asset_id: str,
        conversation_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[MessageView]:
        asset = _get_asset(s, asset_id, org)
        conversation = repo.get_conversation(s, conversation_id, org_id=org)
        if conversation is None or conversation.asset_id != asset.id:
            raise HTTPException(404, "conversation not found")
        return [_message_view(m) for m in repo.list_messages(s, conversation.id, org_id=org)]

    @app.get("/risk/feeds", response_model=FeedsStatus, dependencies=[Depends(require_auth)])
    def risk_feeds() -> FeedsStatus:
        meta = read_meta(app_state.settings.workdir / "feeds")
        return FeedsStatus(
            fetched_at=meta.get("fetched_at"),
            stale=is_stale(meta),
            epss=meta.get("epss"),
            kev=meta.get("kev"),
            errors=meta.get("errors", {}),
        )

    @app.get(
        "/scans/{scan_id}",
        response_model=ScanView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_scan(
        scan_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ScanView:
        return _view(s, _get_scan(s, scan_id, org))

    @app.get(
        "/scans/{scan_id}/findings",
        response_model=FindingsPage,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_findings(
        scan_id: str,
        severity: list[str] | None = Query(default=None),
        category: list[str] | None = Query(default=None),
        tool: str | None = None,
        path: str | None = Query(default=None, description="Substring match on file path."),
        sort: str = Query(default="severity", pattern="^(severity|path|risk)$"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> FindingsPage:
        _get_scan(s, scan_id, org)
        page = repo.query_findings(
            s, scan_id, severities=severity, categories=category, tool=tool,
            path_contains=path, sort=sort, limit=limit, offset=offset,
        )  # fmt: skip
        return FindingsPage(total=page.total, limit=limit, offset=offset, items=page.items)

    @app.get(
        "/scans/{scan_id}/compare",
        response_model=ScanComparisonView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def compare_scans(
        scan_id: str,
        against: str = Query(description="The other scan id to compare against."),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ScanComparisonView:
        """Plan §28.6: two scans of the same project, side by side -- new, fixed, reintroduced and
        unchanged issues. 404s (not 400) when the two scans don't share an asset, the same
        not-a-403 reasoning as `_get_scan` (ADR-0013): which other scans exist to compare against
        isn't information a scan in a different org (or asset) should be able to probe for."""
        _get_scan(s, scan_id, org)
        _get_scan(s, against, org)
        cmp = repo.compare_scans(s, scan_id, against, org_id=org)
        if cmp is None:
            raise HTTPException(404, "these two scans do not belong to the same project")

        def side(scan: Scan) -> ScanComparisonSide:
            return ScanComparisonSide(
                scan_id=scan.id, source_label=scan.source_label, finished_at=scan.finished_at,
                github_pr_number=scan.github_pr_number,
            )  # fmt: skip

        def issues(items: list[dict[str, Any]]) -> list[ComparedIssue]:
            return [ComparedIssue(**i) for i in items]

        return ScanComparisonView(
            earlier=side(cmp.earlier), later=side(cmp.later), new=issues(cmp.new),
            fixed=issues(cmp.fixed), reintroduced=issues(cmp.reintroduced),
            unchanged=issues(cmp.unchanged),
        )  # fmt: skip

    @app.get(
        "/scans/{scan_id}/cost",
        response_model=ScanCostView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_scan_cost(
        scan_id: str,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ScanCostView:
        """Plan §23's cost-per-scan dashboard (Week 50): an estimate, computed fresh on every call
        rather than stored -- a scan's LLM spend keeps growing after the scan job itself finishes
        (remediation suggestions, hypotheses, copilot messages are all requested later), so a cost
        written once at completion would go stale the moment someone asks for a suggestion."""
        scan = _get_scan(s, scan_id, org)
        compute_seconds = repo.scan_compute_seconds(s, scan_id)
        settings = st.settings
        breakdown = cost.estimate_cost(
            compute_seconds=compute_seconds,
            llm_tokens=scan.llm_tokens_used,
            model=LLMConfig.from_env().model,
            compute_usd_per_second=settings.compute_cost_per_second_usd,
            llm_usd_per_1k_tokens=settings.llm_cost_per_1k_tokens_usd,
        )
        return ScanCostView(
            scan_id=scan_id, compute_seconds=breakdown.compute_seconds,
            compute_usd=breakdown.compute_usd, llm_tokens=breakdown.llm_tokens,
            llm_usd=breakdown.llm_usd, total_usd=breakdown.total_usd,
        )  # fmt: skip

    @app.get(
        "/costs/summary",
        response_model=CostSummaryView,
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_cost_summary(
        days: int = Query(default=30, ge=1, le=365),
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> CostSummaryView:
        """The same estimate as `get_scan_cost`, aggregated over every scan in the window -- an
        internal visibility dashboard (plan §23), not a billing export."""
        since = datetime.now(timezone.utc) - timedelta(days=days)
        settings = st.settings
        model = LLMConfig.from_env().model
        rows: list[CostSummaryRow] = []
        total_compute_s = total_llm_tokens = 0.0
        total_compute_usd = total_llm_usd = 0.0
        for scan, compute_seconds in repo.cost_summary_scans(s, org_id=org, since=since):
            breakdown = cost.estimate_cost(
                compute_seconds=compute_seconds, llm_tokens=scan.llm_tokens_used, model=model,
                compute_usd_per_second=settings.compute_cost_per_second_usd,
                llm_usd_per_1k_tokens=settings.llm_cost_per_1k_tokens_usd,
            )  # fmt: skip
            rows.append(
                CostSummaryRow(
                    scan_id=scan.id, source_label=scan.source_label, created_at=scan.created_at,
                    compute_seconds=breakdown.compute_seconds, llm_tokens=breakdown.llm_tokens,
                    total_usd=breakdown.total_usd,
                )
            )  # fmt: skip
            total_compute_s += breakdown.compute_seconds
            total_llm_tokens += breakdown.llm_tokens
            total_compute_usd += breakdown.compute_usd
            total_llm_usd += breakdown.llm_usd
        return CostSummaryView(
            days=days, scan_count=len(rows), total_compute_seconds=total_compute_s,
            total_llm_tokens=int(total_llm_tokens), total_compute_usd=total_compute_usd,
            total_llm_usd=total_llm_usd, total_usd=total_compute_usd + total_llm_usd, scans=rows,
        )  # fmt: skip

    @app.get("/scans/{scan_id}/export", dependencies=[Depends(require_scope("scans:read"))])
    def export_scan(
        scan_id: str,
        format: str = Query(default="sarif", description="sarif | html | pdf | json"),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> Response:
        """Download the whole scan (every finding, ranked) as SARIF 2.1.0, HTML, PDF or JSON."""
        if format not in FORMATS:
            raise HTTPException(422, f"format must be one of: {', '.join(FORMATS)}")
        scan = _get_scan(s, scan_id, org)
        if scan.status not in ("completed", "partial"):
            raise HTTPException(409, "the scan has not finished, or it failed")
        view = _view(s, scan)
        report = ReportData(
            scan_id=scan.id,
            source_label=scan.source_label,
            status=scan.status,
            finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
            tool_status={k: v.model_dump() for k, v in view.tool_status.items()},
            raw_findings=view.raw_findings,
            unique_findings=view.unique_findings,
            dedup_rate=view.dedup_rate,
            severity_counts=view.severity_counts,
            findings=_all_findings(s, scan.id),
        )
        media, ext = FORMATS[format]
        return Response(
            render(format, report),
            media_type=media,
            headers={
                "Content-Disposition": f'attachment; filename="bulwark-{scan.id[:8]}.{ext}"',
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            },
        )

    @app.websocket("/scans/{scan_id}/ws")
    async def scan_ws(ws: WebSocket, scan_id: str) -> None:
        """Live progress. First client message must be {"token": "<bearer token>"}."""
        st: AppState = ws.app.state.bulwark
        await ws.accept()
        try:
            hello = await asyncio.wait_for(ws.receive_json(), timeout=10)
            if not token_ok(str(hello.get("token", "")), st.settings.api_token):
                await ws.close(code=4401, reason="unauthorized")
                return
            # No FastAPI `Depends(db)` on a WebSocket route, so there's no request-scoped
            # `SET LOCAL` here (Postgres RLS still applies at the DB level regardless, ADR-0013);
            # this app-level check is what scopes this path, like every other `repo.py` call site.
            org = str(hello.get("org") or "").strip() or DEFAULT_ORG_ID
            with st.sessions() as s:
                if not _UUID.match(scan_id) or repo.get_scan(s, scan_id, org_id=org) is None:
                    await ws.close(code=4404, reason="scan not found")
                    return
            # Subscribe BEFORE reading the snapshot so no event falls in the gap between them.
            events = st.subscriber.subscribe(scan_id)
            async with contextlib.aclosing(events):  # type: ignore[type-var]
                with st.sessions() as s:
                    view = _view(s, _get_scan(s, scan_id, org))
                await ws.send_json({"type": "snapshot", **json.loads(view.model_dump_json())})
                if view.status in repo.TERMINAL:
                    await ws.close()
                    return
                async for event in events:
                    await ws.send_json(event)
                    if event.get("type") == "scan.finished":
                        break
            await ws.close()
        except (WebSocketDisconnect, asyncio.TimeoutError, ValueError):
            with contextlib.suppress(RuntimeError):
                await ws.close(code=1008)

    register_ingest_routes(app)
    register_dedup_routes(app)
    register_mapping_routes(app)
    register_manual_routes(app)
    register_connector_routes(app)
    register_sla_routes(app)
    register_priority_routes(app)
    register_engagement_routes(app)
    register_retest_routes(app)
    register_collab_routes(app)
    register_acceptance_routes(app)
    register_rules_routes(app)
    register_notify_routes(app)
    register_ticket_routes(app)
    register_calendar_routes(app)
    register_component_routes(app)
    register_advisory_routes(app)
    register_vex_routes(app)
    register_compliance_routes(app)
    register_metric_routes(app)
    register_issue_routes(app)
    register_identity_routes(app)
    register_sso_routes(app)
    register_scim_routes(app)
    register_dashboard_routes(app)
    register_report_routes(app)
    return app


class RedisSubscriber:
    """Relays worker events from Redis pub/sub."""

    def __init__(self, url: str) -> None:
        self._url = url

    async def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]:
        import redis.asyncio as aioredis

        from core.events import channel

        client = aioredis.from_url(self._url)  # type: ignore[no-untyped-call]
        pubsub = client.pubsub()
        await pubsub.subscribe(channel(scan_id))
        try:
            async for msg in pubsub.listen():
                if msg["type"] == "message":
                    yield json.loads(msg["data"])
        finally:
            await pubsub.unsubscribe()
            await pubsub.aclose()
            await client.aclose()


def build_default_app() -> FastAPI:
    """Production wiring, used by `uvicorn api.main:app`."""
    from core.llm.gateway import Task, make_gateway_client
    from core.persistence.db import get_session_factory
    from core.persistence.storage import S3Store
    from core.tasks import (
        recompute_priority_task,
        render_report_task,
        run_connector_task,
        run_dast_campaign_task,
        run_import_task,
        run_scan_task,
        run_targeted_retest_task,
    )

    settings = Settings.from_env()
    if settings.s3_endpoint or settings.s3_access_key:
        S3Store(settings).ensure_bucket()
    return create_app(
        AppState(
            settings=settings,
            sessions=get_session_factory(),
            enqueue=lambda scan_id, org_id: run_scan_task.delay(scan_id, org_id),
            subscriber=RedisSubscriber(settings.redis_url),
            enqueue_dast_campaign=lambda scan_id, org_id: run_dast_campaign_task.delay(
                scan_id, org_id
            ),
            enqueue_import=lambda import_id, org_id: run_import_task.delay(import_id, org_id),
            # None unless the routed backend is enabled and ready; raises at startup, not on the
            # first request, if privacy mode is on with no local model configured (gateway.py).
            llm=make_gateway_client(Task.FIX),
            llm_triage=make_gateway_client(Task.TRIAGE),
            llm_hypotheses=make_gateway_client(Task.HYPOTHESES),
            llm_copilot=make_gateway_client(Task.COPILOT),
            llm_attack_path=make_gateway_client(Task.ATTACK_PATH),
            llm_mapper=make_gateway_client(Task.MAPPER),
            llm_report=make_gateway_client(Task.REPORT),
            enqueue_report=lambda run_id, org_id: render_report_task.delay(run_id, org_id),
            enqueue_connector=lambda cid, org_id: run_connector_task.delay(cid, org_id),
            enqueue_priority=lambda pid, org_id: recompute_priority_task.delay(pid, org_id),
            enqueue_retest=lambda rid, org_id: run_targeted_retest_task.delay(rid, org_id),
            limiter=UsageLimiter.from_env(),
        )
    )


def __getattr__(name: str) -> FastAPI:  # lazy: `uvicorn api.main:app` builds it on first access
    if name == "app":
        return build_default_app()
    raise AttributeError(name)


_ = EventSubscriber  # re-exported for type hints in tests
