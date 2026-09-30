"""FastAPI service: scan lifecycle + findings + live progress (design doc §3, API gateway)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import asdict
from pathlib import Path
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
from fastapi.responses import Response
from fastapi.websockets import WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.orm import Session

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
from api.schemas import (
    AssetSummary,
    AttackPathEdgeView,
    AttackPathNodeView,
    AttackPathView,
    BulkTriageRequest,
    BulkTriageResult,
    CitationView,
    ComparedIssue,
    ConversationView,
    DependenciesView,
    FeedsStatus,
    FindingsPage,
    GenerateHypothesesResult,
    GuidanceView,
    HypothesisView,
    IssueHistoryEvent,
    IssueView,
    MessageView,
    PostMessageRequest,
    ProjectOverview,
    PromoteHypothesisResult,
    RemediationView,
    SaveThreatModelRequest,
    ScanComparisonSide,
    ScanComparisonView,
    ScanCreated,
    ScannedTool,
    ScanRequest,
    ScanSummary,
    ScanView,
    StartConversationRequest,
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
from core.config import Settings
from core.export import FORMATS, ReportData, render
from core.gitfetch import GitUrlError, validate_git_url
from core.github_app import parse_pull_request_event, verify_signature
from core.llm import budget as llm_budget
from core.llm import cache as llm_cache
from core.llm.limits import LimitExceeded, UsageLimiter
from core.llm.prompt import CodeContext
from core.llm.service import static_suggestion
from core.models import finding_from_dict
from core.observability import bind_scan, configure_logging, setup_tracing
from core.persistence import repo
from core.persistence.models import FindingRow, Scan
from core.rag.retrieve import context_for
from core.rag.store import KnowledgeBase
from core.risk import is_stale, read_meta
from core.scan import ADAPTERS, DEFAULT_TOOLS
from core.tenancy import DEFAULT_ORG_ID, set_session_org

log = logging.getLogger(__name__)
_SCAN_IN_PATH = re.compile(r"^/scans/([0-9a-f-]{36})(?:/|$)")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz")
MIN_TOKEN_LEN = 16


def _tools(requested: list[str] | None) -> list[str]:
    names = requested or list(DEFAULT_TOOLS)
    unknown = [t for t in names if t not in ADAPTERS]
    if unknown:
        raise HTTPException(422, f"unknown tool(s): {', '.join(unknown)}; valid: {list(ADAPTERS)}")
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
    # Explicit origin allowlist (never "*"): only the configured UI origins may call the API.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(app_state.settings.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

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
        tools = _tools(body.tools)
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
        wanted = _tools([t.strip() for t in tools.split(",") if t.strip()] if tools else None)
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
                    tools=list(DEFAULT_TOOLS), org_id=installation.org_id, ref=pr.ref,
                    github_repo=pr.repo_full_name, github_pr_number=pr.pr_number,
                    github_installation_id=pr.installation_id,
                )  # fmt: skip
                _dispatch(st, s, scan)
                return {"status": "queued", "scan_id": scan.id}

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

        page = repo.query_findings(s, latest.id, sort="risk", limit=fix_first_limit)
        # Calm by default (§29.2): a critical/high finding only counts toward the "at real risk"
        # verdict while it's reachable (or reachability is unknown) -- a finding whose own scoring
        # says it isn't reachable doesn't inflate the headline, even though it still appears further
        # down the fix-first list with its "not reachable" tag.
        fix_first = page.items
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
            more_at_lower_risk=max(total_open - len(fix_first), 0),
            since_previous_scan=since,
            trend=trend,
            scanned=scanned,
            latest_scan_id=latest.id,
            latest_scan_finished_at=latest.finished_at,
        )

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
        sort: str = Query(default="risk", pattern="^(severity|path|risk)$"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> FindingsPage:
        """Plan §28.3's issues table: the asset's currently-open issues (its latest scan's
        findings, joined with each one's triage state). Empty, not 404, when nothing has scanned
        yet -- mirrors `/scans/{id}/findings`'s own shape so the same frontend table component
        can render either."""
        asset = _get_asset(s, asset_id, org)
        latest = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if latest is None:
            return FindingsPage(total=0, limit=limit, offset=offset, items=[])
        page = repo.list_asset_issues(
            s, asset.id, latest.id, severities=severity, categories=category, triage=triage,
            sort=sort, limit=limit, offset=offset,
        )  # fmt: skip
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
            raise HTTPException(404, "issue not found in the latest scan")
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
        try:
            row = repo.triage_issue(
                s, issue_id, org_id=org, action=body.action, reason=body.reason,
                expires_at=body.expires_at, actor=auth.actor,
            )  # fmt: skip
        except LookupError as exc:
            raise HTTPException(404, "issue not found") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
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
        updated: list[str] = []
        failed: list[dict[str, str]] = []
        for issue_id in body.issue_ids:
            try:
                repo.triage_issue(
                    s, issue_id, org_id=org, action=body.action, reason=body.reason,
                    expires_at=body.expires_at, actor=auth.actor,
                )  # fmt: skip
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
        from core.fixagent import client as fixagent_client
        from core.fixagent import store as fixagent_store
        from core.fixagent.limits import WorkflowLimits
        from core.models import finding_from_dict

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
        tool = (
            finding.evidence.reported_by[0]
            if finding.evidence.reported_by
            else next(iter(finding.evidence.rule_ids), "")
        )
        if not tool:
            raise HTTPException(
                409, "could not tell which scanner originally reported this finding"
            )

        limits = WorkflowLimits.from_env()
        if fixagent_store.count_running_for_org(s, org) >= limits.max_concurrent_per_org:
            raise HTTPException(
                429,
                f"too many verified-fix runs already in progress for this organization "
                f"(max {limits.max_concurrent_per_org})",
            )

        verified_owner = scan.github_installation_id is not None
        run_tests_spec: dict[str, Any] | None = None
        if body.run_tests and verified_owner:
            if not body.test_image or not body.test_command:
                raise HTTPException(
                    422, "test_image and test_command are required when run_tests is true"
                )
            run_tests_spec = {"image": body.test_image, "command": body.test_command}
        # body.run_tests without a verified-owner asset is silently downgraded to "no tests," not a
        # 4xx: asking for an opt-in you don't qualify for yet is a normal request, not an error
        # (plan §21.2: "hardened Docker for now, verified-owner repositories only").

        workflow_id = fixagent_client.new_workflow_id(issue_id)
        run = fixagent_store.create_run(s, org, issue_id, workflow_id)
        baseline = fixagent_store.baseline_fingerprints_for(s, scan.id, finding.location.path)
        try:
            await fixagent_client.start_verified_fix(
                run.id,
                workflow_id,
                org,
                issue_id,
                finding.to_dict(),
                scan.source_ref,
                scan.ref,
                tool,
                baseline,
                scan.github_repo,
                scan.github_installation_id,
                run_tests_spec,
                limits,
            )
        except (
            Exception
        ) as exc:  # noqa: BLE001 - Temporal unreachable, or any other startup failure
            raise HTTPException(503, f"could not start the verified-fix workflow: {exc}") from exc
        return VerifiedFixStarted(run_id=run.id, workflow_id=workflow_id)

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
            run_id=run.id, issue_id=run.issue_id, status=run.status, attempts=run.attempts,
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

    def _regenerate_threat_model(s: Session, asset: Any, org: str) -> Any:
        scan = repo.latest_scan_for_asset(s, asset.id, org_id=org)
        if scan is None:
            raise HTTPException(409, "no completed scan for this asset")
        if scan.source_type != "git":
            raise HTTPException(
                409, "the threat model needs a git source to check out the code from"
            )

        from core.attackpath.checkout import build_graph
        from core.gitfetch import GitUrlError
        from core.threatmodel.generate import generate_threat_model

        app_state.limiter.acquire()
        try:
            graph = build_graph(scan.source_ref, scan.ref)
        except GitUrlError as exc:
            raise HTTPException(422, f"could not check out the repository: {exc}") from exc
        draft = generate_threat_model(graph)
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

        from core.attackpath.checkout import build_graph
        from core.attackpath.narrative import generate as generate_narrative
        from core.attackpath.service import find_attack_paths
        from core.gitfetch import GitUrlError

        app_state.limiter.acquire()
        try:
            graph = build_graph(scan.source_ref, scan.ref)
        except GitUrlError as exc:
            raise HTTPException(422, f"could not check out the repository: {exc}") from exc

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
    from core.tasks import run_scan_task

    settings = Settings.from_env()
    if settings.s3_endpoint or settings.s3_access_key:
        S3Store(settings).ensure_bucket()
    return create_app(
        AppState(
            settings=settings,
            sessions=get_session_factory(),
            enqueue=lambda scan_id, org_id: run_scan_task.delay(scan_id, org_id),
            subscriber=RedisSubscriber(settings.redis_url),
            # None unless the routed backend is enabled and ready; raises at startup, not on the
            # first request, if privacy mode is on with no local model configured (gateway.py).
            llm=make_gateway_client(Task.FIX),
            llm_triage=make_gateway_client(Task.TRIAGE),
            llm_hypotheses=make_gateway_client(Task.HYPOTHESES),
            llm_copilot=make_gateway_client(Task.COPILOT),
            llm_attack_path=make_gateway_client(Task.ATTACK_PATH),
            limiter=UsageLimiter.from_env(),
        )
    )


def __getattr__(name: str) -> FastAPI:  # lazy: `uvicorn api.main:app` builds it on first access
    if name == "app":
        return build_default_app()
    raise AttributeError(name)


_ = EventSubscriber  # re-exported for type hints in tests
