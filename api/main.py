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
    BulkTriageRequest,
    BulkTriageResult,
    ComparedIssue,
    FeedsStatus,
    FindingsPage,
    GuidanceView,
    IssueHistoryEvent,
    IssueView,
    ProjectOverview,
    RemediationView,
    ScanComparisonSide,
    ScanComparisonView,
    ScanCreated,
    ScannedTool,
    ScanRequest,
    ScanSummary,
    ScanView,
    SuggestionRequest,
    ToolStatus,
    TrendPoint,
    TriageRequest,
)
from core.config import Settings
from core.export import FORMATS, ReportData, render
from core.gitfetch import GitUrlError, validate_git_url
from core.github_app import parse_pull_request_event, verify_signature
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
        f = _find(s, scan_id, org, body.finding_id)
        kb = _kb(s)
        try:
            res = llm_cache.suggest_cached(
                f, kb, client, s, _code_of(f), before_call=app_state.limiter.acquire
            )
        except LimitExceeded as exc:
            raise HTTPException(
                429, str(exc), headers={"Retry-After": str(exc.retry_after)}
            ) from exc
        return RemediationView(**asdict(res))

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
    from core.llm.client import make_client
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
            llm=make_client(),  # None unless BULWARK_LLM_ENABLED=1 and a key is set
            limiter=UsageLimiter.from_env(),
        )
    )


def __getattr__(name: str) -> FastAPI:  # lazy: `uvicorn api.main:app` builds it on first access
    if name == "app":
        return build_default_app()
    raise AttributeError(name)


_ = EventSubscriber  # re-exported for type hints in tests
