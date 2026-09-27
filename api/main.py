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

from api.deps import AppState, EventSubscriber, db, require_auth, state, token_ok
from api.schemas import (
    FeedsStatus,
    FindingsPage,
    GuidanceView,
    RemediationView,
    ScanCreated,
    ScanRequest,
    ScanSummary,
    ScanView,
    SuggestionRequest,
    ToolStatus,
)
from core.config import Settings
from core.export import FORMATS, ReportData, render
from core.gitfetch import GitUrlError, validate_git_url
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


def _get_scan(s: Session, scan_id: str) -> Scan:
    scan = repo.get_scan(s, scan_id) if _UUID.match(scan_id) else None
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


def _all_findings(s: Session, scan_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    while True:
        page = repo.query_findings(s, scan_id, sort="risk", limit=500, offset=len(out))
        out.extend(page.items)
        if not page.items or len(out) >= page.total:
            return out


def _find(s: Session, scan_id: str, finding_id: str) -> Any:
    _get_scan(s, scan_id)
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
    )


def _dispatch(st: AppState, s: Session, scan: Scan) -> None:
    """Queue the job; if the queue is unreachable, fail the scan cleanly instead of orphaning it."""
    try:
        st.enqueue(scan.id)
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
        "/scans", status_code=202, response_model=ScanCreated, dependencies=[Depends(require_auth)]
    )
    def create_scan(
        body: ScanRequest, st: AppState = Depends(state), s: Session = Depends(db)
    ) -> ScanCreated:
        tools = _tools(body.tools)
        try:
            validate_git_url(body.source.url)  # fast feedback; re-validated again at clone time
        except GitUrlError as exc:
            raise HTTPException(422, str(exc)) from exc
        scan = repo.create_scan(
            s, source_type="git", source_ref=body.source.url,
            source_label=body.source.url, tools=tools,
        )  # fmt: skip
        _dispatch(st, s, scan)
        return ScanCreated(id=scan.id, status=scan.status)

    @app.post(
        "/scans/upload",
        status_code=202,
        response_model=ScanCreated,
        dependencies=[Depends(require_auth)],
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
            s, source_type="archive", source_ref=str(dest), source_label=name, tools=wanted
        )
        _dispatch(st, s, scan)
        return ScanCreated(id=scan.id, status=scan.status)

    @app.get("/scans", response_model=list[ScanSummary], dependencies=[Depends(require_auth)])
    def list_scans(
        limit: int = Query(default=20, ge=1, le=50), s: Session = Depends(db)
    ) -> list[ScanSummary]:
        out: list[ScanSummary] = []
        for scan in repo.list_scans(s, limit):
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
        "/scans/{scan_id}/guidance",
        response_model=GuidanceView,
        dependencies=[Depends(require_auth)],
    )
    def get_guidance(
        scan_id: str,
        finding_id: str = Query(min_length=1, max_length=500),
        s: Session = Depends(db),
    ) -> GuidanceView:
        """Reference guidance (CWE + OWASP) and any cached AI suggestion. Calls no model."""
        f = _find(s, scan_id, finding_id)
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
        dependencies=[Depends(require_auth)],
    )
    def create_suggestion(
        scan_id: str, body: SuggestionRequest, s: Session = Depends(db)
    ) -> RemediationView:
        """Generate (or fetch cached) an AI suggestion. Sends data to the model provider."""
        client = app_state.llm
        if client is None:
            raise HTTPException(409, "AI suggestions are not enabled on this server")
        f = _find(s, scan_id, body.finding_id)
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

    @app.get("/scans/{scan_id}", response_model=ScanView, dependencies=[Depends(require_auth)])
    def get_scan(scan_id: str, s: Session = Depends(db)) -> ScanView:
        return _view(s, _get_scan(s, scan_id))

    @app.get(
        "/scans/{scan_id}/findings",
        response_model=FindingsPage,
        dependencies=[Depends(require_auth)],
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
    ) -> FindingsPage:
        _get_scan(s, scan_id)
        page = repo.query_findings(
            s, scan_id, severities=severity, categories=category, tool=tool,
            path_contains=path, sort=sort, limit=limit, offset=offset,
        )  # fmt: skip
        return FindingsPage(total=page.total, limit=limit, offset=offset, items=page.items)

    @app.get("/scans/{scan_id}/export", dependencies=[Depends(require_auth)])
    def export_scan(
        scan_id: str,
        format: str = Query(default="sarif", description="sarif | html | pdf | json"),
        s: Session = Depends(db),
    ) -> Response:
        """Download the whole scan (every finding, ranked) as SARIF 2.1.0, HTML, PDF or JSON."""
        if format not in FORMATS:
            raise HTTPException(422, f"format must be one of: {', '.join(FORMATS)}")
        scan = _get_scan(s, scan_id)
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
            with st.sessions() as s:
                if not _UUID.match(scan_id) or repo.get_scan(s, scan_id) is None:
                    await ws.close(code=4404, reason="scan not found")
                    return
            # Subscribe BEFORE reading the snapshot so no event falls in the gap between them.
            events = st.subscriber.subscribe(scan_id)
            async with contextlib.aclosing(events):  # type: ignore[type-var]
                with st.sessions() as s:
                    view = _view(s, _get_scan(s, scan_id))
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
            enqueue=lambda scan_id: run_scan_task.delay(scan_id),
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
