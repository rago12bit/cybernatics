"""The ingest API (Week 54 task 7, plan §42.1, ADR-0040): one endpoint for everything that is not a
scan Bulwark ran, with reimport semantics.

    POST /v2/ingest              upload a report; 202 and a worker does the rest
    GET  /v2/imports/{id}        status, the four counts, warnings, or why it failed
    POST /v2/imports/{id}/confirm   apply a previewed import
    POST /v2/imports/{id}/cancel    discard a previewed import
    POST /v2/imports/{id}/revert    undo the latest applied import of a Test
    GET  /v2/tests/{id}/imports  a Test's import history, with counts
    GET  /v2/projects/{id}/tests a project's Tests, with each one's latest import
    GET  /v2/parsers             the formats that can be imported

Import is reimport with an empty history: the first upload into a Test creates everything, every
later one is compared against it. The same file twice is a no-op that returns the original. Parsing
runs in the scanner sandbox on a worker (`core.imports.jobs`), never in this process, and a file
that cannot be read completely is refused rather than applied -- reimport closes what a file no
longer lists, so a half-read file would look like "everything was fixed".

Importing is its own permission (`ingest:write`), not `scans:write`: it can close Issues, which
starting a scan cannot.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import uuid
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.imports import mapper, service
from core.imports.parsers import CONFIDENT, PARSERS, detect
from core.imports.service import SCOPES
from core.persistence import repo
from core.persistence.models import ImportRecord

log = logging.getLogger(__name__)

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SNIFF_BYTES = 64 * 1024
MAX_IDS_RETURNED = 1000  # an import can touch tens of thousands of Issues; the counts stay exact
WAIT_SECONDS = 20  # the longest `wait_for_dedup` holds a request
SOURCES = ("upload",)  # runner / connector / manual arrive with their own weeks (plan §42.5, §43.2)


class ImportCounts(BaseModel):
    new: int
    unchanged: int
    reopened: int
    closed: int
    detached: int = Field(
        description="Issues this file stopped listing that stay open because another source still "
        "reports them. Not 'closed': they are not fixed."
    )
    held: int = Field(
        default=0,
        description="Issues this file stopped listing at a place its tool only samples (ZAP), "
        "while the same rule still fires on the same host. Held open: not seen, but not shown "
        "fixed either.",
    )


class ImportCreated(BaseModel):
    import_id: str
    status: str
    parser: str
    confidence: float | None = Field(
        description="How sure format detection was; null when the caller named the parser."
    )
    test_id: str
    duplicate: bool = Field(
        default=False,
        description="True when this exact file was already the Test's latest import: nothing was "
        "queued, and `import_id` is the original's.",
    )


class ImportView(BaseModel):
    id: str
    status: str = Field(
        description="queued, processing, previewed, applied, duplicate, failed, cancelled, reverted"
    )
    mode: str
    parser: str
    file_name: str | None
    test_id: str
    engagement_id: str | None
    counts: ImportCounts | None
    reopened_issue_ids: list[str]
    closed_issue_ids: list[str]
    detached_issue_ids: list[str]
    held_issue_ids: list[str] = []
    ids_truncated: bool
    warnings: list[str]
    error: str | None
    close_missing: bool
    scope: str
    dedup_complete: bool = Field(
        description="True once the import has been matched to Issues by the project's "
        "deduplication settings (plan §42.3) -- which happens inside the import itself, so this is "
        "true from the moment the import leaves queued and processing (applied, previewed, "
        "duplicate, reverted, cancelled or failed: nothing is pending)."
    )
    created_at: datetime
    reverted_at: datetime | None


class ParserInfo(BaseModel):
    name: str
    label: str
    formats: list[str]
    categories: list[str]
    recommended_dedup: str = Field(
        description="The deduplication strategy that suits this source (plan §42.2); every source "
        "is matched by `fingerprint_v2` until a project chooses (GET /v2/projects/{id}/dedup)."
    )


class ImportSummary(BaseModel):
    id: str
    status: str
    created_at: datetime
    counts: ImportCounts


class ProjectTest(BaseModel):
    id: str
    name: str
    parser: str | None
    engagement_id: str
    engagement_name: str
    engagement_type: str
    last_import: ImportSummary | None = Field(
        description="The Test's current snapshot: what the next upload is compared with."
    )


class RevertView(BaseModel):
    import_id: str
    status: str
    restored: int
    deleted: int
    skipped: int


def _get_record(s: Session, import_id: str, org: str) -> ImportRecord:
    record = repo.get_import_record(s, import_id, org) if _UUID.match(import_id) else None
    if record is None:
        raise HTTPException(404, "import not found")  # 404, not 403, like every other resource
    return record


def _lite(ids: list[str]) -> tuple[list[str], bool]:
    return ids[:MAX_IDS_RETURNED], len(ids) > MAX_IDS_RETURNED


def _view(s: Session, record: ImportRecord, org: str) -> ImportView:
    test = repo.get_engagement_test(s, record.test_id, org)
    reopened: list[str] = []
    closed: list[str] = []
    detached: list[str] = []
    held: list[str] = []
    counts: ImportCounts | None = None
    if record.status in ("applied", "reverted", "duplicate"):
        counts = ImportCounts(
            new=record.new_count,
            unchanged=record.unchanged_count,
            reopened=record.reopened_count,
            closed=record.closed_count,
            detached=record.detached_count,
            held=record.held_count,
        )
        held = list(record.held_issue_ids or [])
        for change in record.changes or []:
            if change.get("after_state") == "reintroduced":
                reopened.append(change["issue_id"])
            elif change.get("after_state") == "fixed" and not change.get("created"):
                closed.append(change["issue_id"])
    elif record.status == "previewed" and record.preview:
        counts = ImportCounts(**record.preview["counts"])
        reopened = list(record.preview.get("reopened_issue_ids", []))
        closed = list(record.preview.get("closed_issue_ids", []))
        detached = list(record.preview.get("detached_issue_ids", []))
        held = list(record.preview.get("held_issue_ids", []))
    (reopened, t1), (closed, t2), (detached, t3) = _lite(reopened), _lite(closed), _lite(detached)
    held, t4 = _lite(held)
    return ImportView(
        id=record.id,
        status=record.status,
        mode=record.mode,
        parser=record.parser,
        file_name=record.file_name,
        test_id=record.test_id,
        engagement_id=test.engagement_id if test else None,
        counts=counts,
        reopened_issue_ids=reopened,
        closed_issue_ids=closed,
        detached_issue_ids=detached,
        held_issue_ids=held,
        ids_truncated=t1 or t2 or t3 or t4,
        warnings=[str(w) for w in record.warnings or []],
        error=record.error,
        close_missing=record.close_missing,
        scope=record.scope,
        dedup_complete=record.status not in ("queued", "processing"),
        created_at=record.created_at,
        reverted_at=record.reverted_at,
    )


def _dispatch(st: AppState, s: Session, record: ImportRecord) -> None:
    """Queue the job; if the queue is unreachable, fail the import instead of orphaning it."""
    try:
        st.enqueue_import(record.id, record.org_id)
    except Exception as exc:  # noqa: BLE001 - broker errors vary by transport
        log.exception("could not enqueue import %s", record.id)
        record.status, record.error = "failed", "could not queue the import; try again shortly"
        if record.upload_path:
            Path(record.upload_path).unlink(missing_ok=True)
            record.upload_path = None
        s.commit()
        raise HTTPException(503, "import queue unavailable; the import was not started") from exc


async def _store_upload(
    upload: UploadFile, dest_dir: Path, max_bytes: int
) -> tuple[Path, str, int, bytes]:
    """Stream the upload to a server-named file, hashing as it goes. Returns the path, sha256, size
    and the first bytes (for format detection). The client's filename is never used as a path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / uuid.uuid4().hex
    digest, size, head = hashlib.sha256(), 0, b""
    try:
        with open(dest, "wb") as out:
            while chunk := await upload.read(1024 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(413, "the file exceeds the maximum upload size")
                if len(head) < SNIFF_BYTES:
                    head += chunk[: SNIFF_BYTES - len(head)]
                digest.update(chunk)
                out.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return dest, digest.hexdigest(), size, head


def _choose_parser(
    s: Session, org: str, requested: str | None, head: bytes
) -> tuple[str, str, float | None]:
    """`(parser name, label, confidence)`. A saved mapping (`universal:<id>`, ADR-0043) is only
    ever used when named: it is suggested when nothing built-in recognises the file, never picked.
    """
    if requested:
        if mapper.is_mapped(requested):
            row = mapper.get_mapping(s, requested[len(mapper.PREFIX) :], org)
            if row is None:
                raise HTTPException(422, f"unknown mapping {requested!r}")
            return requested, row.name, None
        if requested not in PARSERS:
            raise HTTPException(422, f"unknown parser {requested!r}; available: {sorted(PARSERS)}")
        return requested, PARSERS[requested].label or requested, None
    found = detect(head)
    if found and found[0][1] >= CONFIDENT:
        return found[0][0].name, found[0][0].label or found[0][0].name, found[0][1]
    detected = [{"parser": p.name, "label": p.label or p.name, "confidence": round(c, 2)}
                for p, c in found]  # fmt: skip
    for row in mapper.list_mappings(s, org):
        try:
            confidence = mapper.parser_for(row).sniff(head)
        except ValueError:
            continue  # a mapping saved under rules that have since tightened: never suggested
        if confidence >= 0.5:
            detected.append({"parser": mapper.parser_name(row.id), "label": row.name,
                             "confidence": confidence})  # fmt: skip
    detected.sort(key=lambda d: -float(d["confidence"]))  # type: ignore[arg-type]
    raise HTTPException(
        422,
        detail={
            "message": "could not identify the file's format with confidence; pass `parser`",
            "detected": detected,
            "available": sorted(PARSERS),
        },
    )


def _resolve_test(
    s: Session,
    org: str,
    *,
    test_id: str | None,
    project: str | None,
    engagement: str | None,
    engagement_type: str,
    engagement_name: str | None,
    test_name: str | None,
    default_test_name: str,
    parser: str,
) -> str:
    """Which Test this upload goes into: one named by id, or found/created from project + engagement
    + test name. Every lookup is org-scoped, so another org's ids read as "not found"."""
    if test_id is not None:
        if not _UUID.match(test_id) or repo.get_engagement_test(s, test_id, org) is None:
            raise HTTPException(404, "test not found")
        return test_id
    if not project or not _UUID.match(project) or repo.get_asset(s, project, org_id=org) is None:
        raise HTTPException(404, "project not found")
    if engagement is not None:
        eng = repo.get_engagement(s, engagement, org) if _UUID.match(engagement) else None
        if eng is None or eng.asset_id != project:
            raise HTTPException(404, "engagement not found")
    elif engagement_type == "import":
        eng = repo.get_or_create_import_engagement(s, asset_id=project, org_id=org)
    elif engagement_type == "assessment":
        if not engagement_name:
            raise HTTPException(422, "engagement_name is required to create an assessment")
        eng = repo.create_engagement(
            s,
            org_id=org,
            asset_id=project,
            name=engagement_name[:300],
            engagement_type="assessment",
        )
    else:
        raise HTTPException(422, "engagement_type must be 'import' or 'assessment'")
    name = (test_name or default_test_name).strip()[:200]
    if not name:
        raise HTTPException(422, "test name must not be empty")
    return repo.get_or_create_engagement_test(
        s, org_id=org, engagement_id=eng.id, name=name, parser=parser
    ).id


def register_ingest_routes(app: FastAPI) -> None:
    @app.post(
        "/v2/ingest",
        status_code=202,
        response_model=ImportCreated,
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    async def ingest(
        response: Response,
        file: UploadFile = File(..., description="The report."),
        project: str | None = Form(None, description="Project (asset) id; or give `test_id`."),
        engagement: str | None = Form(None, description="Engagement id within the project."),
        engagement_type: str = Form(
            "import", description="'import' (the project's standing one) or 'assessment' (new)."
        ),
        engagement_name: str | None = Form(None, description="Name for a new assessment."),
        test: str | None = Form(None, description="Test name; defaults to the parser's name."),
        test_id: str | None = Form(None, description="An existing Test; overrides the above."),
        parser: str | None = Form(
            None,
            description="Skip detection; see GET /v2/parsers, or `universal:<id>` for a saved "
            "mapping (GET /v2/mappings).",
        ),
        source: str = Form("upload"),
        close_missing: bool = Form(True, description="Close Issues this file no longer lists."),
        scope: str = Form("test", description="'test' (default) or 'engagement'."),
        wait_for_dedup: bool = Form(
            False,
            description="Hold the response until the import is matched to Issues (its "
            f"`dedup_complete`), up to {WAIT_SECONDS} s; the 202 then carries its resting status. "
            "Otherwise poll GET /v2/imports/{id}.",
        ),
        preview: bool = Form(False, description="Compute the counts, save nothing, keep the file."),
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> ImportCreated:
        if source not in SOURCES:
            raise HTTPException(
                422, f"source {source!r} is not supported yet; use one of {SOURCES}"
            )
        if scope not in SCOPES:
            raise HTTPException(422, f"scope must be one of {SCOPES}")
        path, digest, size, head = await _store_upload(
            file, st.settings.ingest_dir, st.settings.max_upload_bytes
        )
        try:
            if size == 0:
                raise HTTPException(422, "the file is empty")
            parser_name, label, confidence = _choose_parser(s, org, parser, head)
            test_id_resolved = _resolve_test(
                s, org,
                test_id=test_id, project=project, engagement=engagement,
                engagement_type=engagement_type, engagement_name=engagement_name,
                test_name=test, default_test_name=label, parser=parser_name,
            )  # fmt: skip
            latest = repo.latest_applied_import(s, test_id_resolved, org)
            if not preview and latest is not None and latest.file_digest == digest:
                path.unlink(missing_ok=True)
                response.status_code = 200  # nothing queued: the same file is already the latest
                return ImportCreated(
                    import_id=latest.id, status=latest.status, parser=latest.parser,
                    confidence=confidence, test_id=test_id_resolved, duplicate=True,
                )  # fmt: skip
            record = repo.add_import_record(
                s,
                org_id=org,
                test_id=test_id_resolved,
                scan_id=None,
                parser=parser_name,
                file_digest=digest,
                file_name=Path(file.filename or "").name[:300] or None,
                size_bytes=size,
                close_missing=close_missing,
                scope=scope,
                created_by=auth.actor,
                status="queued",
                mode="preview" if preview else "apply",
                upload_path=str(path),
            )
            s.commit()
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        _dispatch(st, s, record)
        if wait_for_dedup:
            for _ in range(WAIT_SECONDS * 4):
                s.refresh(record)
                if record.status not in ("queued", "processing"):
                    break
                await asyncio.sleep(0.25)
        return ImportCreated(
            import_id=record.id, status=record.status, parser=parser_name,
            confidence=confidence, test_id=test_id_resolved,
        )  # fmt: skip

    @app.get(
        "/v2/imports/{import_id}",
        response_model=ImportView,
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def get_import(
        import_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ImportView:
        return _view(s, _get_record(s, import_id, org), org)

    @app.post(
        "/v2/imports/{import_id}/confirm",
        status_code=202,
        response_model=ImportView,
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def confirm_import(
        import_id: str,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ImportView:
        record = _get_record(s, import_id, org)
        if record.status != "previewed":
            raise HTTPException(409, f"only a previewed import can be confirmed ({record.status})")
        record.status, record.mode = "queued", "apply"
        s.commit()
        _dispatch(st, s, record)
        return _view(s, record, org)

    @app.post(
        "/v2/imports/{import_id}/cancel",
        response_model=ImportView,
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def cancel_import(
        import_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ImportView:
        record = _get_record(s, import_id, org)
        if record.status != "previewed":
            raise HTTPException(409, f"only a previewed import can be cancelled ({record.status})")
        if record.upload_path:
            Path(record.upload_path).unlink(missing_ok=True)
        record.status, record.upload_path = "cancelled", None
        s.commit()
        return _view(s, record, org)

    @app.post(
        "/v2/imports/{import_id}/revert",
        response_model=RevertView,
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def revert_import(
        import_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> RevertView:
        record = _get_record(s, import_id, org)
        latest = repo.latest_applied_import(s, record.test_id, org)
        if record.status != "applied" or latest is None or latest.id != record.id:
            raise HTTPException(
                409, "only the most recent applied import into a test can be reverted"
            )
        try:
            out = service.revert_latest_import(s, org_id=org, test_id=record.test_id)
        except service.ImportRequestError as exc:
            raise HTTPException(409, str(exc)) from exc
        if out.inventory_changed:
            from core.advisories.impact import match_after_record

            match_after_record(s, org, out.inventory_changed, [out.asset_id or ""])
        return RevertView(
            import_id=record.id, status=out.record.status,
            restored=out.restored, deleted=out.deleted, skipped=out.skipped,
        )  # fmt: skip

    @app.get(
        "/v2/tests/{test_id}/imports",
        response_model=list[ImportView],
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def list_test_imports(
        test_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[ImportView]:
        if not _UUID.match(test_id) or repo.get_engagement_test(s, test_id, org) is None:
            raise HTTPException(404, "test not found")
        return [_view(s, r, org) for r in repo.list_import_records(s, test_id, org)]

    @app.get(
        "/v2/projects/{project_id}/tests",
        response_model=list[ProjectTest],
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def list_project_tests(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[ProjectTest]:
        if not _UUID.match(project_id) or repo.get_asset(s, project_id, org_id=org) is None:
            raise HTTPException(404, "project not found")
        out = []
        for test, eng in repo.list_tests_for_asset(s, project_id, org):
            latest = repo.latest_applied_import(s, test.id, org)
            out.append(
                ProjectTest(
                    id=test.id,
                    name=test.name,
                    parser=test.parser,
                    engagement_id=eng.id,
                    engagement_name=eng.name,
                    engagement_type=eng.engagement_type,
                    last_import=(
                        ImportSummary(
                            id=latest.id,
                            status=latest.status,
                            created_at=latest.created_at,
                            counts=ImportCounts(
                                new=latest.new_count,
                                unchanged=latest.unchanged_count,
                                reopened=latest.reopened_count,
                                closed=latest.closed_count,
                                detached=latest.detached_count,
                                held=latest.held_count,
                            ),
                        )
                        if latest is not None
                        else None
                    ),
                )
            )
        return out

    @app.get(
        "/v2/parsers",
        response_model=list[ParserInfo],
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def list_parsers() -> list[ParserInfo]:
        return [
            ParserInfo(
                name=p.name, label=p.label or p.name,
                formats=sorted(p.formats), categories=sorted(p.categories),
                recommended_dedup=p.default_dedup,
            )
            for p in PARSERS.values()
        ]  # fmt: skip
