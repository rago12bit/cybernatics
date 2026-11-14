"""The universal mapper API (Week 59, plan §42.4, ADR-0043).

    POST /v2/mappings/analyze   a sample's shape, and a draft mapping (model, else name matching)
    POST /v2/mappings/preview   what a mapping makes of a sample: the issues it would produce
    POST /v2/mappings           save a mapping (the next version, if the name exists)
    GET  /v2/mappings           every mapping, latest version
    GET  /v2/mappings/{id}      one version, with the mapping's history

A saved mapping is imported like any parser: `POST /v2/ingest` with `parser=universal:<id>`.

Every read of an uploaded sample -- describing it, previewing a mapping on it -- happens in the
parser sandbox (when it is on), exactly like an import, because a sample is just as untrusted. The
model sees the description of a sample, never the sample, and only drafts: saving needs a person,
and an import never touches the model.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.imports import mapper
from core.imports.jobs import parse_file
from core.imports.parsers.analyze import MAX_SAMPLE_BYTES, analyze
from core.imports.parsers.base import ParseLimits
from core.imports.parsers.sandbox import analyze_in_sandbox
from core.imports.parsers.universal import FIELDS, MappingError, MappingSpec, UniversalParser
from core.llm import budget as llm_budget
from core.persistence import repo
from core.persistence.models import IngestMapping

log = logging.getLogger(__name__)

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PREVIEW_ROWS = 50


class FieldInfo(BaseModel):
    path: str
    examples: list[str]
    filled: int


class Candidate(BaseModel):
    records: str | None = Field(description="Where the records are; null for a CSV file.")
    count: int
    fields: list[FieldInfo]


class Analysis(BaseModel):
    format: str | None
    candidates: list[Candidate]
    error: str | None


class ProposalView(BaseModel):
    spec: dict[str, Any] = Field(description="A draft: review every field before saving.")
    proposed_by: str = Field(description="'heuristic' (name matching) or 'model:<name>'.")
    notes: list[str]


class AnalyzeResult(BaseModel):
    analysis: Analysis
    proposal: ProposalView | None
    sample_digest: str
    suggested_source: str
    model_available: bool
    fields: list[str] = Field(description="Every field a mapping can fill.")


class PreviewIssue(BaseModel):
    title: str
    severity: str
    native_severity: str | None
    category: str
    location: str
    cwe: list[str]
    cve: list[str]
    rule: str | None


class PreviewResult(BaseModel):
    total: int
    issues: list[PreviewIssue] = Field(description=f"The first {PREVIEW_ROWS}.")
    by_severity: dict[str, int]
    warnings: list[str]
    error: str | None


class MappingIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    spec: dict[str, Any]
    proposed_by: str | None = Field(default=None, max_length=120)
    sample_digest: str | None = Field(default=None, max_length=64)


class MappingVersion(BaseModel):
    id: str
    version: int
    created_at: datetime
    created_by: str | None


class MappingView(BaseModel):
    id: str
    parser: str = Field(description="What to pass as `parser` to POST /v2/ingest.")
    name: str
    version: int
    source: str
    format: str
    spec: dict[str, Any]
    proposed_by: str | None
    created_at: datetime
    created_by: str | None
    versions: list[MappingVersion] = []


def _view(row: IngestMapping, history: list[IngestMapping] | None = None) -> MappingView:
    return MappingView(
        id=row.id,
        parser=mapper.parser_name(row.id),
        name=row.name,
        version=row.version,
        source=row.source,
        format=row.format,
        spec=dict(row.spec),
        proposed_by=row.proposed_by,
        created_at=row.created_at,
        created_by=row.created_by,
        versions=[
            MappingVersion(id=h.id, version=h.version, created_at=h.created_at,
                           created_by=h.created_by)
            for h in history or []
        ],  # fmt: skip
    )


def _store_sample(upload: UploadFile, dest_dir: Path) -> tuple[Path, str]:
    """Copy a sample to a server-named file, refusing more than MAX_SAMPLE_BYTES."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"sample-{uuid.uuid4().hex}"
    digest, size = hashlib.sha256(), 0
    try:
        with open(dest, "wb") as out:
            while chunk := upload.file.read(256 * 1024):
                size += len(chunk)
                if size > MAX_SAMPLE_BYTES:
                    raise HTTPException(
                        413, "a sample is at most 2 MB; upload the first part of the report"
                    )
                digest.update(chunk)
                out.write(chunk)
        if size == 0:
            raise HTTPException(422, "the sample is empty")
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return dest, digest.hexdigest()


def _analyze(st: AppState, path: Path) -> dict[str, Any]:
    limits = ParseLimits(max_bytes=MAX_SAMPLE_BYTES, max_seconds=20.0)
    if st.settings.ingest_sandbox:
        return analyze_in_sandbox(path, limits)
    with path.open("rb") as fh:  # in-process: tests and Docker-less local development only
        return analyze(fh, limits)


def _spec(raw: Any) -> MappingSpec:
    try:
        return MappingSpec.from_dict(raw)
    except MappingError as exc:
        raise HTTPException(422, str(exc)) from exc


def register_mapping_routes(app: FastAPI) -> None:
    @app.post(
        "/v2/mappings/analyze",
        response_model=AnalyzeResult,
        tags=["mappings"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    # Not `async def` (nor `preview_mapping` below): parsing the sample runs a container, and the
    # draft may ask a model -- up to twenty seconds each, which on the event loop is twenty
    # seconds of every other request waiting. A plain `def` runs in a worker thread.
    def analyze_sample(
        file: UploadFile = File(..., description="A sample of the report, at most 2 MB."),
        use_model: bool = Form(True, description="Ask the model for the draft when one is set up."),
        source: str | None = Form(None, description="The tool's name, if you know it."),
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> AnalyzeResult:
        path, digest = _store_sample(file, st.settings.ingest_dir / "samples")
        try:
            analysis = _analyze(st, path)
        finally:
            path.unlink(missing_ok=True)
        suggested = (source or "").strip().lower() or mapper.suggest_source(file.filename)
        proposal: mapper.Proposal | None = None
        model_note: str | None = None
        if analysis.get("candidates"):
            if use_model and st.llm_mapper is not None:
                try:
                    llm_budget.check_org(s, org, st.llm_budget)
                    proposal = mapper.propose_with_model(analysis, st.llm_mapper, source=suggested)
                    if proposal is None:
                        model_note = "The model's draft could not be used, so this draft matches field names instead."  # noqa: E501
                    else:
                        llm_budget.record_org(s, org, proposal.tokens_used)
                except llm_budget.BudgetExceeded as exc:
                    model_note = f"{exc}. This draft matches field names instead."
            if proposal is None:
                proposal = mapper.propose_heuristic(analysis, source=suggested)
                if model_note:
                    proposal.notes.insert(0, model_note)
        return AnalyzeResult(
            analysis=Analysis(**analysis),
            proposal=(
                ProposalView(
                    spec=proposal.spec, proposed_by=proposal.proposed_by, notes=proposal.notes
                )
                if proposal
                else None
            ),
            sample_digest=digest,
            suggested_source=suggested,
            model_available=st.llm_mapper is not None,
            fields=list(FIELDS),
        )

    @app.post(
        "/v2/mappings/preview",
        response_model=PreviewResult,
        tags=["mappings"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def preview_mapping(
        file: UploadFile = File(..., description="The sample, at most 2 MB."),
        spec: str = Form(..., description="The mapping, as JSON."),
        st: AppState = Depends(state),
    ) -> PreviewResult:
        try:
            raw = json.loads(spec)
        except ValueError as exc:
            raise HTTPException(422, "spec is not valid JSON") from exc
        mapping = _spec(raw)
        path, _ = _store_sample(file, st.settings.ingest_dir / "samples")
        try:
            result = parse_file(
                path,
                "universal:preview",
                st.settings,
                parser=UniversalParser(mapping, "universal:preview"),
                mapping=mapping.to_dict(),
                max_bytes=MAX_SAMPLE_BYTES,
            )
        finally:
            path.unlink(missing_ok=True)
        counts = Counter(f.scoring.normalized_severity.value for f in result.findings)
        issues = []
        for f in result.findings[:PREVIEW_ROWS]:
            loc = f.location
            if loc.host or loc.route:
                where = f"{loc.host}{loc.route}"
            elif f.package:
                where = f"{f.package.name}@{f.package.version}"
            else:
                where = f"{loc.path}:{loc.start_line}"
            rules = [r for rs in f.evidence.rule_ids.values() for r in rs]
            issues.append(
                PreviewIssue(
                    title=f.title,
                    severity=f.scoring.normalized_severity.value,
                    native_severity=next(iter(f.scoring.native_severity.values()), None) or None,
                    category=f.taxonomy.category.value,
                    location=where,
                    cwe=list(f.taxonomy.cwe),
                    cve=list(f.taxonomy.cve),
                    rule=rules[0] if rules else None,
                )
            )
        return PreviewResult(
            total=len(result.findings),
            issues=issues,
            by_severity=dict(counts),
            warnings=result.warnings,
            error=result.error,
        )

    @app.post(
        "/v2/mappings",
        status_code=201,
        response_model=MappingView,
        tags=["mappings"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def save_mapping(
        body: MappingIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> MappingView:
        spec = _spec(body.spec)
        try:
            row = mapper.save_mapping(
                s,
                org_id=org,
                name=body.name,
                spec=spec,
                proposed_by=body.proposed_by,
                sample_digest=body.sample_digest,
                created_by=auth.actor,
            )
            s.commit()
        except MappingError as exc:
            s.rollback()
            raise HTTPException(422, str(exc)) from exc
        repo.append_audit_entry(
            s,
            actor=auth.actor,
            action="mapping.saved",
            target=f"mapping:{row.id}",
            payload={"org_id": org, "name": row.name, "version": row.version, "spec": row.spec},
        )
        return _view(row, mapper.versions(s, org, row.name))

    @app.get(
        "/v2/mappings",
        response_model=list[MappingView],
        tags=["mappings"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def list_all(s: Session = Depends(db), org: str = Depends(current_org)) -> list[MappingView]:
        return [_view(r) for r in mapper.list_mappings(s, org)]

    @app.get(
        "/v2/mappings/{mapping_id}",
        response_model=MappingView,
        tags=["mappings"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def get_one(
        mapping_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> MappingView:
        row = mapper.get_mapping(s, mapping_id, org) if _UUID.match(mapping_id) else None
        if row is None:
            raise HTTPException(404, "mapping not found")
        return _view(row, mapper.versions(s, org, row.name))
