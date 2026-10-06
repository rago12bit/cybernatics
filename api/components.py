"""Component inventory API (plan §46.1): "where do we use this?"

    GET /v2/components?purl=pkg:maven/org.apache.logging.log4j/log4j-core&version=<2.17.1
    GET /v2/libraries?q=log4j&ecosystem=maven

`version` is one or more conditions joined by commas (`>=2.0,<2.17.1`), compared the way the
library's ecosystem orders versions; a purl that carries a version (`pkg:npm/lodash@4.17.20`)
means exactly that version. Reading is `scans:read`.
"""

from __future__ import annotations

import re
import time
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import current_org, db, require_scope
from core import inventory
from core.persistence import repo

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class LibraryOut(BaseModel):
    id: str
    ecosystem: str
    name: str
    purl: str


class LibrarySummary(LibraryOut):
    projects: int
    versions: int


class VersionOut(BaseModel):
    version: str
    projects: int
    matches: bool | None  # None: the ecosystem cannot read this version, so it was not compared


class UseOut(BaseModel):
    project_id: str
    project: str
    portfolio: str | None
    version: str
    relation: str
    paths: list[str]
    reachable: bool | None
    reachable_reason: str
    exposure: str
    source: str
    scan_id: str
    seen_at: datetime


class SummaryOut(BaseModel):
    projects: int
    portfolios: int
    internet_facing: int
    exposure_unset: int
    imported_by_app: int
    direct: int
    versions: int


class ComponentSearchOut(BaseModel):
    library: LibraryOut | None
    constraint: str | None
    summary: SummaryOut
    versions: list[VersionOut]
    uses: list[UseOut]
    uncomparable: list[str]
    truncated: bool
    elapsed_ms: float


def register_component_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/components",
        response_model=ComponentSearchOut,
        tags=["components"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def search_components(
        purl: str = Query(max_length=2000),
        version: str | None = Query(default=None, max_length=500),
        project_id: str | None = Query(default=None),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> ComponentSearchOut:
        started = time.perf_counter()
        if project_id is not None and (
            not _UUID.match(project_id) or repo.get_asset(s, project_id, org_id=org) is None
        ):
            raise HTTPException(404, "project not found")
        try:
            r = inventory.search(s, org, purl=purl, constraint=version, project_id=project_id)
        except inventory.SearchError as exc:
            raise HTTPException(422, {"field": exc.field, "message": str(exc)}) from exc
        return ComponentSearchOut(
            library=LibraryOut(**r.library) if r.library else None,
            constraint=r.constraint,
            summary=SummaryOut(**r.summary()),
            versions=[VersionOut(**v) for v in r.versions],
            uses=[UseOut(**u.to_dict()) for u in r.uses],
            uncomparable=r.uncomparable,
            truncated=r.truncated,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 1),
        )

    @app.get(
        "/v2/libraries",
        response_model=list[LibrarySummary],
        tags=["components"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def list_libraries(
        q: str = Query(default="", max_length=300),
        ecosystem: str | None = Query(default=None, max_length=32),
        limit: int = Query(default=20, ge=1, le=100),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[LibrarySummary]:
        rows = inventory.libraries(s, org, q=q, ecosystem=ecosystem, limit=limit)
        return [LibrarySummary(**r) for r in rows]
