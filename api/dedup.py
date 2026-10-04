"""The deduplication settings API (Week 58, plan §42.3, ADR-0042).

    GET  /v2/projects/{id}/dedup           each source of the project, its strategy and its history
    POST /v2/projects/{id}/dedup/preview   the dry run: what a change would merge and split
    POST /v2/projects/{id}/dedup/apply     make exactly the previewed change (needs its digest)

A change rewrites Issue identity, so applying it is `ingest:write` -- the same permission as the
imports that can close Issues -- and the preview is `ingest:read`. Nothing changes until `apply`,
and `apply` refuses a preview the project has moved away from (409): the digest in the preview is
what it checks.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core.dedup import service
from core.dedup.settings import current_settings, history
from core.dedup.strategies import DEFAULT, FIELDS, RECOMMENDED, STRATEGIES, describe
from core.imports.parsers import PARSERS
from core.persistence import repo
from core.persistence.models import FindingRow, Scan

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class StrategyInfo(BaseModel):
    name: str
    description: str


class SourceSetting(BaseModel):
    source: str
    strategy: str
    fields: list[str]
    version: int = Field(description="0 until someone chooses: the default applies.")
    recommended: str | None = Field(description="What suits this source, when we know it.")
    issues_seen: int = Field(description="Distinct Issues this source has reported (approximate).")
    changed_at: datetime | None
    changed_by: str | None
    effect: dict[str, Any]


class DedupOverview(BaseModel):
    default: str
    strategies: list[StrategyInfo]
    fields: list[str]
    sources: list[SourceSetting]


class ChangeRequest(BaseModel):
    source: str = Field(min_length=1, max_length=60)
    strategy: str
    fields: list[str] = Field(default_factory=list)


class ApplyRequest(ChangeRequest):
    digest: str = Field(description="The `digest` of the preview being confirmed.")
    note: str | None = Field(default=None, max_length=500)


class HistoryEntry(BaseModel):
    source: str
    version: int
    strategy: str
    fields: list[str]
    note: str | None
    created_by: str | None
    created_at: datetime
    effect: dict[str, Any]


class AppliedView(BaseModel):
    source: str
    version: int
    effect: dict[str, Any]
    summary: str


def _project(s: Session, org: str, project_id: str) -> str:
    if not _UUID.match(project_id) or repo.get_asset(s, project_id, org_id=org) is None:
        raise HTTPException(404, "project not found")
    return project_id


def _sources(s: Session, asset_id: str) -> dict[str, int]:
    """The tools that have reported findings in this project, with how many Issues each reported."""
    counts: dict[str, int] = {}
    q = (
        select(FindingRow.tools, func.count(func.distinct(FindingRow.issue_id)))
        .join(Scan, Scan.id == FindingRow.scan_id)
        .where(Scan.asset_id == asset_id)
        .group_by(FindingRow.tools)
    )
    for tools, n in s.execute(q):
        first = tools[0] if tools else "unknown"
        counts[first] = counts.get(first, 0) + int(n)
    return counts


def _validated(body: ChangeRequest) -> tuple[str, ...]:
    from core.dedup.strategies import validate

    try:
        return validate(body.strategy, tuple(body.fields))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def register_dedup_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/projects/{project_id}/dedup",
        response_model=DedupOverview,
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def dedup_overview(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> DedupOverview:
        asset = _project(s, org, project_id)
        settings = current_settings(s, asset)
        seen = _sources(s, asset)
        latest = (
            {h.source: h for h in history(s, asset) if h.version == settings[h.source].version}
            if settings
            else {}
        )
        names = sorted(set(seen) | set(settings))
        rows = []
        for name in names:
            now = settings.get(name)
            row = latest.get(name)
            rows.append(
                SourceSetting(
                    source=name,
                    strategy=now.strategy if now else DEFAULT,
                    fields=list(now.fields) if now else [],
                    version=now.version if now else 0,
                    recommended=_recommended(name),
                    issues_seen=seen.get(name, 0),
                    changed_at=row.created_at if row else None,
                    changed_by=row.created_by if row else None,
                    effect=dict(row.effect) if row else {},
                )
            )
        return DedupOverview(
            default=DEFAULT,
            strategies=[StrategyInfo(name=n, description=describe(n)) for n in STRATEGIES],
            fields=list(FIELDS),
            sources=rows,
        )

    @app.get(
        "/v2/projects/{project_id}/dedup/history",
        response_model=list[HistoryEntry],
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def dedup_history(
        project_id: str,
        source: str | None = None,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[HistoryEntry]:
        asset = _project(s, org, project_id)
        return [
            HistoryEntry(
                source=h.source,
                version=h.version,
                strategy=h.strategy,
                fields=list(h.fields or []),
                note=h.note,
                created_by=h.created_by,
                created_at=h.created_at,
                effect=dict(h.effect or {}),
            )
            for h in history(s, asset, source)
        ]

    @app.post(
        "/v2/projects/{project_id}/dedup/preview",
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def dedup_preview(
        project_id: str,
        body: ChangeRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> dict[str, Any]:
        asset = _project(s, org, project_id)
        fields = _validated(body)
        try:
            return service.preview_change(
                s,
                org_id=org,
                asset_id=asset,
                source=body.source,
                strategy=body.strategy,
                fields=fields,
            ).to_dict()
        except service.DedupError as exc:
            raise HTTPException(404, str(exc)) from exc

    @app.post(
        "/v2/projects/{project_id}/dedup/apply",
        response_model=AppliedView,
        tags=["ingest"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def dedup_apply(
        project_id: str,
        body: ApplyRequest,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> AppliedView:
        asset = _project(s, org, project_id)
        fields = _validated(body)
        try:
            done = service.apply_change(
                s, org_id=org, asset_id=asset, source=body.source, strategy=body.strategy,
                fields=fields, expected_digest=body.digest, created_by=auth.actor, note=body.note,
            )  # fmt: skip
        except service.StalePlan as exc:
            raise HTTPException(409, str(exc)) from exc
        except service.DedupError as exc:
            raise HTTPException(422, str(exc)) from exc
        return AppliedView(
            source=body.source, version=done.version, effect=done.effect,
            summary=done.preview.to_dict()["summary"],
        )  # fmt: skip


def _recommended(source: str) -> str | None:
    parser = PARSERS.get(source)
    if parser is not None:
        return parser.default_dedup
    return None


__all__ = ["RECOMMENDED", "register_dedup_routes"]
