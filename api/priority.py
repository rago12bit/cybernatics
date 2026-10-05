"""The priority policy API (Week 63, plan §44.3).

    GET  /v2/projects/{id}/priority           the policy in force (or none: the v2 score), the
                                              factors, the recomputation's progress, the history
    POST /v2/projects/{id}/priority/preview   how the open queue's top 50 would reorder under
                                              proposed weights and context; saves nothing
    PUT  /v2/projects/{id}/priority           save a new version (audit-logged) and recompute every
                                              Issue in the background; 409 while the last change is
                                              still being applied

Reading and previewing are `scans:read`; saving is `scans:write`, the same permission as the SLA
policy. Each Issue's own priority, with its factors and weights, is on the issue endpoints
(`issue.priority`), and the issues table sorts by it and filters by band (`?priority=P1`).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope, state
from core.persistence import repo
from core.priority import service
from core.priority.engine import (
    BANDS,
    CRITICALITY,
    DATA_SENSITIVITY,
    FACTORS,
    MAX_WEIGHT,
    STARTER,
    V2_WEIGHTS,
    PolicyError,
)
from core.tenancy import scoped_sessions

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

PRIORITY_LOCKED = {
    "code": "PRIORITY_RECOMPUTING",
    "message": "The last change is still being applied to every issue. Try again when it finishes.",
}


class FactorOut(BaseModel):
    key: str
    label: str
    description: str


class ContextOut(BaseModel):
    internet_facing: bool | None = None
    data_sensitivity: str | None = None
    criticality: str | None = None


class Recompute(BaseModel):
    status: str = Field(description="pending, running, done, failed, or superseded.")
    total: int
    processed: int
    changed: int = Field(description="Issues whose priority band moved.")
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None


class PolicyVersion(BaseModel):
    version: int
    weights: dict[str, float]
    context: ContextOut
    note: str | None
    changed_at: datetime
    changed_by: str | None
    recompute: Recompute


class PriorityOverview(BaseModel):
    version: int = Field(description="0 until someone saves a policy: priority is the v2 score.")
    weights: dict[str, float] = Field(description="In force; with no policy, v2's equivalents.")
    context: ContextOut
    starter: dict[str, float]
    max_weight: float
    factors: list[FactorOut]
    bands: dict[str, int] = Field(description="Each band's lowest score.")
    sensitivity_levels: list[str]
    criticality_levels: list[str]
    locked: bool = Field(description="True while a recomputation runs; saving is refused.")
    recompute: Recompute | None
    history: list[PolicyVersion]


class PolicyIn(BaseModel):
    weights: dict[str, Any]
    context: dict[str, Any] | None = None
    note: str | None = Field(default=None, max_length=500)


class Rank(BaseModel):
    rank: int | None
    score: int | None
    band: str | None


class PreviewRow(BaseModel):
    issue_id: str
    title: str
    severity: str
    path: str
    before: Rank | None
    after: Rank | None


class PreviewOut(BaseModel):
    open_issues: int
    current_version: int
    moved: int = Field(description="How many of the new top 50 change rank (or are new to it).")
    top: list[PreviewRow]
    dropped: list[PreviewRow] = Field(description="In the top 50 now, not under these weights.")
    bands_before: dict[str, int]
    bands_after: dict[str, int]


def _asset(s: Session, asset_id: str, org: str) -> Any:
    asset = repo.get_asset(s, asset_id, org_id=org) if _UUID.match(asset_id) else None
    if asset is None:
        raise HTTPException(404, "project not found")
    return asset


def _recompute(row: Any) -> Recompute:
    return Recompute(
        status=row.status, total=row.total, processed=row.processed, changed=row.changed,
        started_at=row.started_at, finished_at=row.finished_at, error=row.error,
    )  # fmt: skip


def _overview(s: Session, asset_id: str) -> PriorityOverview:
    row = service.current(s, asset_id)
    return PriorityOverview(
        version=row.version if row else 0,
        weights=dict(row.weights) if row else dict(V2_WEIGHTS),
        context=ContextOut(**(row.context if row else {})),
        starter=dict(STARTER),
        max_weight=MAX_WEIGHT,
        factors=[FactorOut(key=f.key, label=f.label, description=f.description) for f in FACTORS],
        bands=dict(BANDS),
        sensitivity_levels=list(DATA_SENSITIVITY),
        criticality_levels=list(CRITICALITY),
        locked=service.locked(row),
        recompute=_recompute(row) if row else None,
        history=[
            PolicyVersion(
                version=h.version, weights=h.weights, context=ContextOut(**h.context), note=h.note,
                changed_at=h.created_at, changed_by=h.created_by, recompute=_recompute(h),
            )  # fmt: skip
            for h in service.history(s, asset_id)
        ],
    )


def _bad(exc: PolicyError) -> HTTPException:
    return HTTPException(422, {"field": exc.field, "message": str(exc)})


def _run_here(factory: Any, org: str, policy_id: str) -> Callable[[], None]:
    def run() -> None:
        with scoped_sessions(factory, org)() as s:
            service.recompute(s, policy_id)

    return run


def register_priority_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/projects/{project_id}/priority",
        response_model=PriorityOverview,
        tags=["priority"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_priority(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> PriorityOverview:
        return _overview(s, _asset(s, project_id, org).id)

    @app.post(
        "/v2/projects/{project_id}/priority/preview",
        response_model=PreviewOut,
        tags=["priority"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def preview_priority(
        project_id: str, body: PolicyIn, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        asset = _asset(s, project_id, org)
        try:
            return service.preview(s, asset.id, body.weights, body.context)
        except PolicyError as exc:
            raise _bad(exc) from exc

    @app.put(
        "/v2/projects/{project_id}/priority",
        response_model=PriorityOverview,
        status_code=202,
        tags=["priority"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def put_priority(
        project_id: str,
        body: PolicyIn,
        request: Request,
        background: BackgroundTasks,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> PriorityOverview:
        """Accepted, not finished: every Issue is re-ranked in the background, and the policy stays
        locked until that is done. Poll the GET for progress."""
        asset = _asset(s, project_id, org)
        try:
            row = service.save(
                s, org_id=org, asset_id=asset.id, weights=body.weights, context=body.context,
                note=body.note, actor=auth.actor,
            )  # fmt: skip
        except PolicyError as exc:
            s.rollback()
            raise _bad(exc) from exc
        except service.PolicyLocked as exc:
            s.rollback()
            raise HTTPException(409, PRIORITY_LOCKED) from exc
        st = state(request)
        if st.enqueue_priority is not None:
            st.enqueue_priority(row.id, org)
        else:  # no worker (tests, local development): after the response, in this process
            background.add_task(_run_here(st.sessions, org, row.id))
        return _overview(s, asset.id)
