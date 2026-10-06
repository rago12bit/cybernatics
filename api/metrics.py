"""Metrics API (plan §48.1): every number a dashboard shows, defined, filtered, and traceable to the
Issues behind it.

    GET /v2/metrics                         every metric with its written definition
    GET /v2/metrics/{id}?portfolio=&project=&tag=&from=&to=&group=
    GET /v2/metrics/issues?kind=open|past_sla|opened|fixed&band=&...   the Issues behind a number

All `scans:read`. Read from summary tables only (ADR-0054); `pending_refresh` says how many projects
are waiting for theirs.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import current_org, db, require_scope
from core.metrics import query
from core.metrics.definitions import METRICS

_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,49}$")


class MetricOut(BaseModel):
    id: str
    name: str
    definition: str
    unit: str
    period: bool


def _filters(
    portfolio: list[str] | None, project: list[str] | None, tag: str | None,
    start: date | None, end: date | None, group: str,
) -> query.Filters:  # fmt: skip
    for value in (*(portfolio or []), *(project or [])):
        if not _ID.match(value):
            raise HTTPException(422, {"field": "portfolio/project", "message": "not an id"})
    if tag is not None and not _TAG.match(tag):
        raise HTTPException(422, {"field": "tag", "message": "not a tag"})
    return query.Filters(portfolio or [], project or [], tag, start, end, group)


def register_metric_routes(app: FastAPI) -> None:
    @app.get("/v2/metrics", response_model=list[MetricOut], tags=["metrics"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def list_metrics() -> list[MetricOut]:
        return [MetricOut(id=m.id, name=m.name, definition=m.definition, unit=m.unit,
                          period=m.period) for m in METRICS]  # fmt: skip

    @app.get("/v2/metrics/issues", tags=["metrics"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def metric_issues(
        kind: str = Query(...),
        band: str | None = Query(default=None, max_length=8),
        in_portfolio: str | None = Query(default=None, alias="in_portfolio", max_length=36),
        in_project: str | None = Query(default=None, alias="in_project", max_length=36),
        older_than: int | None = Query(default=None, ge=1, le=3650),
        after: str | None = Query(default=None, max_length=36),
        limit: int = Query(default=50, ge=1, le=200),
        portfolio: list[str] | None = Query(default=None),
        project: list[str] | None = Query(default=None),
        tag: str | None = Query(default=None),
        start: date | None = Query(default=None, alias="from"),
        end: date | None = Query(default=None, alias="to"),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> dict[str, Any]:
        """The Issues behind a number: `kind` and the row's key (`band`, `in_portfolio`,
        `in_project`, `older_than`) plus the widget's own filters."""
        f = _filters(portfolio, project, tag, start, end, "band")
        try:
            return query.issues(
                s, org, f, kind=kind, band=band, portfolio=in_portfolio, project=in_project,
                older_than=older_than, after=after, limit=limit,
            )  # fmt: skip
        except query.MetricError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/v2/metrics/{metric_id}", tags=["metrics"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def get_metric(
        metric_id: str,
        portfolio: list[str] | None = Query(default=None),
        project: list[str] | None = Query(default=None),
        tag: str | None = Query(default=None),
        start: date | None = Query(default=None, alias="from"),
        end: date | None = Query(default=None, alias="to"),
        group: str = Query(default="band"),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> dict[str, Any]:
        f = _filters(portfolio, project, tag, start, end, group)
        try:
            return query.compute(s, org, metric_id, f)
        except query.MetricError as exc:
            status = 404 if str(exc).startswith("no metric") else 422
            raise HTTPException(status, str(exc)) from exc
