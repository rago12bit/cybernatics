"""Dashboards API (plan §48.2, §55.4): saved, shared dashboards of metric widgets, and the role
each person picks for their home.

    GET    /v2/dashboards                  mine, those shared with my role, and the built-in one
    POST   /v2/dashboards                  {name, shared_with, widgets}
    GET    /v2/dashboards/{id}
    PUT    /v2/dashboards/{id}             {version, name?, shared_with?, widgets?}; 409 if stale
    DELETE /v2/dashboards/{id}
    POST   /v2/dashboards/{id}/copy        make a dashboard I can see (or the built-in one) mine
    GET    /v2/me                          who I am and the role I picked
    PUT    /v2/me/role                     {role: lead | engineer | tester}; a personal token
    GET    /v2/me/assigned                 an engineer's home: my open Issues, soonest SLA first
    GET    /v2/me/engagements              a tester's home: engagements naming me
    GET    /v2/portfolio-overviews         every business unit's sentence, neediest first
    GET    /v2/portfolio-overviews/{id}    one unit: the sentence and its projects by need
                                           ("none": projects without a portfolio)

All `scans:read`: a dashboard is a way of looking at what the token can already read. Every change
is audit-logged. The widgets' numbers come from `/v2/metrics` (ADR-0054).
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core import dashboards as svc
from core.collab.people import is_person
from core.metrics import portfolio as units


class RoleIn(BaseModel):
    role: str


class DashboardIn(BaseModel):
    """Checked by `core.dashboards` (field by field, with the field named in a 422), so loose here.
    On a save, `version` is the one the edit started from; fields left out stay as they are."""

    name: Any = None
    shared_with: Any = None
    widgets: Any = None
    version: Any = None


def _viewer(s: Session, org: str, auth: AuthContext) -> svc.Viewer:
    return svc.Viewer(auth.actor, svc.role_of(s, org, auth.actor))


def _fail(s: Session, exc: svc.DashboardError) -> HTTPException:
    s.rollback()
    return HTTPException(exc.status, {"field": exc.field, "message": exc.message})


def register_dashboard_routes(app: FastAPI) -> None:
    read = [Depends(require_scope("scans:read"))]

    @app.get("/v2/me", tags=["dashboards"], dependencies=read)
    def me(
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        user = None
        if auth.access is not None:
            from core.identity.users import get as get_user
            from core.identity.users import view as user_view

            user = user_view(get_user(s, org, auth.access.user_id))
        return {"actor": auth.actor, "person": is_person(auth.actor),
                "role": svc.role_of(s, org, auth.actor), "roles": list(svc.ROLES),
                "user": user, "org_role": auth.access.role if auth.access else None,
                "scopes": sorted(auth.scopes) if auth.scopes is not None else None}  # fmt: skip

    @app.put("/v2/me/role", tags=["dashboards"], dependencies=read)
    def choose_role(
        body: RoleIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        try:
            svc.set_role(s, org, auth.actor, body.role)
        except svc.DashboardError as exc:
            raise _fail(s, exc) from exc
        return me(s, org, auth)

    @app.get("/v2/dashboards", tags=["dashboards"], dependencies=read)
    def list_dashboards(
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        v = _viewer(s, org, auth)
        return {"role": v.role, "dashboards": svc.listing(s, org, v)}

    @app.post("/v2/dashboards", tags=["dashboards"], dependencies=read, status_code=201)
    def create_dashboard(
        body: DashboardIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        v = _viewer(s, org, auth)
        try:
            return svc.view(svc.create(s, org, v, body.model_dump(exclude_unset=True)), v)
        except svc.DashboardError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/dashboards/{dashboard_id}", tags=["dashboards"], dependencies=read)
    def get_dashboard(
        dashboard_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        if dashboard_id == svc.PROGRAM["id"]:
            return svc.builtin_view()
        v = _viewer(s, org, auth)
        try:
            return svc.view(svc.get(s, org, dashboard_id, v), v)
        except svc.DashboardError as exc:
            raise _fail(s, exc) from exc

    @app.put("/v2/dashboards/{dashboard_id}", tags=["dashboards"], dependencies=read)
    def save_dashboard(
        dashboard_id: str,
        body: DashboardIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        v = _viewer(s, org, auth)
        try:
            return svc.view(
                svc.update(s, org, v, dashboard_id, body.model_dump(exclude_unset=True)), v
            )
        except svc.DashboardError as exc:
            raise _fail(s, exc) from exc

    @app.delete("/v2/dashboards/{dashboard_id}", tags=["dashboards"], dependencies=read,
                status_code=204)  # fmt: skip
    def delete_dashboard(
        dashboard_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        try:
            svc.delete(s, org, _viewer(s, org, auth), dashboard_id)
        except svc.DashboardError as exc:
            raise _fail(s, exc) from exc

    @app.post("/v2/dashboards/{dashboard_id}/copy", tags=["dashboards"], dependencies=read,
              status_code=201)  # fmt: skip
    def copy_dashboard(
        dashboard_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        v = _viewer(s, org, auth)
        try:
            return svc.view(svc.copy_of(s, org, v, dashboard_id), v)
        except svc.DashboardError as exc:
            raise _fail(s, exc) from exc

    @app.get("/v2/me/assigned", tags=["dashboards"], dependencies=read)
    def my_assigned(
        limit: int = Query(default=100, ge=1, le=500),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> dict[str, Any]:
        return svc.assigned(s, org, auth.actor, limit)

    @app.get("/v2/me/engagements", tags=["dashboards"], dependencies=read)
    def my_engagements(
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> list[dict[str, Any]]:
        return svc.my_engagements(s, org, auth.actor)

    @app.get("/v2/portfolio-overviews", tags=["dashboards"], dependencies=read)
    def portfolio_overviews(
        s: Session = Depends(db), org: str = Depends(current_org)
    ) -> list[dict[str, Any]]:
        return units.overviews(s, org)

    @app.get("/v2/portfolio-overviews/{portfolio_id}", tags=["dashboards"], dependencies=read)
    def portfolio_overview(
        portfolio_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> dict[str, Any]:
        try:
            return units.overview(s, org, portfolio_id)
        except LookupError as exc:
            raise HTTPException(404, "No such portfolio.") from exc
