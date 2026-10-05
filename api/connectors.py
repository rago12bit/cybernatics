"""Connectors API (Week 60, plan §42.5, §55.7, ADR-0045).

    GET    /v2/connector-kinds          what can be connected, what each needs, what it may access
    GET    /v2/connectors               every connector of the organization, with its health
    POST   /v2/connectors               add one (the credential goes to OpenBao when it is set up)
    GET    /v2/connectors/{id}          one, with its recent runs
    PATCH  /v2/connectors/{id}          enable/disable, interval, name, rotate the credential
    DELETE /v2/connectors/{id}
    POST   /v2/connectors/{id}/run      run it now

Reading is `ingest:read`; anything that changes a connector or runs one is `ingest:write` (a pull
can close Issues, exactly like an upload). A credential is write-only: no response ever contains
it, only where it is stored. Every change is audit-logged.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AppState, AuthContext, current_org, db, require_auth, require_scope, state
from core.connectors import service
from core.persistence import repo
from core.persistence.models import Connector, ConnectorRun

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class KindOut(BaseModel):
    name: str
    label: str
    direction: str
    needs_credential: bool
    fields: list[str]
    permissions: str


class RunOut(BaseModel):
    id: str
    started_at: datetime
    finished_at: datetime | None
    outcome: str
    items: int
    requests: int
    import_id: str | None
    counts: dict[str, Any]
    warnings: list[str]
    error: str | None


class ConnectorOut(BaseModel):
    id: str
    project_id: str
    project: str
    kind: str
    kind_label: str
    direction: str
    name: str
    config: dict[str, Any]
    enabled: bool
    interval_minutes: int
    close_on_empty: bool
    credential_store: str = Field(description="none, openbao, or database (stored unencrypted).")
    test_id: str | None
    status: str = Field(description="never_run, ok, empty, failing or disabled.")
    warning: str | None = Field(description="What the health screen should say, if anything.")
    last_run_at: datetime | None
    last_success_at: datetime | None
    next_run_at: datetime | None
    last_items: int | None
    max_items_seen: int
    consecutive_failures: int
    last_error: str | None
    runs: list[RunOut] = []


class ConnectorIn(BaseModel):
    project_id: str
    kind: str
    name: str = Field(default="", max_length=200)
    config: dict[str, Any] = Field(default_factory=dict)
    credential: str | None = Field(default=None, max_length=4000)
    interval_minutes: int = 360
    enabled: bool = True
    close_on_empty: bool = False


class ConnectorPatch(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    enabled: bool | None = None
    interval_minutes: int | None = None
    close_on_empty: bool | None = None
    credential: str | None = Field(default=None, max_length=4000)


def _run(r: ConnectorRun) -> RunOut:
    return RunOut(
        id=r.id,
        started_at=r.started_at,
        finished_at=r.finished_at,
        outcome=r.outcome,
        items=r.items,
        requests=r.requests,
        import_id=r.import_id,
        counts=dict(r.counts or {}),
        warnings=[str(w) for w in r.warnings or []],
        error=r.error,
    )


def _out(s: Session, c: Connector, history: list[ConnectorRun] | None = None) -> ConnectorOut:
    h = service.health(c)
    asset = repo.get_asset(s, c.asset_id, org_id=c.org_id)
    kind = service.KINDS[c.kind]
    return ConnectorOut(
        id=c.id,
        project_id=c.asset_id,
        project=asset.label if asset else c.asset_id,
        kind=c.kind,
        kind_label=kind.label,
        direction=kind.direction,
        name=c.name,
        config=dict(c.config),
        enabled=c.enabled,
        interval_minutes=c.interval_minutes,
        close_on_empty=c.close_on_empty,
        credential_store=c.credential_store,
        test_id=c.test_id,
        status=h.status,
        warning=h.warning,
        last_run_at=c.last_run_at,
        last_success_at=c.last_success_at,
        next_run_at=c.next_run_at,
        last_items=c.last_items,
        max_items_seen=c.max_items_seen,
        consecutive_failures=c.consecutive_failures,
        last_error=c.last_error,
        runs=[_run(r) for r in history or []],
    )


def _get(s: Session, connector_id: str, org: str) -> Connector:
    c = service.get(s, connector_id, org) if _UUID.match(connector_id) else None
    if c is None:
        raise HTTPException(404, "connector not found")
    return c


def _config_error(exc: service.ConnectorConfigError) -> HTTPException:
    return HTTPException(422, {"field": exc.field, "message": str(exc)})


def _audit(s: Session, auth: AuthContext, action: str, c: Connector, extra: dict[str, Any]) -> None:
    repo.append_audit_entry(
        s,
        actor=auth.actor,
        action=action,
        target=f"connector:{c.id}",
        payload={"org_id": c.org_id, "kind": c.kind, "project": c.asset_id, **extra},
    )


def _start(st: AppState, s: Session, c: Connector) -> None:
    """Run now: on the worker when there is one, otherwise in this request."""
    c.next_run_at = datetime.now(timezone.utc)
    s.commit()
    if st.enqueue_connector is not None:
        st.enqueue_connector(c.id, c.org_id)
    else:
        service.run(s, c, st.settings)


def register_connector_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/connector-kinds",
        response_model=list[KindOut],
        tags=["connectors"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def kinds() -> list[KindOut]:
        return [
            KindOut(
                name=k.name,
                label=k.label,
                direction=k.direction,
                needs_credential=k.needs_credential,
                fields=list(k.fields),
                permissions=k.permissions,
            )
            for k in service.KINDS.values()
        ]

    @app.get(
        "/v2/connectors",
        response_model=list[ConnectorOut],
        tags=["connectors"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def list_connectors(
        project_id: str | None = Query(None),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[ConnectorOut]:
        return [_out(s, c) for c in service.list_for(s, org, project_id)]

    @app.post(
        "/v2/connectors",
        status_code=201,
        response_model=ConnectorOut,
        tags=["connectors"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def create_connector(
        body: ConnectorIn,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> ConnectorOut:
        if (
            not _UUID.match(body.project_id)
            or repo.get_asset(s, body.project_id, org_id=org) is None
        ):
            raise HTTPException(404, "project not found")
        try:
            c = service.create(
                s,
                org_id=org,
                asset_id=body.project_id,
                kind=body.kind,
                name=body.name,
                config=body.config,
                credential=body.credential,
                settings=st.settings,
                interval_minutes=body.interval_minutes,
                enabled=body.enabled,
                close_on_empty=body.close_on_empty,
                created_by=auth.actor,
            )
        except service.ConnectorConfigError as exc:
            s.rollback()
            raise _config_error(exc) from exc
        _audit(
            s,
            auth,
            "connector.created",
            c,
            {"config": c.config, "credential_store": c.credential_store},
        )
        return _out(s, c)

    @app.get(
        "/v2/connectors/{connector_id}",
        response_model=ConnectorOut,
        tags=["connectors"],
        dependencies=[Depends(require_scope("ingest:read"))],
    )
    def get_connector(
        connector_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> ConnectorOut:
        c = _get(s, connector_id, org)
        return _out(s, c, service.runs(s, c.id, org))

    @app.patch(
        "/v2/connectors/{connector_id}",
        response_model=ConnectorOut,
        tags=["connectors"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def update_connector(
        connector_id: str,
        body: ConnectorPatch,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> ConnectorOut:
        c = _get(s, connector_id, org)
        changed: dict[str, Any] = {}
        if body.name is not None and body.name.strip():
            c.name = " ".join(body.name.split())[:200]
            changed["name"] = c.name
        if body.interval_minutes is not None:
            c.interval_minutes = service._interval(body.interval_minutes)
            changed["interval_minutes"] = c.interval_minutes
        if body.close_on_empty is not None:
            c.close_on_empty = body.close_on_empty
            changed["close_on_empty"] = c.close_on_empty
        if body.enabled is not None:
            c.enabled = body.enabled
            c.status = (
                c.status
                if body.enabled and c.status != "disabled"
                else ("disabled" if not body.enabled else "never_run")
            )
            if body.enabled:
                c.next_run_at = datetime.now(timezone.utc)
            changed["enabled"] = c.enabled
        if body.credential:
            try:
                service.set_credential(c, body.credential, st.settings)
            except service.ConnectorConfigError as exc:
                s.rollback()
                raise _config_error(exc) from exc
            changed["credential"] = "rotated"
        s.commit()
        _audit(s, auth, "connector.updated", c, changed)
        return _out(s, c, service.runs(s, c.id, org))

    @app.delete(
        "/v2/connectors/{connector_id}",
        status_code=204,
        tags=["connectors"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def delete_connector(
        connector_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> Response:
        c = _get(s, connector_id, org)
        _audit(s, auth, "connector.deleted", c, {"name": c.name})
        s.delete(c)
        s.commit()
        return Response(status_code=204)

    @app.post(
        "/v2/connectors/{connector_id}/run",
        response_model=ConnectorOut,
        status_code=202,
        tags=["connectors"],
        dependencies=[Depends(require_scope("ingest:write"))],
    )
    def run_connector(
        connector_id: str,
        st: AppState = Depends(state),
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> ConnectorOut:
        c = _get(s, connector_id, org)
        if not c.enabled:
            raise HTTPException(409, "the connector is disabled; enable it first")
        _start(st, s, c)
        _audit(s, auth, "connector.run", c, {})
        s.refresh(c)
        return _out(s, c, service.runs(s, c.id, org))
