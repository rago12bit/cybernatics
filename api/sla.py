"""The SLA policy API (Week 61, plan §44.1).

    GET /v2/projects/{id}/sla   the policy in force (or the starter values, off), its history, and
                                how many Issues are in each SLA state
    PUT /v2/projects/{id}/sla   save a new version of the policy (audit-logged)

Reading is `scans:read`; changing a policy is `scans:write`, the same permission as triaging the
Issues it governs. Each Issue's own SLA is on the issue endpoints (`issue.sla`), and the issues
table filters by it (`?sla=breached`).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from core.persistence import repo
from core.sla import service
from core.sla.policy import BANDS, STARTER, PolicyError

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class BandOut(BaseModel):
    days: int | None = Field(description="Days from first detection to fix; null: no deadline.")
    warn: int = Field(description="'Due soon' in the last this-many days.")


class PolicyVersion(BaseModel):
    version: int
    enabled: bool
    bands: dict[str, BandOut]
    note: str | None
    changed_at: datetime
    changed_by: str | None


class SlaOverview(BaseModel):
    enabled: bool
    basis: str
    version: int = Field(
        description="0 until someone saves a policy; the starter values are shown."
    )
    bands: dict[str, BandOut]
    starter: dict[str, BandOut]
    counts: dict[str, int] = Field(description="Issues by SLA state, under the policy in force.")
    history: list[PolicyVersion]


class PolicyIn(BaseModel):
    enabled: bool
    bands: dict[str, dict[str, Any]]
    basis: str = "severity"
    note: str | None = Field(default=None, max_length=500)


def _bands(raw: dict[str, Any]) -> dict[str, BandOut]:
    return {k: BandOut(days=v.get("days"), warn=int(v.get("warn") or 0)) for k, v in raw.items()}


def _asset(s: Session, asset_id: str, org: str) -> Any:
    asset = repo.get_asset(s, asset_id, org_id=org) if _UUID.match(asset_id) else None
    if asset is None:
        raise HTTPException(404, "project not found")
    return asset


def _overview(s: Session, asset_id: str) -> SlaOverview:
    row = service.current(s, asset_id)
    policy = service.policy_for(s, asset_id)
    return SlaOverview(
        enabled=policy.enabled,
        basis=policy.basis,
        version=row.version if row else 0,
        bands=_bands(policy.to_dict()["bands"]),
        starter=_bands({k: STARTER[k] for k in BANDS}),
        counts=service.summary(s, asset_id),
        history=[
            PolicyVersion(
                version=h.version, enabled=h.enabled, bands=_bands(h.bands), note=h.note,
                changed_at=h.created_at, changed_by=h.created_by,
            )  # fmt: skip
            for h in service.history(s, asset_id)
        ],
    )


def register_sla_routes(app: FastAPI) -> None:
    @app.get(
        "/v2/projects/{project_id}/sla",
        response_model=SlaOverview,
        tags=["sla"],
        dependencies=[Depends(require_scope("scans:read"))],
    )
    def get_sla(
        project_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> SlaOverview:
        asset = _asset(s, project_id, org)
        return _overview(s, asset.id)

    @app.put(
        "/v2/projects/{project_id}/sla",
        response_model=SlaOverview,
        tags=["sla"],
        dependencies=[Depends(require_scope("scans:write"))],
    )
    def put_sla(
        project_id: str,
        body: PolicyIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> SlaOverview:
        asset = _asset(s, project_id, org)
        try:
            service.save(
                s, org_id=org, asset_id=asset.id, enabled=body.enabled, bands=body.bands,
                basis=body.basis, note=body.note, actor=auth.actor,
            )  # fmt: skip
        except PolicyError as exc:
            s.rollback()
            raise HTTPException(422, {"field": exc.field, "message": str(exc)}) from exc
        return _overview(s, asset.id)
