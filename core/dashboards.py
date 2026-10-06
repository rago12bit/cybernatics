"""Saved dashboards and role homes (plan §48.2, §55.4, §55.6).

A dashboard is a grid of widgets, 12 columns wide; each widget shows one metric (`core.metrics`)
with its own filters -- portfolios, projects, a tag, the last N days, and how to group. Its owner
edits it; sharing it with a role lists it, read-only, for everyone who picked that role, who can
copy it to make it theirs. Every save names the version it was based on: a stale save is refused,
not merged, so two people editing at once never lose each other's work unseen.

The shared token is nobody in particular (ADR-0013's single operator): it sees and may edit every
dashboard of the organization, and its own are owned by "shared-token".

Until user accounts carry roles (Week 75), each person picks theirs -- lead, engineer or tester --
and lands on that role's home: leads on a program dashboard, engineers on what is assigned to them,
testers on their engagements.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.metrics.definitions import BY_ID
from core.metrics.query import GROUPS, MAX_DAYS
from core.persistence import repo
from core.persistence.models import Dashboard, PersonRole

ROLES = ("lead", "engineer", "tester")
COLS = 12
MAX_ROWS = 400
MAX_WIDGETS = 24
MAX_OWN = 50
SHARED_TOKEN = "shared-token"

_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_WIDGET_ID = re.compile(r"^[A-Za-z0-9_-]{1,36}$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,49}$")


class DashboardError(ValueError):
    def __init__(self, field: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.field, self.message, self.status = field, message, status


def _w(i: str, metric: str, x: int, y: int, w: int, h: int, **filters: Any) -> dict[str, Any]:
    return {"id": i, "metric": metric, "x": x, "y": y, "w": w, "h": h, "filters": filters}


# The program dashboard a lead lands on until they save their own (plan §55.4's mock-up).
PROGRAM: dict[str, Any] = {
    "id": "builtin:program",
    "name": "Program overview",
    "builtin": True,
    "widgets": [
        _w("sla", "sla_adherence", 0, 0, 6, 4),
        _w("risk", "open_risk", 6, 0, 6, 4, group="portfolio"),
        _w("past", "past_sla", 0, 4, 12, 5),
        _w("mttr", "mttr", 0, 9, 6, 4),
        _w("nvf", "new_vs_fixed", 6, 9, 6, 4),
        _w("cov", "scan_coverage", 0, 13, 6, 5),
        _w("adv", "advisory_impact", 6, 13, 6, 5),
    ],
}


def _int(raw: dict[str, Any], key: str, lo: int, hi: int, where: str) -> int:
    value = raw.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise DashboardError(f"{where}.{key}", f"{key} is a whole number from {lo} to {hi}.")
    return value


def clean_filters(raw: Any, where: str) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise DashboardError(where, "Filters are an object.")
    unknown = set(raw) - {"portfolios", "projects", "tag", "days", "group"}
    if unknown:
        raise DashboardError(where, f"Unknown filter: {sorted(unknown)[0][:40]}.")
    out: dict[str, Any] = {}
    for key, most in (("portfolios", 20), ("projects", 50)):
        ids = raw.get(key) or []
        if not isinstance(ids, list) or len(ids) > most:
            raise DashboardError(f"{where}.{key}", f"At most {most} {key}.")
        if not all(isinstance(i, str) and _ID.match(i) for i in ids):
            raise DashboardError(f"{where}.{key}", "Not an id.")
        if ids:
            out[key] = sorted(set(ids))
    tag = raw.get("tag")
    if tag not in (None, ""):
        if not isinstance(tag, str) or not _TAG.match(tag):
            raise DashboardError(f"{where}.tag", "Not a tag.")
        out["tag"] = tag
    if raw.get("days") is not None:
        out["days"] = _int(raw, "days", 1, MAX_DAYS, where)
    group = raw.get("group")
    if group not in (None, ""):
        if group not in GROUPS:
            raise DashboardError(f"{where}.group", f"Group by one of {', '.join(GROUPS)}.")
        out["group"] = group
    return out


def clean_widgets(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise DashboardError("widgets", "Widgets are a list.")
    if len(raw) > MAX_WIDGETS:
        raise DashboardError("widgets", f"At most {MAX_WIDGETS} widgets on a dashboard.")
    out, seen = [], set()
    for n, w in enumerate(raw):
        where = f"widgets[{n}]"
        if not isinstance(w, dict):
            raise DashboardError(where, "A widget is an object.")
        wid = w.get("id")
        if not isinstance(wid, str) or not _WIDGET_ID.match(wid) or wid in seen:
            raise DashboardError(f"{where}.id", "Each widget needs its own short id.")
        seen.add(wid)
        metric = w.get("metric")
        if metric not in BY_ID:
            raise DashboardError(f"{where}.metric", "Not a metric in the catalogue.")
        width = _int(w, "w", 2, COLS, where)
        x = _int(w, "x", 0, COLS - width, where)
        out.append(
            {
                "id": wid,
                "metric": metric,
                "x": x,
                "y": _int(w, "y", 0, MAX_ROWS, where),
                "w": width,
                "h": _int(w, "h", 2, 12, where),
                "filters": clean_filters(w.get("filters"), f"{where}.filters"),
            }
        )
    return out


def _name(raw: Any) -> str:
    name = (raw or "").strip() if isinstance(raw, str) else ""
    if not 1 <= len(name) <= 80:
        raise DashboardError("name", "A name of 1 to 80 characters.")
    return name


def _roles(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or any(r not in ROLES for r in raw):
        raise DashboardError("shared_with", f"Share with any of: {', '.join(ROLES)}.")
    return [r for r in ROLES if r in raw]


@dataclass(frozen=True)
class Viewer:
    actor: str
    role: str | None

    @property
    def operator(self) -> bool:
        return self.actor == SHARED_TOKEN


def visible(d: Dashboard, v: Viewer) -> bool:
    return v.operator or d.owner == v.actor or (v.role is not None and v.role in d.shared_with)


def editable(d: Dashboard, v: Viewer) -> bool:
    return v.operator or d.owner == v.actor


def view(d: Dashboard, v: Viewer) -> dict[str, Any]:
    return {
        "id": d.id,
        "name": d.name,
        "owner": d.owner,
        "shared_with": list(d.shared_with or []),
        "widgets": list(d.widgets or []),
        "version": d.version,
        "updated_at": d.updated_at,
        "updated_by": d.updated_by,
        "builtin": False,
        "can_edit": editable(d, v),
    }


def builtin_view() -> dict[str, Any]:
    return {**copy.deepcopy(PROGRAM), "owner": None, "shared_with": ["lead"], "version": 0,
            "updated_at": None, "updated_by": None, "can_edit": False}  # fmt: skip


def listing(s: Session, org_id: str, v: Viewer) -> list[dict[str, Any]]:
    """The viewer's own dashboards, then those shared with their role, then the built-in one."""
    rows = [
        d
        for d in s.scalars(
            select(Dashboard).where(Dashboard.org_id == org_id).order_by(Dashboard.name)
        )
        if visible(d, v)
    ]
    rows.sort(key=lambda d: (d.owner != v.actor, d.name.lower()))
    return [*(view(d, v) for d in rows), builtin_view()]


def get(s: Session, org_id: str, dashboard_id: str, v: Viewer) -> Dashboard:
    d = s.get(Dashboard, dashboard_id)
    if d is None or d.org_id != org_id or not visible(d, v):
        raise DashboardError("id", "No such dashboard.", 404)
    return d


def _audit(s: Session, v: Viewer, action: str, d: Dashboard, org_id: str) -> None:
    repo.append_audit_entry(  # commits
        s,
        actor=v.actor,
        action=action,
        target=f"dashboard:{d.id}",
        payload={"org_id": org_id, "name": d.name, "shared_with": list(d.shared_with or []),
                 "widgets": len(d.widgets or []), "version": d.version},
    )  # fmt: skip


def create(s: Session, org_id: str, v: Viewer, raw: dict[str, Any]) -> Dashboard:
    own = sum(1 for _ in s.scalars(select(Dashboard.id).where(
        Dashboard.org_id == org_id, Dashboard.owner == v.actor)))  # fmt: skip
    if own >= MAX_OWN:
        raise DashboardError("name", f"At most {MAX_OWN} dashboards each.", 409)
    now = datetime.now(timezone.utc)
    d = Dashboard(org_id=org_id, name=_name(raw.get("name")), owner=v.actor,
                  shared_with=_roles(raw.get("shared_with")),
                  widgets=clean_widgets(raw.get("widgets", [])), version=1, created_at=now,
                  updated_at=now, updated_by=v.actor)  # fmt: skip
    s.add(d)
    s.flush()
    _audit(s, v, "dashboard.created", d, org_id)
    return d


def update(s: Session, org_id: str, v: Viewer, dashboard_id: str, raw: dict[str, Any]) -> Dashboard:
    d = get(s, org_id, dashboard_id, v)
    if not editable(d, v):
        raise DashboardError(
            "id", "Only its owner can change this dashboard; copy it instead.", 403
        )
    if raw.get("version") != d.version:
        raise DashboardError(
            "version",
            f"Someone saved this dashboard since you opened it (now version {d.version}). "
            "Reload it, then make your change again.",
            409,
        )
    if "name" in raw:
        d.name = _name(raw["name"])
    if "shared_with" in raw:
        d.shared_with = _roles(raw["shared_with"])
    if "widgets" in raw:
        d.widgets = clean_widgets(raw["widgets"])
    d.version += 1
    d.updated_at, d.updated_by = datetime.now(timezone.utc), v.actor
    s.flush()
    _audit(s, v, "dashboard.saved", d, org_id)
    return d


def delete(s: Session, org_id: str, v: Viewer, dashboard_id: str) -> None:
    d = get(s, org_id, dashboard_id, v)
    if not editable(d, v):
        raise DashboardError("id", "Only its owner can delete this dashboard.", 403)
    _audit(s, v, "dashboard.deleted", d, org_id)
    s.delete(d)
    s.commit()


def copy_of(s: Session, org_id: str, v: Viewer, dashboard_id: str) -> Dashboard:
    if dashboard_id == PROGRAM["id"]:
        src = {"name": PROGRAM["name"], "widgets": PROGRAM["widgets"]}
    else:
        d = get(s, org_id, dashboard_id, v)
        src = {"name": d.name, "widgets": d.widgets}
    name = f"{str(src['name'])[:73]} (copy)"
    return create(s, org_id, v, {"name": name, "widgets": copy.deepcopy(src["widgets"])})


# --- roles -----------------------------------------------------------------------------------


def role_of(s: Session, org_id: str, person: str) -> str | None:
    row = s.get(PersonRole, (org_id, person))
    return row.role if row is not None else None


def set_role(s: Session, org_id: str, person: str, role: str) -> None:
    if role not in ROLES:
        raise DashboardError("role", f"A role is one of: {', '.join(ROLES)}.")
    row = s.get(PersonRole, (org_id, person))
    if row is None:
        s.add(PersonRole(org_id=org_id, person=person, role=role,
                         updated_at=datetime.now(timezone.utc)))  # fmt: skip
    else:
        row.role, row.updated_at = role, datetime.now(timezone.utc)
    s.flush()
    repo.append_audit_entry(  # commits
        s, actor=person, action="home.role.chosen", target=f"person:{person}",
        payload={"org_id": org_id, "role": role},
    )  # fmt: skip
