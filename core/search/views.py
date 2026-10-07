"""Saved views of the Issues list, and the columns and density each person chose (plan §56).

A saved view is a name for a query (core.search.language), with the sort and, optionally, the
columns to show. Like a dashboard (core.dashboards), its owner edits it; sharing it with a role
lists it, read-only, for everyone who picked that role, who can copy it to make it theirs. Every
save names the version it started from, and a stale save is refused rather than merged.

The query is stored written back canonically, so a view saved from the panel and one typed in the
query bar look the same. It is checked when saved, not trusted: a view that cannot be parsed is
never stored. `assignee:me` means whoever is looking, so one shared "Mine" view serves a team.

A few views are built in and cannot be changed (copy one to start from it). Views saved in the
browser before Week 73 (one project's filters each) can be imported once; the browser turns each
into a query, and names already taken get "(imported)".

Table settings are per person and per table: which columns, in what order, and how dense. The
shared token is nobody in particular (ADR-0013), so its settings are shared by everyone using it.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.dashboards import ROLES, Viewer
from core.persistence import repo
from core.persistence.models import PersonPref, SavedView
from core.search.issues import SORTS
from core.search.language import QueryError, format_query, parse

MAX_OWN = 100
MAX_IMPORT = 200
COLUMNS = ("project", "priority", "severity", "status", "sla", "assignee", "path", "category",
           "source", "retest", "first_seen", "last_seen", "fixed")  # fmt: skip
DEFAULT_COLUMNS = ("project", "priority", "severity", "status", "sla", "assignee", "first_seen")
DENSITIES = ("comfortable", "compact")
TABLES = ("issues",)


class ViewError(ValueError):
    def __init__(self, field: str, message: str, status: int = 422, **extra: Any) -> None:
        super().__init__(message)
        self.field, self.message, self.status, self.extra = field, message, status, extra

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "message": self.message, **self.extra}


@dataclass(frozen=True)
class Builtin:
    id: str
    name: str
    query: str
    sort: str = "priority"


BUILTINS = (Builtin("builtin:mine", "Assigned to me", "assignee:me"), Builtin(
    "builtin:past-sla", "Past their SLA", "sla:breached"
), Builtin("builtin:due-soon", "Due soon", "sla:due_soon"), Builtin(
    "builtin:unowned-critical",
    "Critical and high, nobody on them",
    "severity:critical,high assignee:none"),  # fmt: skip
    Builtin("builtin:new", "New this week", "first_seen:<7d", "newest"),
    Builtin("builtin:not-a-risk", "Marked not a risk", "status:not_a_risk", "newest"),
)
BY_BUILTIN = {b.id: b for b in BUILTINS}


# --- checking what a person sends ------------------------------------------------------------


def _name(raw: Any) -> str:
    name = (raw or "").strip() if isinstance(raw, str) else ""
    if not 1 <= len(name) <= 80:
        raise ViewError("name", "A name of 1 to 80 characters.")
    return name


def clean_query(raw: Any, field: str = "query") -> str:
    """The query, parsed and written back canonically; a query that cannot be read is refused
    with the span at fault, as the query bar shows it."""
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise ViewError(field, "A query is text.")
    if len(raw) > 2000:
        raise ViewError(field, "At most 2,000 characters.")
    try:
        return format_query(parse(raw))
    except QueryError as exc:
        raise ViewError(field, exc.message, start=exc.start, end=exc.end) from exc


def _sort(raw: Any) -> str:
    if raw in (None, ""):
        return "priority"
    if raw not in SORTS:
        raise ViewError("sort", f"One of: {', '.join(SORTS)}.")
    return str(raw)


def clean_columns(raw: Any, field: str = "columns") -> list[str] | None:
    """Columns in the order given, each once; the title is always shown, so it is not one."""
    if raw is None:
        return None
    if not isinstance(raw, list) or any(c not in COLUMNS for c in raw):
        raise ViewError(field, f"Columns from: {', '.join(COLUMNS)}.")
    return list(dict.fromkeys(raw))


def _roles(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or any(r not in ROLES for r in raw):
        raise ViewError("shared_with", f"Share with any of: {', '.join(ROLES)}.")
    return [r for r in ROLES if r in raw]


# --- seeing and changing views ---------------------------------------------------------------


def visible(v: SavedView, who: Viewer) -> bool:
    return (
        who.operator
        or v.owner == who.actor
        or (who.role is not None and who.role in (v.shared_with or []))
    )


def editable(v: SavedView, who: Viewer) -> bool:
    return who.operator or v.owner == who.actor


def view(v: SavedView, who: Viewer) -> dict[str, Any]:
    return {
        "id": v.id,
        "name": v.name,
        "owner": v.owner,
        "query": v.query,
        "sort": v.sort,
        "columns": list(v.columns) if v.columns is not None else None,
        "shared_with": list(v.shared_with or []),
        "version": v.version,
        "updated_at": v.updated_at,
        "updated_by": v.updated_by,
        "builtin": False,
        "can_edit": editable(v, who),
    }


def builtin_view(b: Builtin) -> dict[str, Any]:
    return {"id": b.id, "name": b.name, "owner": None, "query": b.query, "sort": b.sort,
            "columns": None, "shared_with": list(ROLES), "version": 0, "updated_at": None,
            "updated_by": None, "builtin": True, "can_edit": False}  # fmt: skip


def listing(s: Session, org_id: str, who: Viewer) -> list[dict[str, Any]]:
    """The viewer's own views, then those shared with their role, then the built-in ones."""
    rows = [v for v in s.scalars(select(SavedView).where(SavedView.org_id == org_id))
            if visible(v, who)]  # fmt: skip
    rows.sort(key=lambda v: (v.owner != who.actor, v.name.lower()))
    return [*(view(v, who) for v in rows), *(builtin_view(b) for b in BUILTINS)]


def get(s: Session, org_id: str, view_id: str, who: Viewer) -> SavedView:
    v = s.get(SavedView, view_id) if len(view_id) <= 36 else None
    if v is None or v.org_id != org_id or not visible(v, who):
        raise ViewError("id", "No such saved view.", 404)
    return v


def resolve(s: Session, org_id: str, view_id: str, who: Viewer) -> dict[str, Any]:
    """A view by id, built-in or saved, as the list shows it."""
    if view_id in BY_BUILTIN:
        return builtin_view(BY_BUILTIN[view_id])
    return view(get(s, org_id, view_id, who), who)


def _audit(s: Session, who: Viewer, action: str, v: SavedView, org_id: str) -> None:
    repo.append_audit_entry(  # commits
        s, actor=who.actor, action=action, target=f"saved_view:{v.id}",
        payload={"org_id": org_id, "name": v.name, "query": v.query,
                 "shared_with": list(v.shared_with or []), "version": v.version},
    )  # fmt: skip


def _own_count(s: Session, org_id: str, actor: str) -> int:
    return len(list(s.scalars(select(SavedView.id).where(
        SavedView.org_id == org_id, SavedView.owner == actor))))  # fmt: skip


def _new(org_id: str, who: Viewer, raw: dict[str, Any], now: datetime) -> SavedView:
    return SavedView(org_id=org_id, name=_name(raw.get("name")), owner=who.actor,
                     query=clean_query(raw.get("query")), sort=_sort(raw.get("sort")),
                     columns=clean_columns(raw.get("columns")),
                     shared_with=_roles(raw.get("shared_with")), version=1, created_at=now,
                     updated_at=now, updated_by=who.actor)  # fmt: skip


def create(s: Session, org_id: str, who: Viewer, raw: dict[str, Any]) -> SavedView:
    if _own_count(s, org_id, who.actor) >= MAX_OWN:
        raise ViewError("name", f"At most {MAX_OWN} saved views each.", 409)
    v = _new(org_id, who, raw, datetime.now(timezone.utc))
    s.add(v)
    s.flush()
    _audit(s, who, "saved_view.created", v, org_id)
    return v


def update(s: Session, org_id: str, who: Viewer, view_id: str, raw: dict[str, Any]) -> SavedView:
    if view_id in BY_BUILTIN:
        raise ViewError("id", "Built-in views can't be changed; copy it instead.", 403)
    v = get(s, org_id, view_id, who)
    if not editable(v, who):
        raise ViewError("id", "Only its owner can change this view; copy it instead.", 403)
    if raw.get("version") != v.version:
        raise ViewError(
            "version",
            f"Someone saved this view since you opened it (now version {v.version}). "
            "Reload it, then make your change again.",
            409,
        )
    if "name" in raw:
        v.name = _name(raw["name"])
    if "query" in raw:
        v.query = clean_query(raw["query"])
    if "sort" in raw:
        v.sort = _sort(raw["sort"])
    if "columns" in raw:
        v.columns = clean_columns(raw["columns"])
    if "shared_with" in raw:
        v.shared_with = _roles(raw["shared_with"])
    v.version += 1
    v.updated_at, v.updated_by = datetime.now(timezone.utc), who.actor
    s.flush()
    _audit(s, who, "saved_view.saved", v, org_id)
    return v


def delete(s: Session, org_id: str, who: Viewer, view_id: str) -> None:
    if view_id in BY_BUILTIN:
        raise ViewError("id", "Built-in views can't be deleted.", 403)
    v = get(s, org_id, view_id, who)
    if not editable(v, who):
        raise ViewError("id", "Only its owner can delete this view.", 403)
    _audit(s, who, "saved_view.deleted", v, org_id)
    s.delete(v)
    s.commit()


def copy_of(s: Session, org_id: str, who: Viewer, view_id: str) -> SavedView:
    src = resolve(s, org_id, view_id, who)
    return create(s, org_id, who, {"name": f"{str(src['name'])[:73]} (copy)",
                                   "query": src["query"], "sort": src["sort"],
                                   "columns": copy.deepcopy(src["columns"])})  # fmt: skip


def import_views(s: Session, org_id: str, who: Viewer, raw: Any) -> dict[str, Any]:
    """Views saved in the browser before Week 73, each already turned into a query by the browser.
    All or nothing: one that cannot be read refuses the lot, naming it, so nothing is half
    imported. A name already taken gets " (imported)"; a view identical to one the person already
    has (same query and sort) is skipped."""
    if not isinstance(raw, list) or not raw:
        raise ViewError("views", "Nothing to import.")
    if len(raw) > MAX_IMPORT:
        raise ViewError("views", f"At most {MAX_IMPORT} views at once.")
    mine = [v for v in s.scalars(select(SavedView).where(
        SavedView.org_id == org_id, SavedView.owner == who.actor))]  # fmt: skip
    taken = {v.name.lower() for v in mine}
    have = {(v.query, v.sort) for v in mine}
    if len(mine) + len(raw) > MAX_OWN:
        raise ViewError("views", f"At most {MAX_OWN} saved views each; you have {len(mine)}.", 409)
    now = datetime.now(timezone.utc)
    made: list[SavedView] = []
    skipped = 0
    for n, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ViewError(f"views[{n}]", "A view is an object.")
        try:
            v = _new(org_id, who, {**item, "shared_with": []}, now)
        except ViewError as exc:
            field = f"views[{n}].{exc.field}"
            raise ViewError(field, exc.message, exc.status, **exc.extra) from exc
        if (v.query, v.sort) in have:
            skipped += 1
            continue
        if v.name.lower() in taken:
            v.name = f"{v.name[:69]} (imported)"
        taken.add(v.name.lower())
        have.add((v.query, v.sort))
        s.add(v)
        made.append(v)
    s.flush()
    repo.append_audit_entry(  # commits
        s, actor=who.actor, action="saved_view.imported", target=f"person:{who.actor}",
        payload={"org_id": org_id, "imported": [v.id for v in made], "skipped": skipped},
    )  # fmt: skip
    return {"imported": [view(v, who) for v in made], "skipped": skipped}


# --- each person's table settings ------------------------------------------------------------


def default_prefs(table: str) -> dict[str, Any]:
    return {"columns": list(DEFAULT_COLUMNS), "density": "comfortable", "saved": False}


def prefs(s: Session, org_id: str, person: str, table: str) -> dict[str, Any]:
    if table not in TABLES:
        raise ViewError("table", "No such table.", 404)
    row = s.get(PersonPref, (org_id, person, table))
    if row is None:
        return default_prefs(table)
    return {**default_prefs(table), **row.value, "saved": True}


def set_prefs(s: Session, org_id: str, person: str, table: str, raw: Any) -> dict[str, Any]:
    """Not audit-logged: it changes only how one person's table looks."""
    if table not in TABLES:
        raise ViewError("table", "No such table.", 404)
    if not isinstance(raw, dict):
        raise ViewError("prefs", "Settings are an object.")
    current = prefs(s, org_id, person, table)
    value = {"columns": current["columns"], "density": current["density"]}
    if "columns" in raw:
        cols = clean_columns(raw["columns"])
        if not cols:
            raise ViewError("columns", "Show at least one column besides the title.")
        value["columns"] = cols
    if "density" in raw:
        if raw["density"] not in DENSITIES:
            raise ViewError("density", f"One of: {', '.join(DENSITIES)}.")
        value["density"] = raw["density"]
    row = s.get(PersonPref, (org_id, person, table))
    now = datetime.now(timezone.utc)
    if row is None:
        s.add(PersonPref(org_id=org_id, person=person, key=table, value=value, updated_at=now))
    else:
        row.value, row.updated_at = value, now
    s.commit()
    return {**value, "saved": True}
