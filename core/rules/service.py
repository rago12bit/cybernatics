"""Rules: validate, save, version, delete; and their runs (plan §45, Week 65, ADR-0049).

Only Admins write rules -- the `rules:write` scope until roles exist (Week 75). Every change is a
hash-chained audit entry with the whole definition, and bumps the rule's version; each run records
the version it ran. Deleting a rule keeps it (and its runs) so the history still says what ran.

A rule is validated as a whole before it is saved: the trigger and its parameters, the condition
compiles under OPA (with the network and environment builtins removed), every action fits the
trigger's subject, a named person exists, and the confirmation threshold is in range.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from core.collab import tags as tag_service
from core.collab.assign import AssignError, resolve
from core.persistence import repo
from core.persistence.models import Asset, AutomationRule, RuleRun
from core.rules import rego
from core.rules.catalog import (
    ACTIONS,
    BANDS,
    DEFAULT_CONFIRM_OVER,
    DEFAULT_FIX_PER_DAY,
    EVERY,
    MAX_ACTIONS,
    MAX_CONFIRM_OVER,
    MAX_FIX_PER_DAY,
    TRIGGERS,
)

MAX_NAME = 120
MAX_TEXT = 1000
RUN_STATUSES = ("running", "applied", "held", "confirmed", "dismissed", "depth_limited", "failed")


class RuleError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Definition:
    name: str
    description: str | None
    asset_id: str | None
    enabled: bool
    trigger: str
    trigger_params: dict[str, Any]
    condition: str
    actions: list[dict[str, Any]]
    confirm_over: int
    template: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "description": self.description, "asset_id": self.asset_id,
            "enabled": self.enabled, "trigger": self.trigger,
            "trigger_params": self.trigger_params, "condition": self.condition,
            "actions": self.actions, "confirm_over": self.confirm_over,
            "template": self.template,
        }  # fmt: skip


def _int(raw: Any, field: str, lo: int, hi: int, default: int | None = None) -> int:
    if raw in (None, "") and default is not None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, int) or not lo <= raw <= hi:
        raise RuleError(field, f"A whole number from {lo} to {hi}.")
    return raw


def _text(raw: Any, field: str, limit: int, *, required: bool = False) -> str | None:
    value = str(raw or "").strip()
    if required and not value:
        raise RuleError(field, "Required.")
    if len(value) > limit:
        raise RuleError(field, f"At most {limit} characters.")
    return value or None


def _trigger_params(trigger: str, raw: Any) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    if trigger == "project.quiet":
        return {"days": _int(raw.get("days"), "trigger_params.days", 1, 365)}
    if trigger == "schedule":
        every = raw.get("every") or "day"
        if every not in EVERY:
            raise RuleError("trigger_params.every", f"One of: {', '.join(EVERY)}.")
        out: dict[str, Any] = {"every": every}
        if every in ("day", "week"):
            out["hour"] = _int(raw.get("hour"), "trigger_params.hour", 0, 23, default=9)
        if every == "week":
            out["weekday"] = _int(raw.get("weekday"), "trigger_params.weekday", 0, 6, default=0)
        return out
    return {}


def _action(s: Session, org_id: str, subject: str, i: int, raw: Any) -> dict[str, Any]:
    field = f"actions.{i}"
    if not isinstance(raw, dict) or raw.get("type") not in ACTIONS:
        raise RuleError(f"{field}.type", f"One of: {', '.join(ACTIONS)}.")
    kind = raw["type"]
    spec = ACTIONS[kind]
    if subject not in spec.subjects:
        raise RuleError(
            f"{field}.type", f"“{spec.label}” needs an issue; this trigger is about a project."
        )
    if kind == "assign":
        to = str(raw.get("to") or "").strip().lstrip("@").lower()
        try:
            resolve(s, org_id, to)
        except AssignError as exc:
            raise RuleError(f"{field}.to", str(exc)) from exc
        return {"type": kind, "to": to}
    if kind == "set_priority":
        band = str(raw.get("band") or "").upper()
        if band not in BANDS:
            raise RuleError(f"{field}.band", f"One of: {', '.join(BANDS)}.")
        return {"type": kind, "band": band}
    if kind == "tag":
        names = raw.get("tags")
        if isinstance(names, str):
            names = [n for n in names.replace(",", " ").split() if n]
        if not isinstance(names, list) or not names:
            raise RuleError(f"{field}.tags", "One or more tags.")
        try:
            tags = list(dict.fromkeys(tag_service.normalize(n) for n in names))
        except tag_service.TagError as exc:
            raise RuleError(f"{field}.tags", str(exc)) from exc
        if len(tags) > 10:
            raise RuleError(f"{field}.tags", "At most 10 tags.")
        return {"type": kind, "tags": tags}
    if kind == "request_retest":
        return {"type": kind, "note": _text(raw.get("note"), f"{field}.note", 500)}
    if kind == "request_fix":
        cap = _int(raw.get("max_per_day"), f"{field}.max_per_day", 1, MAX_FIX_PER_DAY,
                   default=DEFAULT_FIX_PER_DAY)  # fmt: skip
        return {"type": kind, "max_per_day": cap}
    return {"type": kind, "message": _text(raw.get("message"), f"{field}.message", 500)}


def validate(s: Session, org_id: str, raw: dict[str, Any]) -> Definition:
    name = _text(raw.get("name"), "name", MAX_NAME, required=True)
    assert name is not None
    trigger = raw.get("trigger")
    if trigger not in TRIGGERS:
        raise RuleError("trigger", f"One of: {', '.join(TRIGGERS)}.")
    asset_id = raw.get("asset_id") or None
    if asset_id is not None and repo.get_asset(s, str(asset_id), org_id=org_id) is None:
        raise RuleError("asset_id", "No such project.")
    condition = str(raw.get("condition") or "").strip("\n")
    try:
        rego.check(condition)
    except rego.ConditionError as exc:
        raise RuleError("condition", str(exc)) from exc
    actions = raw.get("actions")
    if not isinstance(actions, list) or not actions:
        raise RuleError("actions", "At least one action.")
    if len(actions) > MAX_ACTIONS:
        raise RuleError("actions", f"At most {MAX_ACTIONS} actions.")
    subject = TRIGGERS[trigger].subject
    return Definition(
        name=name,
        description=_text(raw.get("description"), "description", MAX_TEXT),
        asset_id=asset_id,
        enabled=bool(raw.get("enabled", True)),
        trigger=trigger,
        trigger_params=_trigger_params(trigger, raw.get("trigger_params")),
        condition=condition,
        actions=[_action(s, org_id, subject, i, a) for i, a in enumerate(actions)],
        confirm_over=_int(
            raw.get("confirm_over"),
            "confirm_over",
            1,
            MAX_CONFIRM_OVER,
            default=DEFAULT_CONFIRM_OVER,
        ),
        template=_text(raw.get("template"), "template", 64),
    )


def _audit(s: Session, rule: AutomationRule, actor: str, action: str) -> None:
    repo.append_audit_entry(  # commits, with the rule
        s, actor=actor, action=action, target=f"rule:{rule.id}",
        payload={"org_id": rule.org_id, "version": rule.version, "name": rule.name,
                 "enabled": rule.enabled, "asset_id": rule.asset_id, "trigger": rule.trigger,
                 "trigger_params": rule.trigger_params, "condition": rule.condition,
                 "actions": rule.actions, "confirm_over": rule.confirm_over},
    )  # fmt: skip


def create(s: Session, org_id: str, d: Definition, *, actor: str) -> AutomationRule:
    now = _now()
    rule = AutomationRule(
        org_id=org_id, created_by=actor, updated_by=actor, created_at=now, updated_at=now,
        version=1, **d.to_dict(),
    )  # fmt: skip
    s.add(rule)
    s.flush()
    _audit(s, rule, actor, "rule.created")
    return rule


def update(s: Session, rule: AutomationRule, d: Definition, *, actor: str) -> AutomationRule:
    for key, value in d.to_dict().items():
        setattr(rule, key, value)
    rule.version += 1
    rule.updated_by, rule.updated_at = actor, _now()
    s.flush()
    _audit(s, rule, actor, "rule.updated")
    return rule


def set_enabled(s: Session, rule: AutomationRule, enabled: bool, *, actor: str) -> AutomationRule:
    if rule.enabled == enabled:
        return rule
    rule.enabled = enabled
    rule.version += 1
    rule.updated_by, rule.updated_at = actor, _now()
    s.flush()
    _audit(s, rule, actor, "rule.enabled" if enabled else "rule.disabled")
    return rule


def delete(s: Session, rule: AutomationRule, *, actor: str) -> None:
    rule.deleted_at, rule.enabled = _now(), False
    rule.updated_by, rule.updated_at = actor, _now()
    for run in s.scalars(select(RuleRun).where(RuleRun.rule_id == rule.id,
                                               RuleRun.status == "held")):  # fmt: skip
        run.status, run.decided_by, run.decided_at = "dismissed", actor, _now()
    s.flush()
    _audit(s, rule, actor, "rule.deleted")


def get(s: Session, org_id: str, rule_id: str) -> AutomationRule | None:
    return s.scalars(
        select(AutomationRule).where(
            AutomationRule.id == rule_id,
            AutomationRule.org_id == org_id,
            AutomationRule.deleted_at.is_(None),
        )
    ).one_or_none()


def list_rules(s: Session, org_id: str, asset_id: str | None = None) -> list[AutomationRule]:
    q = select(AutomationRule).where(
        AutomationRule.org_id == org_id, AutomationRule.deleted_at.is_(None)
    )
    if asset_id is not None:
        q = q.where(or_(AutomationRule.asset_id.is_(None), AutomationRule.asset_id == asset_id))
    return list(s.scalars(q.order_by(AutomationRule.created_at)))


def project_names(s: Session, org_id: str, ids: set[str]) -> dict[str, str]:
    if not ids:
        return {}
    q = select(Asset.id, Asset.label).where(Asset.org_id == org_id, Asset.id.in_(ids))
    return {i: label for i, label in s.execute(q)}


def get_run(s: Session, org_id: str, run_id: str) -> RuleRun | None:
    return s.scalars(
        select(RuleRun).where(RuleRun.id == run_id, RuleRun.org_id == org_id)
    ).one_or_none()


def runs(
    s: Session,
    org_id: str,
    *,
    rule_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[RuleRun]:
    q = select(RuleRun).where(RuleRun.org_id == org_id)
    if rule_id is not None:
        q = q.where(RuleRun.rule_id == rule_id)
    if status is not None:
        q = q.where(RuleRun.status == status)
    return list(s.scalars(q.order_by(RuleRun.created_at.desc(), RuleRun.id).limit(limit)))
