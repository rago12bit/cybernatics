"""Rules API (Week 65, plan §45): automation an Admin configures without writing code.

    GET    /v2/rules/catalogue                triggers, actions, the fields a condition can read
    GET    /v2/rules?project_id=              the organization's rules (and a project's own)
    POST   /v2/rules                          create          GET/PUT/DELETE /v2/rules/{id}
    PUT    /v2/rules/{id}/enabled             turn on or off
    POST   /v2/rules/test                     dry run a draft: "would have matched 37 issues"
    POST   /v2/rules/{id}/test                dry run a saved rule
    GET    /v2/rule-runs?rule_id=&status=     run history (held runs wait for an Admin)
    POST   /v2/rule-runs/{id}/confirm         apply a held run      POST .../dismiss
    GET    /v2/issues/{id}/assignee           who owns it, and any priority set by hand or rule
    PUT    /v2/issues/{id}/assignee           assign (or clear)
    PUT    /v2/issues/{id}/priority           set a priority band by hand (or clear it)

Reading is `scans:read`. Writing a rule, testing one, and deciding a held run is `rules:write` --
plan §45's "only Admins create rules" until roles exist (Week 75). Assigning and setting a priority
by hand is `scans:write`, like triage. Every change is audit-logged.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.deps import AuthContext, current_org, db, require_auth, require_scope
from api.retest import issue_for
from core.collab.assign import AssignError, assign
from core.collab.people import handle_of, names
from core.persistence.models import AutomationRule, IssueRow, RuleRun
from core.rules import engine, rego
from core.rules import service as rules
from core.rules.catalog import ACTIONS, TRIGGERS, catalogue

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class RuleIn(BaseModel):
    name: str = Field(max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    project_id: str | None = None
    enabled: bool = True
    trigger: str = Field(max_length=40)
    trigger_params: dict[str, Any] = Field(default_factory=dict)
    condition: str = Field(default="", max_length=8000)
    actions: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    confirm_over: int | None = None
    template: str | None = Field(default=None, max_length=64)


class RuleOut(BaseModel):
    id: str
    name: str
    description: str | None
    project_id: str | None
    project_name: str | None
    enabled: bool
    trigger: str
    trigger_label: str
    trigger_params: dict[str, Any]
    condition: str
    rego: str = Field(description="The whole module OPA evaluates")
    actions: list[dict[str, Any]]
    summary: list[str] = Field(description="WHEN, IF and THEN, in words")
    confirm_over: int
    version: int
    template: str | None
    created_by: str | None
    created_at: datetime
    updated_by: str | None
    updated_at: datetime
    last_fired_at: datetime | None
    names: dict[str, str]


class EnabledIn(BaseModel):
    enabled: bool


class SampleOut(BaseModel):
    id: str
    text: str
    project: str
    title: str | None = None
    severity: str | None = None
    priority_band: str | None = None
    asset_id: str | None = None


class DryRunOut(BaseModel):
    subject: str
    matched: int
    runs: int
    would_hold: int
    checked: int
    window_days: int
    sample: list[SampleOut]
    note: str
    sentence: str


class RunOut(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    rule_version: int
    trigger: str
    cause: str
    cause_label: str
    depth: int
    status: str
    subject_ids: list[str]
    subjects: list[SampleOut]
    results: list[dict[str, Any]]
    error: str | None
    created_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    names: dict[str, str]


class AssigneeIn(BaseModel):
    to: str | None = Field(default=None, max_length=80, description="@handle, or null to clear")


class PriorityIn(BaseModel):
    band: str | None = Field(default=None, description="P1-P4, or null for the computed band")


class OwnerOut(BaseModel):
    assignee: str | None
    assignee_name: str | None
    assignee_handle: str | None
    assigned_at: datetime | None
    priority_override: str | None
    priority_override_by: str | None
    computed_band: str | None
    names: dict[str, str]


def _bad(exc: Exception, field: str | None = None) -> HTTPException:
    return HTTPException(422, {"field": field or getattr(exc, "field", ""), "message": str(exc)})


def _project(project_id: str | None) -> None:
    if project_id is not None and not _UUID.match(project_id):
        raise HTTPException(422, {"field": "project_id", "message": "No such project."})


def _sentence(rule: AutomationRule, project: str | None) -> list[str]:
    trig = TRIGGERS.get(rule.trigger)
    when = trig.label if trig else rule.trigger
    p = rule.trigger_params or {}
    if rule.trigger == "project.quiet":
        when = f"No scan for {p.get('days')} days"
    elif rule.trigger == "schedule":
        every = p.get("every")
        hour = f"{int(p.get('hour', 9)):02d}:00 UTC"
        day = ["Mondays", "Tuesdays", "Wednesdays", "Thursdays", "Fridays", "Saturdays",
               "Sundays"][int(p.get("weekday", 0))]  # fmt: skip
        when = {"hour": "Every hour", "day": f"Every day at {hour}",
                "week": f"{day} at {hour}"}.get(str(every), "On a schedule")  # fmt: skip
    where = f" in {project}" if project else " in any project"
    lines = [f"WHEN {when[0].lower()}{when[1:]}{where}"]
    cond = [ln.strip() for ln in rule.condition.splitlines() if ln.strip()]
    lines.append("IF " + (" and ".join(cond) if cond else "always"))
    for a in rule.actions:
        label = ACTIONS[a["type"]].label if a["type"] in ACTIONS else a["type"]
        detail = {
            "assign": f"@{a.get('to')}", "set_priority": a.get("band"),
            "tag": ", ".join(a.get("tags") or []), "request_retest": "",
            "request_fix": f"(at most {a.get('max_per_day')} a day)",
            "notify": "Slack, Discord and the outbound webhook",
        }.get(a["type"], "")  # fmt: skip
        lines.append(f"THEN {label.lower()} {detail}".rstrip())
    return lines


def _out(s: Session, org: str, rule: AutomationRule) -> RuleOut:
    project = rules.project_names(s, org, {rule.asset_id}) if rule.asset_id else {}
    pname = project.get(rule.asset_id) if rule.asset_id else None
    actors = {a for a in (rule.created_by, rule.updated_by) if a}
    trig = TRIGGERS.get(rule.trigger)
    return RuleOut(
        id=rule.id, name=rule.name, description=rule.description, project_id=rule.asset_id,
        project_name=pname, enabled=rule.enabled, trigger=rule.trigger,
        trigger_label=trig.label if trig else rule.trigger, trigger_params=rule.trigger_params,
        condition=rule.condition, rego=rego.module(rule.condition), actions=rule.actions,
        summary=_sentence(rule, pname), confirm_over=rule.confirm_over, version=rule.version,
        template=rule.template, created_by=rule.created_by, created_at=rule.created_at,
        updated_by=rule.updated_by, updated_at=rule.updated_at, last_fired_at=rule.last_fired_at,
        names=names(s, org, actors),
    )  # fmt: skip


def cause_label(cause: str) -> str:
    kind, _, rest = cause.partition(":")
    if kind == "scan":
        return "a scan"
    if kind == "import":
        return "an import"
    if kind == "acceptance":
        return "a risk acceptance"
    if kind == "quiet":
        since = rest.split(":", 1)[1] if ":" in rest else ""
        return f"no scan since {since[:10]}" if since else "a quiet project"
    if kind == "schedule":
        return f"the schedule, {rest.replace('T', ' ')} UTC"
    return kind.replace("_", " ") if kind else cause


def _subjects(s: Session, org: str, run: RuleRun, limit: int = 20) -> list[SampleOut]:
    if run.trigger in TRIGGERS and TRIGGERS[run.trigger].subject == "project":
        found = rules.project_names(s, org, set(run.subject_ids[:limit]))
        return [SampleOut(id=i, text=found.get(i, i), project=found.get(i, i))
                for i in run.subject_ids[:limit]]  # fmt: skip
    from core.persistence.models import Asset

    rows = (
        s.query(IssueRow, Asset.label)
        .join(Asset, Asset.id == IssueRow.asset_id)
        .filter(Asset.org_id == org, IssueRow.id.in_(run.subject_ids[:limit]))
        .all()
    )
    by_id = {r.id: (r, label) for r, label in rows}
    out = []
    for i in run.subject_ids[:limit]:
        if i in by_id:
            r, label = by_id[i]
            out.append(SampleOut(id=r.id, text=r.title, project=label, title=r.title,
                                 severity=r.severity,
                                 priority_band=r.priority_override or r.priority_band,
                                 asset_id=r.asset_id))  # fmt: skip
    return out


def _run_out(s: Session, org: str, run: RuleRun, rule_name: str | None = None) -> RunOut:
    if rule_name is None:
        rule = s.get(AutomationRule, run.rule_id)
        rule_name = rule.name if rule else "(deleted)"
    return RunOut(
        id=run.id, rule_id=run.rule_id, rule_name=rule_name, rule_version=run.rule_version,
        trigger=run.trigger, cause=run.cause, cause_label=cause_label(run.cause), depth=run.depth,
        status=run.status, subject_ids=run.subject_ids or [], subjects=_subjects(s, org, run),
        results=run.results or [], error=run.error, created_at=run.created_at,
        decided_by=run.decided_by, decided_at=run.decided_at,
        names=names(s, org, {run.decided_by} if run.decided_by else set()),
    )  # fmt: skip


def _draft(body: RuleIn) -> dict[str, Any]:
    raw = body.model_dump()
    raw["asset_id"] = raw.pop("project_id")
    return raw


def _dry_out(d: engine.DryRun) -> DryRunOut:
    what = "issue" if d.subject == "issue" else "project"
    plural = "s" if d.matched != 1 else ""
    if d.subject == "issue" and d.checked and d.note.startswith("Checked against each"):
        sentence = (f"This rule would have matched {d.matched} {what}{plural} in the last "
                    f"{d.window_days} days")  # fmt: skip
    else:
        sentence = f"This rule would match {d.matched} {what}{plural} now"
    if d.would_hold:
        sentence += (f"; {d.would_hold} of its {d.runs} run{'s' if d.runs != 1 else ''} would "
                     "wait for an Admin to confirm")  # fmt: skip
    return DryRunOut(subject=d.subject, matched=d.matched, runs=d.runs, would_hold=d.would_hold,
                     checked=d.checked, window_days=d.window_days,
                     sample=[SampleOut(**x) for x in d.sample], note=d.note,
                     sentence=sentence + ".")  # fmt: skip


def _probe(org: str, d: rules.Definition, rule_id: str = "draft") -> AutomationRule:
    from datetime import timezone

    now = datetime.now(timezone.utc)
    return AutomationRule(id=rule_id, org_id=org, version=0, created_at=now, **d.to_dict())


def register_rules_routes(app: FastAPI) -> None:
    @app.get("/v2/rules/catalogue", tags=["rules"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def rules_catalogue() -> dict[str, Any]:
        return catalogue()

    @app.get("/v2/rules", response_model=list[RuleOut], tags=["rules"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def list_rules(
        project_id: str | None = Query(default=None),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[RuleOut]:
        _project(project_id)
        return [_out(s, org, r) for r in rules.list_rules(s, org, project_id)]

    @app.post("/v2/rules", response_model=RuleOut, status_code=201, tags=["rules"],
              dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def create_rule(
        body: RuleIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RuleOut:
        try:
            d = rules.validate(s, org, _draft(body))
        except rules.RuleError as exc:
            raise _bad(exc) from exc
        return _out(s, org, rules.create(s, org, d, actor=auth.actor))

    def _rule(s: Session, org: str, rule_id: str) -> AutomationRule:
        rule = rules.get(s, org, rule_id) if _UUID.match(rule_id) else None
        if rule is None:
            raise HTTPException(404, "rule not found")
        return rule

    @app.get("/v2/rules/{rule_id}", response_model=RuleOut, tags=["rules"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def get_rule(
        rule_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> RuleOut:
        return _out(s, org, _rule(s, org, rule_id))

    @app.put("/v2/rules/{rule_id}", response_model=RuleOut, tags=["rules"],
             dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def update_rule(
        rule_id: str,
        body: RuleIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RuleOut:
        rule = _rule(s, org, rule_id)
        try:
            d = rules.validate(s, org, _draft(body))
        except rules.RuleError as exc:
            raise _bad(exc) from exc
        return _out(s, org, rules.update(s, rule, d, actor=auth.actor))

    @app.put("/v2/rules/{rule_id}/enabled", response_model=RuleOut, tags=["rules"],
             dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def enable_rule(
        rule_id: str,
        body: EnabledIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RuleOut:
        rule = _rule(s, org, rule_id)
        return _out(s, org, rules.set_enabled(s, rule, body.enabled, actor=auth.actor))

    @app.delete("/v2/rules/{rule_id}", status_code=204, tags=["rules"],
                dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def delete_rule(
        rule_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> None:
        rules.delete(s, _rule(s, org, rule_id), actor=auth.actor)

    @app.post("/v2/rules/test", response_model=DryRunOut, tags=["rules"],
              dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def test_draft(
        body: RuleIn, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> DryRunOut:
        try:
            d = rules.validate(s, org, _draft(body))
            return _dry_out(engine.dry_run(s, org, _probe(org, d)))
        except rules.RuleError as exc:
            raise _bad(exc) from exc
        except rego.ConditionError as exc:
            raise _bad(exc, "condition") from exc

    @app.post("/v2/rules/{rule_id}/test", response_model=DryRunOut, tags=["rules"],
              dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def test_rule(
        rule_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> DryRunOut:
        rule = _rule(s, org, rule_id)
        try:
            return _dry_out(engine.dry_run(s, org, rule))
        except rego.ConditionError as exc:
            raise _bad(exc, "condition") from exc

    @app.get("/v2/rule-runs", response_model=list[RunOut], tags=["rules"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def list_runs(
        rule_id: str | None = Query(default=None),
        status: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
        s: Session = Depends(db),
        org: str = Depends(current_org),
    ) -> list[RunOut]:
        if status is not None and status not in rules.RUN_STATUSES:
            raise HTTPException(422, f"status is one of {', '.join(rules.RUN_STATUSES)}")
        if rule_id is not None and not _UUID.match(rule_id):
            return []
        rows = rules.runs(s, org, rule_id=rule_id, status=status, limit=limit)
        rule_names = {r.id: r.name for r in s.query(AutomationRule).filter(
            AutomationRule.org_id == org,
            AutomationRule.id.in_({x.rule_id for x in rows})).all()}  # fmt: skip
        return [_run_out(s, org, r, rule_names.get(r.rule_id, "(deleted)")) for r in rows]

    def _held(s: Session, org: str, run_id: str) -> RuleRun:
        run = rules.get_run(s, org, run_id) if _UUID.match(run_id) else None
        if run is None:
            raise HTTPException(404, "run not found")
        return run

    @app.get("/v2/rule-runs/{run_id}", response_model=RunOut, tags=["rules"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def get_run(run_id: str, s: Session = Depends(db), org: str = Depends(current_org)) -> RunOut:
        return _run_out(s, org, _held(s, org, run_id))

    @app.post("/v2/rule-runs/{run_id}/confirm", response_model=RunOut, tags=["rules"],
              dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def confirm_run(
        run_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RunOut:
        try:
            run = engine.confirm(s, org, _held(s, org, run_id), actor=auth.actor)
        except engine.RunError as exc:
            raise HTTPException(409, str(exc)) from exc
        return _run_out(s, org, run)

    @app.post("/v2/rule-runs/{run_id}/dismiss", response_model=RunOut, tags=["rules"],
              dependencies=[Depends(require_scope("rules:write"))])  # fmt: skip
    def dismiss_run(
        run_id: str,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> RunOut:
        try:
            run = engine.dismiss(s, org, _held(s, org, run_id), actor=auth.actor)
        except engine.RunError as exc:
            raise HTTPException(409, str(exc)) from exc
        return _run_out(s, org, run)

    # --- an Issue's owner and priority --------------------------------------------------------

    def _owner(s: Session, org: str, issue: IssueRow) -> OwnerOut:
        actors = {a for a in (issue.assignee, issue.priority_override_by) if a}
        who = names(s, org, actors)
        return OwnerOut(
            assignee=issue.assignee,
            assignee_name=who.get(issue.assignee) if issue.assignee else None,
            assignee_handle=handle_of(who[issue.assignee])
            if issue.assignee and issue.assignee in who else None,
            assigned_at=issue.assigned_at, priority_override=issue.priority_override,
            priority_override_by=issue.priority_override_by, computed_band=issue.priority_band,
            names={**who, **_rule_names(s, org, actors)},
        )  # fmt: skip

    @app.get("/v2/issues/{issue_id}/assignee", response_model=OwnerOut, tags=["rules"],
             dependencies=[Depends(require_scope("scans:read"))])  # fmt: skip
    def get_owner(
        issue_id: str, s: Session = Depends(db), org: str = Depends(current_org)
    ) -> OwnerOut:
        return _owner(s, org, issue_for(s, issue_id, org))

    @app.put("/v2/issues/{issue_id}/assignee", response_model=OwnerOut, tags=["rules"],
             dependencies=[Depends(require_scope("scans:write"))])  # fmt: skip
    def set_owner(
        issue_id: str,
        body: AssigneeIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> OwnerOut:
        issue = issue_for(s, issue_id, org)
        try:
            assign(s, issue, body.to or None, actor=auth.actor)
        except AssignError as exc:
            s.rollback()
            raise _bad(exc) from exc
        return _owner(s, org, issue)

    @app.put("/v2/issues/{issue_id}/priority", response_model=OwnerOut, tags=["rules"],
             dependencies=[Depends(require_scope("scans:write"))])  # fmt: skip
    def set_priority(
        issue_id: str,
        body: PriorityIn,
        s: Session = Depends(db),
        org: str = Depends(current_org),
        auth: AuthContext = Depends(require_auth),
    ) -> OwnerOut:
        from core.priority.service import set_override

        issue = issue_for(s, issue_id, org)
        band = body.band.upper() if body.band else None
        try:
            set_override(s, issue, band, actor=auth.actor, org_id=org)
        except ValueError as exc:
            raise _bad(exc, "band") from exc
        return _owner(s, org, issue)


def _rule_names(s: Session, org: str, actors: set[str]) -> dict[str, str]:
    """`rule:<id>` -> "the rule “<name>”", for actors that are rules."""
    ids = [a.split(":", 1)[1] for a in actors if a.startswith("rule:")]
    if not ids:
        return {}
    rows = s.query(AutomationRule.id, AutomationRule.name).filter(
        AutomationRule.org_id == org, AutomationRule.id.in_(ids)
    )
    return {f"rule:{i}": f"the rule “{n}”" for i, n in rows}
