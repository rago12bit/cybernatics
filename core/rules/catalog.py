"""What a rule can react to and what it can do (plan §45).

Each trigger names the outbox events that fire it (or none, for the two the sweep fires: a quiet
project and a schedule) and its subject: an Issue, or a project. Each action names the subjects it
can act on, so a rule whose trigger has no Issue cannot try to tag one. The editor and the API read
this catalogue; nothing else lists triggers or actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Trigger:
    key: str
    label: str
    subject: str  # "issue" | "project"
    events: tuple[str, ...] = ()
    params: tuple[str, ...] = ()
    help: str = ""


@dataclass(frozen=True)
class Action:
    key: str
    label: str
    subjects: tuple[str, ...]
    params: tuple[str, ...] = ()
    help: str = ""
    fields: dict[str, str] = field(default_factory=dict)


TRIGGERS: dict[str, Trigger] = {
    t.key: t
    for t in (
        Trigger("issue.created", "An issue is found", "issue", ("issue.created",),
                help="A scan, an import or a person reported an issue for the first time."),
        Trigger("issue.reopened", "An issue comes back", "issue", ("issue.reopened",),
                help="Something reports an issue that had been fixed."),
        Trigger("issue.closed", "An issue is fixed", "issue", ("issue.closed",),
                help="The source that reported it no longer does."),
        Trigger("issue.assigned", "An issue is assigned", "issue", ("issue.assigned",)),
        Trigger("issue.retest_requested", "A retest is requested", "issue",
                ("issue.retest_requested",)),
        Trigger("issue.retest_decided", "A retest is decided", "issue",
                ("issue.retest_passed", "issue.retest_failed"),
                help="A person, a scan or a targeted retest passed or failed it."),
        Trigger("sla.due_soon", "An SLA is due soon", "issue", ("sla.due_soon",)),
        Trigger("sla.breached", "An SLA is breached", "issue", ("sla.breached",)),
        Trigger("risk_acceptance.expiring", "A risk acceptance expires within 7 days", "issue",
                ("risk_acceptance.expiring",),
                help="Once per acceptance, seven days before its date. Fires for each Issue."),
        Trigger("risk_acceptance.expired", "A risk acceptance expires", "issue",
                ("risk_acceptance.expired",), help="Its Issues are open again."),
        Trigger("scan.completed", "A scan or import completes", "project", ("scan.completed",),
                help="input.scan has its counts."),
        Trigger("project.quiet", "No scan for N days", "project", params=("days",),
                help="Once per quiet stretch: a scan starts the count again."),
        Trigger("schedule", "On a schedule", "issue", params=("every", "hour", "weekday"),
                help="Checks every open Issue in scope at the time given (UTC)."),
    )
}  # fmt: skip

ACTIONS: dict[str, Action] = {
    a.key: a
    for a in (
        Action("assign", "Assign to", ("issue",), ("to",),
               help="A person's @handle. Replaces the current assignee."),
        Action("set_priority", "Set priority", ("issue",), ("band",),
               help="P1 to P4. Overrides the computed band; the SLA follows it when the project's "
                    "SLA is by priority."),
        Action("tag", "Add tags", ("issue",), ("tags",)),
        Action("request_retest", "Mark ready for retest", ("issue",), ("note",)),
        Action("request_fix", "Request a verified fix", ("issue",), ("max_per_day",),
               help="Starts the verified-fix agent. Counts against the AI budget, and at most "
                    "max_per_day (default 3) per rule per day."),
        Action("group", "Put in a group", ("issue",), ("name",),
               help="The project's group of that name, made if it does not exist. One ticket "
                    "tracks a group."),
        Action("ticket", "File or update its ticket", ("issue",), (),
               help="Where the project's ticket settings say: Jira or GitHub Issues. An issue in "
                    "a group goes on the group's ticket."),
        Action("notify", "Notify", ("issue", "project"), ("message", "people"),
               help="Posts to the team channels (Slack, Discord, Teams, the webhook) as the team "
                    "chose; people named get it in their inbox and by email as they chose."),
    )
}  # fmt: skip

BANDS = ("P1", "P2", "P3", "P4")
EVERY = ("hour", "day", "week")
MAX_ACTIONS = 8
MAX_DEPTH = 3
DEFAULT_CONFIRM_OVER = 25
MAX_CONFIRM_OVER = 1000
DEFAULT_FIX_PER_DAY = 3
MAX_FIX_PER_DAY = 20

#: Fields `input` carries, for the editor's condition builder and the docs. Every one is present
#: for its subject; one with no value is absent rather than null.
INPUT_FIELDS: dict[str, list[tuple[str, str]]] = {
    "issue": [
        ("input.issue.severity", "CRITICAL, HIGH, MEDIUM, LOW or INFO"),
        ("input.issue.priority_band", "P1 to P4 (an override if one is set)"),
        ("input.issue.priority_score", "0 to 100"),
        ("input.issue.category", "sast, sca, secrets, iac, dast ..."),
        ("input.issue.state", "new, open, fixed or reintroduced"),
        ("input.issue.triage_status", "open, not_a_risk or accepted"),
        ("input.issue.title", "text"),
        ("input.issue.path", "file or URL"),
        ("input.issue.rule_id", "the scanner's rule"),
        ("input.issue.tool", "the scanner that reported it"),
        ("input.issue.cwe", "list, e.g. CWE-89"),
        ("input.issue.in_cisa_kev", "true or false"),
        ("input.issue.reachable", "true or false (absent if unknown)"),
        ("input.issue.tags", "list: its own, its project's and portfolio's"),
        ("input.issue.assignee", "a person's @handle (absent if nobody)"),
        ("input.issue.source", "scanner, manual, import ..."),
        ("input.issue.age_days", "days since first detection"),
        ("input.issue.sla.state", "on_track, due_soon, breached, exempt or none"),
    ],
    "project": [
        ("input.project.name", "text"),
        ("input.project.tags", "list, including the portfolio's"),
        ("input.project.portfolio", "the portfolio's name (absent if none)"),
        ("input.project.internet_facing", "true or false (absent if not set)"),
        ("input.project.data_sensitivity", "low, medium or high"),
        ("input.project.criticality", "low, medium or high"),
        ("input.project.days_since_scan", "whole days (project.quiet only)"),
    ],
    "event": [
        ("input.event.type", "e.g. issue.created"),
        ("input.event.source", "scan or import, when a scan or import caused it"),
        ("input.scan.counts.new", "scan.completed only"),
    ],
}


def catalogue() -> dict[str, Any]:
    return {
        "triggers": [
            {"key": t.key, "label": t.label, "subject": t.subject, "params": list(t.params),
             "help": t.help}
            for t in TRIGGERS.values()
        ],
        "actions": [
            {"key": a.key, "label": a.label, "subjects": list(a.subjects),
             "params": list(a.params), "help": a.help}
            for a in ACTIONS.values()
        ],
        "fields": {k: [{"path": p, "help": h} for p, h in v] for k, v in INPUT_FIELDS.items()},
        "limits": {"max_actions": MAX_ACTIONS, "max_depth": MAX_DEPTH,
                   "default_confirm_over": DEFAULT_CONFIRM_OVER,
                   "max_confirm_over": MAX_CONFIRM_OVER},
    }  # fmt: skip
