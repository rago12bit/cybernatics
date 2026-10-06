"""The template gallery (plan §45: "a template gallery ships common rules, so nobody starts from a
blank editor"). Each template is a whole draft the editor opens, plus what it still needs from you
(a person to assign, say). Every condition here compiles under the same OPA checks as any rule;
a test holds that.
"""

from __future__ import annotations

from typing import Any

TEMPLATES: list[dict[str, Any]] = [
    {
        "key": "critical-to-oncall",
        "name": "Critical issues go to the on-call",
        "description": "Assign every new critical issue to one person and make it P1.",
        "needs": ["actions.0.to"],
        "draft": {
            "trigger": "issue.created",
            "condition": 'input.issue.severity == "CRITICAL"',
            "actions": [{"type": "assign", "to": ""}, {"type": "set_priority", "band": "P1"}],
        },
    },
    {
        "key": "kev-first",
        "name": "Known-exploited vulnerabilities first",
        "description": "Anything on CISA's KEV list becomes P1 and is tagged, whatever its score.",
        "needs": [],
        "draft": {
            "trigger": "issue.created",
            "condition": "input.issue.in_cisa_kev == true",
            "actions": [{"type": "set_priority", "band": "P1"}, {"type": "tag", "tags": ["kev"]}],
        },
    },
    {
        "key": "payments-p1-ticket",
        "name": "P1 in a payments project: file a ticket and tell the team",
        "description": "The plan's own example. Needs the project's ticket settings.",
        "needs": [],
        "draft": {
            "trigger": "issue.created",
            "condition": 'input.issue.priority_band == "P1"\ninput.project.tags[_] == "payments"',
            "actions": [{"type": "ticket"}, {"type": "notify", "message": "A P1 in payments."}],
        },
    },
    {
        "key": "sla-breached",
        "name": "Tell the team when an SLA is breached",
        "description": "Tag the issue and post to the team channels.",
        "needs": [],
        "draft": {
            "trigger": "sla.breached",
            "condition": "",
            "actions": [{"type": "tag", "tags": ["sla-breached"]}, {"type": "notify"}],
        },
    },
    {
        "key": "quiet-project",
        "name": "A project has not been scanned for two weeks",
        "description": "The quiet failure: a pipeline that stopped scanning says nothing.",
        "needs": [],
        "draft": {
            "trigger": "project.quiet",
            "trigger_params": {"days": 14},
            "condition": "",
            "actions": [{"type": "notify", "message": "Is its pipeline still running?"}],
        },
    },
    {
        "key": "retest-failed",
        "name": "A retest failed",
        "description": "Tag it and tell the people you name, so a reproduced issue is not missed.",
        "needs": ["actions.1.people"],
        "draft": {
            "trigger": "issue.retest_decided",
            "condition": 'input.event.type == "issue.retest_failed"',
            "actions": [
                {"type": "tag", "tags": ["retest-failed"]},
                {"type": "notify", "people": []},
            ],
        },
    },
    {
        "key": "group-dependencies",
        "name": "One ticket for dependency upgrades",
        "description": "Put every new dependency issue in one group, so one ticket tracks them.",
        "needs": [],
        "draft": {
            "trigger": "issue.created",
            "condition": 'input.issue.category == "sca"',
            "actions": [{"type": "group", "name": "Dependency upgrades"}],
        },
    },
    {
        "key": "weekly-unowned",
        "name": "Monday: high issues nobody owns",
        "description": "Mondays at 09:00 UTC: open high and critical issues with no assignee.",
        "needs": [],
        "draft": {
            "trigger": "schedule",
            "trigger_params": {"every": "week", "weekday": 0, "hour": 9},
            "condition": 'input.issue.severity in {"HIGH", "CRITICAL"}\nnot input.issue.assignee',
            "actions": [{"type": "notify", "message": "High issues with no owner."}],
            "confirm_over": 200,
        },
    },
    {
        "key": "acceptance-expiring",
        "name": "A risk acceptance expires within a week",
        "description": "Tag its issues so the owners plan the fix before they reopen.",
        "needs": [],
        "draft": {
            "trigger": "risk_acceptance.expiring",
            "condition": "",
            "actions": [{"type": "tag", "tags": ["acceptance-expiring"]}],
        },
    },
]


def gallery() -> list[dict[str, Any]]:
    return [
        {**t, "draft": {"name": t["name"], "template": t["key"], **t["draft"]}} for t in TEMPLATES
    ]
