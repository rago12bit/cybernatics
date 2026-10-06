"""Every metric a dashboard shows, with its written definition (plan §48.1). One place: the API
serves these to the widgets' tooltips, and `docs/metrics.md` is generated from them (a test keeps
the two the same).

"Open" everywhere means: an Issue a scan or import still reports (new, open or reintroduced) that a
person has not marked not a risk and has no risk acceptance in force. Bands are each Issue's
priority band (P1-P4) as it stands now, a band set by hand winning over the computed one.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Metric:
    id: str
    name: str
    definition: str
    unit: str  # count | percent | days | score | list
    period: bool  # whether the date range applies
    source: str  # the summary table(s) it reads


METRICS: tuple[Metric, ...] = (
    Metric(
        "open_issues",
        "Open issues by priority",
        "Open Issues now, by priority band. Excludes Issues marked not a risk and Issues with a "
        "risk acceptance in force.",
        "count",
        False,
        "metric_open_issues",
    ),
    Metric(
        "sla_adherence",
        "SLA adherence",
        "Issues fixed within their SLA, divided by Issues whose SLA deadline fell in the period "
        "(fixed in time + fixed late + still open past the deadline), under each project's "
        "current SLA policy. Exempt Issues (not a risk, or accepted) are left out. Projects "
        "without an SLA policy are not counted.",
        "percent",
        True,
        "metric_sla_days",
    ),
    Metric(
        "mttr",
        "Mean time to remediate",
        "Mean of (fixed − first seen) over Issues fixed in the period, in days, by priority "
        "band.",
        "days",
        True,
        "metric_issue_days",
    ),
    Metric(
        "new_vs_fixed",
        "New versus fixed",
        "Issues first seen in each week of the period, and Issues fixed in each week.",
        "count",
        True,
        "metric_issue_days",
    ),
    Metric(
        "open_risk",
        "Open risk",
        "Sum of the priority scores of open Issues, excluding accepted risk. The burndown is the "
        "same sum at the end of each week, from when each Issue was first seen and fixed, "
        "counting Issues as they are classified now.",
        "score",
        True,
        "metric_open_issues, metric_issue_days",
    ),
    Metric(
        "backlog_age",
        "Backlog age",
        "Median age, in days, of open Issues, with how many are older than 30, 90 and 180 days.",
        "days",
        False,
        "metric_open_issues",
    ),
    Metric(
        "past_sla",
        "Past SLA",
        "Open Issues past their SLA deadline, the most overdue first.",
        "list",
        False,
        "metric_open_issues",
    ),
    Metric(
        "scan_coverage",
        "Scan coverage",
        "Projects with a successful full scan in the last 30 days, divided by all projects that "
        "have ever been scanned. For each project, the scanners that ran out of those that "
        "applied to its files in its last scan.",
        "percent",
        False,
        "metric_asset_status",
    ),
    Metric(
        "vulnerable_components",
        "Most vulnerable components",
        "Libraries ranked by the number of projects whose current SBOM has an affected version; "
        "for each, the most vulnerabilities any one of those versions has, and how many projects "
        "have a known-exploited one.",
        "list",
        False,
        "metric_components",
    ),
    Metric(
        "expiring_acceptances",
        "Expiring risk acceptances",
        "Approved risk acceptances that expire in the next 30 days, the soonest first.",
        "list",
        False,
        "risk_acceptances",
    ),
    Metric(
        "engagement_status",
        "Engagement status",
        "Penetration tests, audits and ad hoc assessments by status, with the active ones and "
        "their target end dates.",
        "count",
        False,
        "engagements",
    ),
    Metric(
        "advisory_impact",
        "Advisory impact",
        "Vulnerabilities that first affected a project in the period: how many, how many are "
        "known exploited, and how many no one has acted on yet.",
        "count",
        True,
        "advisory_states, advisory_impacts",
    ),
)

BY_ID = {m.id: m for m in METRICS}


def markdown() -> str:
    """`docs/metrics.md`, generated from the definitions above."""
    lines = [
        "# Metrics",
        "",
        "Every number on a dashboard, defined (plan §48.1). Generated from",
        "`core/metrics/definitions.py`; the same text is each widget's tooltip.",
        "",
        '"Open" means: an Issue a scan or import still reports (new, open or reintroduced) that',
        "a person has not marked not a risk and has no risk acceptance in force. Bands are each",
        "Issue's priority band as it stands now, a band set by hand winning over the computed one.",
        "Metrics are read from summary tables refreshed when Issues change",
        "([ADR-0054](adr/0054-metrics-layer.md)), never computed from Occurrences on page load.",
        "",
        "| Metric | Definition | Period applies |",
        "|---|---|---|",
    ]
    for m in METRICS:
        lines.append(
            f"| **{m.name}** (`{m.id}`) | {m.definition} | {'yes' if m.period else 'no'} |"
        )
    return "\n".join(lines) + "\n"
