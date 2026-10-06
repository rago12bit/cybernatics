# Metrics

Every number on a dashboard, defined (plan §48.1). Generated from
`core/metrics/definitions.py`; the same text is each widget's tooltip.

"Open" means: an Issue a scan or import still reports (new, open or reintroduced) that
a person has not marked not a risk and has no risk acceptance in force. Bands are each
Issue's priority band as it stands now, a band set by hand winning over the computed one.
Metrics are read from summary tables refreshed when Issues change
([ADR-0054](adr/0054-metrics-layer.md)), never computed from Occurrences on page load.

| Metric | Definition | Period applies |
|---|---|---|
| **Open issues by priority** (`open_issues`) | Open Issues now, by priority band. Excludes Issues marked not a risk and Issues with a risk acceptance in force. | no |
| **SLA adherence** (`sla_adherence`) | Issues fixed within their SLA, divided by Issues whose SLA deadline fell in the period (fixed in time + fixed late + still open past the deadline), under each project's current SLA policy. Exempt Issues (not a risk, or accepted) are left out. Projects without an SLA policy are not counted. | yes |
| **Mean time to remediate** (`mttr`) | Mean of (fixed − first seen) over Issues fixed in the period, in days, by priority band. | yes |
| **New versus fixed** (`new_vs_fixed`) | Issues first seen in each week of the period, and Issues fixed in each week. | yes |
| **Open risk** (`open_risk`) | Sum of the priority scores of open Issues, excluding accepted risk. The burndown is the same sum at the end of each week, from when each Issue was first seen and fixed, counting Issues as they are classified now. | yes |
| **Backlog age** (`backlog_age`) | Median age, in days, of open Issues, with how many are older than 30, 90 and 180 days. | no |
| **Past SLA** (`past_sla`) | Open Issues past their SLA deadline, the most overdue first. | no |
| **Scan coverage** (`scan_coverage`) | Projects with a successful full scan in the last 30 days, divided by all projects that have ever been scanned. For each project, the scanners that ran out of those that applied to its files in its last scan. | no |
| **Most vulnerable components** (`vulnerable_components`) | Libraries ranked by the number of projects whose current SBOM has an affected version; for each, the most vulnerabilities any one of those versions has, and how many projects have a known-exploited one. | no |
| **Expiring risk acceptances** (`expiring_acceptances`) | Approved risk acceptances that expire in the next 30 days, the soonest first. | no |
| **Engagement status** (`engagement_status`) | Penetration tests, audits and ad hoc assessments by status, with the active ones and their target end dates. | no |
| **Advisory impact** (`advisory_impact`) | Vulnerabilities that first affected a project in the period: how many, how many are known exploited, and how many no one has acted on yet. | yes |
