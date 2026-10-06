# ADR-0054: Metrics from summary tables refreshed on ingest, every one defined, measured at one million Occurrences

Status: Accepted (2026-10-06), Weeks 70–71 (plan §48.1, §48.2, §60). The plan calls this "ADR-021";
that number was already taken by [ADR-0021](0021-taint-analysis.md). Builds on
[ADR-0013](0013-tenancy-row-level-security.md) (forced RLS), [ADR-0046](0046-sla-and-risk-acceptance.md)
(SLAs and risk acceptance) and [ADR-0052](0052-advisory-engine.md) (advisory impacts).

## Context

Plan §48.1: dashboards read "materialized views refreshed on ingest", and every metric has "a
written definition". §55.4: every number opens the Issues behind it, and a percentage always shows
its counts. Week 70: a synthetic dataset with one million Occurrences, with widget latency measured.
The budget, from §60 and the task, is 300 ms at the 95th percentile for every widget.

Computing a dashboard from Occurrences on page load fails twice. It is too slow at this size, and
each widget would calculate "open" its own way.

## Decision

**Ordinary tables, not materialized views.** Postgres materialized views cannot have row-level
security, and `REFRESH MATERIALIZED VIEW` rebuilds every organization at once. Every v3 table is
under forced RLS (ADR-0013), so the summaries are ordinary tables with the same `tenant_isolation`
policy. They are refreshed one project at a time by the application, as `bulwark_worker`. Migration
0042 creates six:

| Table | One row per | Holds |
|---|---|---|
| `metric_open_issues` | open Issue | band, severity, priority score, first seen, SLA deadline |
| `metric_issue_days` | project × day × band | opened, fixed, total time to fix, risk opened and fixed |
| `metric_sla_days` | project × deadline day × band | met, missed, still open past deadline, exempt |
| `metric_asset_status` | project | last full scan, scanners that ran of those that applied |
| `metric_components` | library × project | vulnerabilities, known-exploited ones |
| `metric_dirty` | project (or "components") | when it was marked |

Their organization foreign key cascades. They are derived data, and deleting an organization must
not need to know about them.

**One meaning of "open".** An Issue is open when a scan or import still reports it (new, open or
reintroduced), nobody has marked it not a risk, and no risk acceptance is in force. A row's band is
the band set by hand if there is one, else the computed one. `core.metrics.rollup` is the only code
that applies these rules, and every metric reads its output.

**Refreshed on ingest, and marked automatically.** An `after_flush` listener marks a project dirty
whenever anything it touches changes in a session: an Issue, an SLA policy, the project itself, or a
scan. Advisory impact changes mark the organization's components. The mark is written in the same
transaction, so code that changes Issues cannot forget to mark them. A mark records when it was made.
A refresh clears only marks made before it read the project, so a change made during a refresh stays
dirty. What is dirty is refreshed:

- straight away, after a full scan completes (`core.pipeline`) and after an import is applied
  (`core.imports.jobs`). This is "refreshed on ingest";
- every 120 s on the worker (`bulwark.refresh_metrics`) for everything else, such as triage,
  priority changes and SLA policy edits;
- for every project of every organization once an hour (`bulwark.refresh_metrics_all`). An
  acceptance that expires changes what is open without changing any row;
- on demand with `bulwark metrics refresh [--org]`.

A project is rebuilt from all of its Issues in one pass. That takes 50 ms for a project of 1,250
Issues, and it is simpler to reason about than incremental deltas. Each response carries
`pending_refresh`, the number of projects waiting, so a stale number is labelled as stale.

**One source of definitions.** `core/metrics/definitions.py` holds the twelve metrics, each with
its name, written definition, unit, whether the date range applies, and the table it reads. The API
serves the definitions to each widget's title, and `docs/metrics.md` is generated from the same file.
A test fails if the two differ.

**Every number is traceable.** Each metric returns its value with the counts behind it ("195 of
214"), plus rows or a weekly series. Each row carries a drill-down: the filter that
`GET /v2/metrics/issues` uses to list the Issues behind it, one page at a time.

**Filters.** Portfolios, projects, a tag, and a date range of up to 731 days (90 by default). A tag
selects whatever carries it, following the same inheritance rule as tags themselves: tagged
projects, projects in tagged portfolios, and tagged Issues. Metrics that read per Issue honour all
three. Metrics that read per project and day honour project and portfolio tags only, and their
`notes` say so.

## Measurement

`scripts/bench-metrics.py` seeds an organization inside Postgres using `generate_series`:

- 200 projects in 10 portfolios, each with 1,250 Issues: 250,000 Issues;
- 4 scans per project, each finding every Issue: **1,000,000 Occurrences**;
- a year of history, about half of it fixed, 5% marked not a risk;
- SLA policies, tags on 2 portfolios and on 1% of Issues;
- 2,000 libraries, 150,000 advisory impacts, 5,000 advisory states;
- risk acceptances and engagements.

It then runs `VACUUM ANALYZE`, refreshes every project as the worker would, and times every metric
20 times (after a warm-up) under five filter variants, plus the first page of Issues behind a
number. The results are in
[`benchmarks/metrics/one-million-occurrences.json`](../../benchmarks/metrics/one-million-occurrences.json).
They were measured on an Apple M5 with 16 GB, against Postgres 16.15 in Docker, connected as
`bulwark_worker` under forced RLS.

Seeding took 32 s. Refreshing all 200 projects took 13.3 s, and one project 0.05 s.

Milliseconds, p50 / p95:

| Metric | No filter | Portfolio | Project | Project tag | Issue tag |
|---|---:|---:|---:|---:|---:|
| `open_issues` | 13.9 / 15.4 | 3.6 / 4.5 | 2.0 / 3.1 | 5.6 / 6.0 | 18.6 / 29.4 |
| `sla_adherence` | 11.5 / 15.4 | 5.4 / 7.6 | 2.6 / 3.6 | 34.4 / 39.4 | 3.1 / 13.6 |
| `mttr` | 68.2 / 79.7 | 8.6 / 9.0 | 3.2 / 4.5 | 60.3 / 76.8 | 3.2 / 3.9 |
| `new_vs_fixed` | 10.3 / 11.8 | 4.5 / 5.5 | 4.1 / 4.6 | 40.6 / 44.4 | 3.1 / 5.3 |
| `open_risk` | 27.3 / 29.4 | 8.3 / 9.5 | 5.6 / 8.9 | 13.7 / 14.8 | 18.7 / 29.0 |
| `backlog_age` | 30.8 / 32.2 | 34.7 / 39.5 | 4.7 / 6.2 | 56.3 / 62.1 | 87.5 / 99.1 |
| `past_sla` | 8.3 / 9.1 | 5.0 / 5.7 | 3.9 / 5.1 | 7.0 / 9.4 | 27.5 / 39.4 |
| `scan_coverage` | 1.8 / 2.0 | 1.4 / 1.5 | 1.1 / 1.2 | 1.9 / 2.0 | 2.8 / 4.5 |
| `vulnerable_components` | 2.7 / 3.0 | 2.4 / 2.6 | 2.1 / 2.2 | 3.0 / 3.4 | 3.8 / 15.5 |
| `expiring_acceptances` | 14.6 / 16.2 | 3.3 / 3.6 | 1.0 / 1.0 | 6.0 / 6.2 | 2.7 / 4.7 |
| `engagement_status` | 1.7 / 2.1 | 1.1 / 1.2 | 1.0 / 1.2 | 1.6 / 1.8 | 2.7 / 13.4 |
| `advisory_impact` | 23.8 / 31.5 | 12.8 / 16.0 | 12.3 / 13.6 | 21.0 / 23.7 | 3.5 / 6.5 |

| The Issues behind a number (first page, P1) | p50 / p95 |
|---|---:|
| `open` | 1.7 / 1.8 |
| `past_sla` | 1.8 / 3.8 |
| `fixed` | 116.7 / 123.6 |

**Every widget is within the 300 ms budget. The slowest metric is 99 ms at p95** (backlog age with
an Issue tag). The slowest request overall is 124 ms: the Issues fixed in a period, which reads the
live `issues` table because no summary row holds individual fixed Issues.

These timings are for the query layer: `query.compute` and `query.issues` in the worker's session.
HTTP and JSON add a few milliseconds for responses this small. The browser's own budget, a widget
drawn within 300 ms of its data arriving (§60), is checked separately in the Weeks 70–71
verification.

**What the benchmark changed.** The first full run found three problems:

1. *Advisory impact took up to 634 ms* with a project filter, even on a small dataset. It checked
   each impact against lists of 500 vulnerability keys at a time. It is now a single join with
   `advisory_states`, which Postgres hashes.
2. *The Issues behind a number took up to 294 ms.* Under RLS, Postgres cannot estimate a join on
   `assets` (`org_id = current_setting(...)` is one row as far as it knows), so it walked every
   Issue of the organization to fetch 51. The drill-down now looks up Issues by id, gets project
   names separately, and passes the organization's projects as a list. The result is 2 ms for open
   Issues and 124 ms for fixed ones.
3. *That first run was taken while autovacuum was still working through the newly loaded tables.*
   Its numbers ran up to 238 ms for metrics that take 62 ms on a table at rest. The benchmark now
   runs `VACUUM ANALYZE` first (without parallel workers, since Docker's default 64 MB `/dev/shm`
   is too small for them). A real database is mostly at rest, but a large import followed by an
   immediate dashboard load can see the slower numbers for a few minutes.

## Consequences

- A dashboard number can be up to two minutes behind a triage change (one beat interval), and up to
  an hour behind an acceptance expiring. `pending_refresh` shows when that is happening. Scans and
  imports are reflected as soon as they finish.
- Twelve metrics share one meaning of "open". A new metric reads the summary tables, gains a
  definition and a section in `docs/metrics.md`, and gets a row in the benchmark.
- Refreshing a project costs one pass over its Issues. A 20,000-Issue project would take about
  1 s per refresh, still fine for the worker. If projects grow much larger than that,
  incremental updates become worth their complexity.
- The summary tables are in the RLS test (`tests/integration/test_metrics_rls_docker.py`). Each one
  is seeded for one organization and must be invisible to another, and the test fails for each
  table when its policy is removed.
- Reproduce the benchmark with:
  `python scripts/bench-metrics.py --projects 200 --issues 1250 --out results.json`, with
  `BULWARK_BENCH_OWNER_URL` and `BULWARK_BENCH_APP_URL` pointing at a Postgres database at the
  current migration.
