# Benchmarks

Reproduce with `benchmarks/run.sh <label>` (needs Docker, the scanner images and network for the
git clones). Each run writes versioned JSON to `benchmarks/results/`.

## Deduplication rate (design doc §10.2, metric 1)

`dedup rate = 1 - unique / raw`, where *raw* is the sum of every scanner's findings and *unique* is
what remains after cross-tool correlation ([ADR-004](../docs/adr/0004-fingerprinting-and-correlation.md)).

Measured 2026-09-25, default branch HEAD of each repo, all five scanners, correlation parameters
`line_window=3`, `snippet_overlap=0.8`, `min_tokens=4`.
Scanner images: bandit=1.7.10, semgrep=1.90.0, gitleaks=v8.21.0, trivy=0.55.2, osv-scanner=2.6.0.
Result file: `results/dedup-2026-09-25-v2-aligned-scope.json`.

| Repository | Languages | Raw findings | Unique findings | Dedup rate | Merged across tools | Wall time |
|---|---|---:|---:|---:|---:|---:|
| VAmPI | python | 23 | 21 | **8.7%** | 2 | 40s |
| NodeGoat | javascript | 771 | 463 | **40.0%** | 291 | 78s |
| nodejs-goof | javascript | 601 | 305 | **49.2%** | 284 | 24s |
| Vulnerable-Flask-App | javascript, python | 212 | 155 | **26.9%** | 48 | 89s |
| terragoat | Terraform / Docker | 945 | 880 | **6.9%** | 65 | 224s |
| **All 5** | | **2552** | **1824** | **28.5%** | | |

Robustness (metric 5): **5 / 5** repositories completed with no scanner failing or timing out.

### How to read this number
- It depends on the **repository mix**. Dependency-heavy projects overlap the most because two SCA
  tools (Trivy, OSV-Scanner) independently report the same advisories (`nodejs-goof`
  49.2%, `NodeGoat` 40.0%). Infrastructure-as-code repositories overlap the
  least because only Trivy scans Terraform (`terragoat` 6.9%). Code scanning
  (Bandit + Semgrep) sits in between (`VAmPI` 8.7%, `Vulnerable-Flask-App`
  26.9%).
- It measures **duplicate reduction, not correctness**. A merged finding can still be a false
  positive. Precision/recall against labelled corpora comes in Phase 6 (OWASP Benchmark, Juliet).
- Five repositories is a **baseline, not the final corpus** (the target is 20-30).

## Incremental scanning (plan §20.1/§36, Week 36)

Median PR scan time against a full scan, with the content-addressed result cache
(`core/cache.py`) warm. Reproduce with `python -m benchmarks.incremental.run --repo NodeGoat`.

Methodology: clone once, run one full scan with an empty cache (cold), then simulate a small pull
request -- edit 3 existing files -- and rescan with the *same* cache directory, three times, taking
the median. This is one repository with a small, fixed edit size, not the plan §34 evaluation
("replay the last 20 merged PRs of each repository in the 30-repository corpus") -- that is a
separate, larger evaluation task for a later phase; this is the narrower thing Week 36 itself asks
to measure. Result file: `results/incremental-2026-09-29-nodegoat.json`.

| Repository | Tools | Cold full scan | Warm PR scan (median of 3, 3 files changed) | Speedup |
|---|---|---:|---:|---:|
| NodeGoat | bandit, semgrep, gitleaks, trivy, osv-scanner | 71.2s | **19.6s** | **3.6x** |

Target (§20.1): under 60 seconds for a typical 50-file pull request. **Met** on this repository
(19.6s), with a 3-file change -- a smaller diff than the target's "typical 50-file" case, but the
warm-scan time is dominated by a cost that doesn't scale with diff size (see below), so a larger
diff on this repository would not be expected to cost much more.

### Why the speedup is 3.6x and not closer to instant
Caching eliminates re-running each *tool* against unchanged files -- confirmed directly: with zero
files touched, `core.cache.ResultCache` reports 100% hits and `cached_outcomes()` itself completes
in under 0.1s, down from the cold run's ~55s of actual Bandit/Semgrep/Gitleaks/Trivy/OSV-Scanner
execution. But the warm run still takes ~17-20s, almost all of it in `core.correlation.correlate()`
-- cross-tool deduplication over NodeGoat's 771 raw findings, measured in isolation at ~16.8s. That
step runs over *every* finding regardless of which files changed or where their results came from,
so it isn't sped up by this week's cache at all, and dominates once tool execution is no longer the
bottleneck. Making correlation itself incremental (skip re-comparing two findings whose files are
both unchanged since the last scan) would be the natural next optimization, but is out of this
week's scope -- noted here rather than left for someone to rediscover by profiling.

### An honest before/after: aligning scanner scope
The first run scored **19.2%** (2088 -> 1686). On `NodeGoat` only 83 of OSV-Scanner's 292 findings
had a Trivy match, which looked like a weak matcher. Investigating showed the matcher was fine: Trivy
**skips dev dependencies by default** while OSV-Scanner includes them, so the tools were not
scanning the same thing (208 of the 209 unmatched findings were on package versions Trivy reported
nothing for). With `--include-dev-deps`, **291 of 292** matched. The change is kept in the Trivy
adapter and pinned by a regression test; the original run is preserved as
`results/dedup-2026-09-25-v1-trivy-default-scope.json` for the record.

## Dashboard metrics at one million Occurrences (plan §48.1, §60, Weeks 70–71)

`scripts/bench-metrics.py` seeds 200 projects × 1,250 Issues × 4 scans (250,000 Issues and
1,000,000 Occurrences) in Postgres. It times every metric 20 times as `bulwark_worker` under forced
RLS, with no filter and with a portfolio, a project, a project tag and an Issue tag, plus the Issues
behind a number. Budget: 300 ms at p95 for every widget.

| | Result (Apple M5, Postgres 16.15 in Docker) |
|---|---|
| Slowest metric, p95 | **99 ms** (backlog age, Issue tag) |
| Slowest request, p95 | **124 ms** (Issues fixed in the period, from the live `issues` table) |
| Refresh, all 200 projects | 13.3 s |
| Refresh, one project | 0.05 s |

Full numbers: [`metrics/one-million-occurrences.json`](metrics/one-million-occurrences.json).
What they mean, and what the first run caught: [ADR-0054](../docs/adr/0054-metrics-layer.md).

## The rules engine under a synthetic event stream (plan §45, §60)

`scripts/bench-rules.py` seeds 20 projects × 500 open Issues in Postgres and ten enabled rules (on
new, returning and fixed Issues; some match often, some rarely, one never; their actions set
priorities and tags, which announce follow-up events). As `bulwark_worker` under forced RLS, a
producer writes Issue events at a fixed rate for 30 s while the real dispatcher drains the outbox
continuously (batches of 500, every subscriber). Every `opa eval` is timed -- one per rule per
batch, over every candidate in it -- and so is each event's delay from written to dispatched.

| Rate | Rule evaluation p50 / p95 / p99 | Batch p95 | Event delay p50 / p95 | Backlog max | Overall |
|---|---|---|---|---|---|
| 50/s | 13.4 / 15.0 / 17.3 ms | 0.34 s | 0.4 / 0.6 s | 40 | keeps up |
| 200/s | 14.1 / 16.4 / 19.7 ms | 0.65 s | 0.6 / 1.2 s | 236 | keeps up |
| 500/s | 15.6 / 18.1 / 25.6 ms | 0.61 s | 0.7 / 1.0 s | 353 | keeps up |
| 1,000/s | 17.7 / 23.1 / 34.3 ms | 0.73 s | 3.4 / 4.0 s | 3,473 | ~880 events/s, drains 4 s after |

Apple M5, Postgres 16.15 in Docker, OPA 1.21.0, 2026-10-12. **Rule evaluation stays at about 20 ms
at p95 at every rate**: an evaluation costs one `opa eval` however many candidates it covers, so a
busier stream means bigger batches, not more evaluations. What limits throughput is the rules' own
writes (tags, priority overrides, runs and their audit entries), at about 880 events a second for
one dispatcher with rules this eager (a quarter of new Issues matched something). The worker drains
every ten seconds, which adds up to ten seconds to every delay above.

Two rounds of fixes, each found by this test:

- **Projects fetched once per candidate.** A fifth of each batch went to fetching the same project
  rows again (2,200 queries per 500 events): the session's identity map keeps rows only while
  something refers to them. The rules engine now holds them for the batch: about 310 to 520 events
  a second. Numbers: [`rules/synthetic-stream-before-asset-cache.json`](rules/synthetic-stream-before-asset-cache.json).
- **A commit per change.** Every action committed on its own, and so did its audit entry, which
  first reads the chain's tip: about 6,000 statements per 500 events, each a round trip. Now the
  Issue documents are built once per batch, not once per rule (a rule that acted rebuilds the ones
  it changed, so the next rule still reads them as they are); a run's actions and audit entries
  share one commit, each action in a savepoint so a failing one still undoes only itself; a
  savepoint no longer re-applies the organization (the transaction around it already did); the
  notifier loads a batch's Issues in one query, not one per event; and marking a batch dispatched
  is one statement, not 500 (78 ms). About 3,700 statements per 500 events. Throughput went from
  about 520 to 880 events a second, the delay at 500/s from 6.2 to 1.0 s at p95, and at 1,000/s
  from 26 to 4 s. Numbers: [`rules/synthetic-stream.json`](rules/synthetic-stream.json), and before
  them [`rules/synthetic-stream-before-one-commit.json`](rules/synthetic-stream-before-one-commit.json).

What is left is mostly the ORM's own work per row (a flush per savepoint, the metrics hook on each)
and a commit per run before it acts, which the engine keeps so a run is on record even if its
actions fail. Organizations are dispatched in parallel (one dispatcher each, behind an advisory
lock), but one organization's events go through one dispatcher, so about 900 a second is that
organization's ceiling with rules this eager.

## The Issues list at 100,000 and 500,000 Issues (plan §56, §58, Week 73)

`scripts/bench-issue-search.py` seeds P projects × I Issues in Postgres: a year of history, a third
fixed, some accepted or not a risk, bands, scores, assignees, SLA policies on half the projects,
a tag on two business units. As `bulwark_worker` under forced RLS, it times seven queries 20 times
(first page of 50 with its count, and the page alone), then pages 25 pages deep by cursor.
Budget: 300 ms for a page with its count. The plan's own target is 50,000 Issues (§58).

| Apple M5, Postgres 16.15 in Docker | 100,000 Issues | 500,000 Issues |
|---|---:|---:|
| Active queue, page + exact count | 43 ms (60,000) | 151 ms (300,000) |
| The plan's example query, page + count | 33 ms | 109 ms |
| Everything (fixed too), page + count | 99 ms (100,000) | 167 ms (500,000) |
| Free text (a word in 1 title in 5), page + count | 113 ms | **520 ms** |
| A page alone, any order but free text | 4-27 ms | 6-64 ms |
| Page 25, by cursor | 9.5 ms | 10.6 ms |

Every count at 100,000 Issues is exact. At 500,000, one count (a tag inherited from business
units) did not finish in 200 ms and the list said "more than 10,000", as designed.

The ordered indexes of migration 0045 are what make a page cheap: before them, a page at 500,000
Issues took 0.23-0.61 s, because every match was sorted. Free text cannot use an index under
row-level security (a `LIKE` on the title is not leakproof, so Postgres applies it only after the
policy), so it scans the organization's matching Issues: fine at the plan's scale, over budget at
five times it. Full numbers: [`issues/search-100k.json`](issues/search-100k.json),
[`issues/search-500k.json`](issues/search-500k.json); the reasoning: [ADR-0056](../docs/adr/0056-issue-search.md).

**Bulk changes (Week 73, task 3).** The same script then tags every open Issue of one business
unit in one batch (`core.search.bulk`): at 100,000 Issues that is 6,000 Issues, previewed in
122 ms, applied in 708 ms (one audit entry per Issue and one for the batch, one commit) and undone
in 977 ms. Removing tags one statement per Issue made Undo take 6.3 s; they are now removed a
thousand at a time. Numbers: [`issues/search-and-bulk-100k-2026-10-07b.json`](issues/search-and-bulk-100k-2026-10-07b.json).

That second run was on the same machine later the same day, and every search query took 2-3 times
as long as in the table above (free text 275/328 ms p50/p95, over the budget). Task 1's own code,
run against the same database straight after, gave the same slower numbers, so the difference is
the machine's state that afternoon, not the change; the cause was not pinned down. Both runs are
kept as measured.

**After Week 75 (accounts and project-scoped roles).** Both benchmarks were run again on a fresh
Postgres, with the project-scope policies in place and JIT compilation off per transaction
(`core.tenancy`): the worst search p95 at 100,000 Issues was **93 ms** (task 1's run: 113 ms) and the
worst dashboard metric p95 at a million Occurrences **120 ms** (Week 70: 124 ms). Two things were
measured and changed on the way, both in [ADR-0058](../docs/adr/0058-identity-sso-scim-roles.md):
the policies first applied to every session and made the organization-wide "past SLA" metric 30 times
slower (median 7 ms to 224 ms; its list of the ten most overdue Issues took 666 ms under EXPLAIN
ANALYZE), so they now apply only to the role a person limited to some projects runs as;
and JIT compilation took 116 of a 153 ms count, so it is off -- which also halved large counts that
had nothing to do with roles (counting 100,000 Issues: 93 ms to 44 ms). Numbers:
[`issues/search-100k-week75.json`](issues/search-100k-week75.json),
[`metrics/one-million-occurrences-week75.json`](metrics/one-million-occurrences-week75.json).
