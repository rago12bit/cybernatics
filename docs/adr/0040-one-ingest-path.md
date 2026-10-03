# ADR-0040: One ingest path -- import is reimport with an empty history

Status: Accepted (2026-10-04), Weeks 54-56 (plan §41-§42, §55.1; "ADR-017" in the plan's own
numbering -- renumbered to this repository's real, sequential ADR series, as ADR-0038 explains).
Amends [ADR-0039](0039-portfolio-engagement-hierarchy.md) on what a "Test" is.

## Context

Everything through v2 enters the system one way: a Bulwark scan runs, produces a complete snapshot of
one asset, and `core.issues.sync` compares that snapshot against the asset's Issues. v3 has to
accept findings from sources that are not that: a penetration tester's Nessus export, a CycloneDX
file, a SARIF file from a tool Bulwark does not run, a report uploaded last quarter. The plan's rule
(§39.3, §41, C12) is one code path for matching, closing and reopening, so "one place to get it
right" -- and §42.1 spells the semantics out: import is reimport with an empty history; the same
file into the same Test twice is a no-op; `close_missing` is scoped to the Test by default; the four
counts are the product; the most recent import into a Test can be reverted.

## Decision

### An import is a real Scan, plus an ImportRecord

Each upload creates a `Scan` row (`source_type="import"`, status `completed`) that owns its findings
exactly like a native scan's, and an `ImportRecord` carrying what a Scan does not: the file digest,
the parser, the four counts, and `changes` (the prior state of every Issue the import touched).

This avoids a second way to store an Occurrence. `findings.scan_id` stays `NOT NULL`, the
`findings`/`tool_runs` RLS policies (an `EXISTS` join through `scans`) keep working unchanged, and
every existing reader of "the findings of a scan" works on an import without knowing it is one.
Making `findings.scan_id` nullable would have been smaller on paper and would have made imported
findings invisible under RLS, so it was rejected.

### A persistent Test, and what that does to ADR-0039

ADR-0039 said "Test is a ToolRun, not a new table." That is right for CI and wrong for imports, and
Week 54's real requirement exposed it: a `ToolRun` is unique per `(scan_id, tool)`, so it is
per-run, but §42.1 needs a Test that outlives every upload ("every later upload is compared against
that Test's previous Occurrences"), and `tool_runs`' RLS goes through `scans`, so a Test without a
scan cannot be a ToolRun at all.

So both are true, one per engagement kind:

- **CI engagements**: a Test is still a `ToolRun`, one per tool per pipeline run -- the plan's "each
  run of your own pipeline creates one Test per scanner." Unchanged.
- **Assessment and Import engagements**: a Test is an `EngagementTest` row (unique per
  `(engagement_id, name)`), created once and reimported into. Named `EngagementTest`, not `Test`, so
  pytest never tries to collect it.

The two are not duplicate state: they hold different things (a per-run result versus a standing
container), and neither can stand in for the other.

### A Test's "previous Occurrences" is its latest applied import's snapshot

A Test's current occurrences are the findings of its most recent `applied` `ImportRecord`. A new
upload is therefore compared against exactly one snapshot, the same snapshot semantics ADR-0012
already gives a scan, and a revert is "delete the latest import's scan and restore the Issues it
changed" -- no per-occurrence open/closed bookkeeping to keep consistent.

### Issue identity stays at project level; counts are Issue outcomes

An Issue is still `(asset, category, fingerprint)` (ADR-0012). A SQL injection found by CI and again
by a pen tester is one Issue with two Occurrences (§41.2). The four counts are about Issues:

| Count | Meaning |
|---|---|
| new | the incoming finding matches no Issue: a new Issue is created |
| unchanged | it matches a live Issue (whether or not this Test already reported it) |
| reopened | it matches a `fixed` Issue: the Issue becomes `reintroduced` |
| closed | the previous snapshot had the Issue, this one does not, `close_missing` is on, and **no other source still reports it**: the Issue becomes `fixed` |

A fifth number, `detached`, is recorded but is not one of the four on the screen: Issues this file
stopped reporting that stay open because another source (the CI scan, another Test) still does.
Calling those "closed" would tell a reader something is fixed when it is not, which is the failure
the plan's risk R20 ("reimport bugs silently closing or reopening issues") names.

"Another source still reports it" means the Issue has a finding in the latest snapshot of any other
source on the same asset: the latest completed native scan, or the latest applied import of any
other Test. The same rule must also apply to native scans, so `sync_issues_for_scan` stops marking
an Issue `fixed` while an import still reports it (Week 54 task 4).

### Scope

`close_missing` has two scopes. `test` (the default) considers only the Test's own previous
snapshot -- one tool's report cannot close another tool's findings, which is why it is the default.
`engagement` considers every Test in the engagement and exists for assessments that must reconcile
as a whole.

### Events go through an outbox

`outbox_events` rows (`issue.created`, `issue.closed`, `issue.reopened`, `scan.completed`, ...) are
written in the same transaction as the change that caused them, then dispatched. A crash between
"saved" and "announced" cannot lose an event.

### Parsers

`core/imports/parsers/` holds the `IngestParser` interface (`sniff(head) -> confidence`, streaming
`parse(stream)`), a registry, and one parser per format. Decisions, and where this departs from the
plan's wording:

- **A parser yields canonical `Finding`s, not a separate `RawOccurrence` type.** A second
  intermediate type would need its own mapping into `Finding` and so a second place that mapping can
  drift. SARIF results go through `core.sarif.result_to_finding`, the function native scans already
  use, so an uploaded Semgrep SARIF and a Semgrep run Bulwark did itself cannot disagree.
- **A parse that did not reach the end of the file is an error, never a smaller report.** Reimport
  closes what a file no longer lists, so a truncated or half-parsed file would read as "everything
  was fixed." `parse` never raises on bad input; it records `ctx.error`, and `ParseResult.complete`
  is false. Callers must refuse to apply an incomplete result. The same holds for a sandbox that
  fails or times out: that is an error, not an empty report.
- **Limits are enforced while reading**, not after: byte size, JSON/XML nesting depth, wall-clock
  time and finding count (`parsers/safe.py`), so a hostile file is stopped before it exhausts memory.
  XML goes through `defusedxml` with DTDs, entities and external references refused; identifiers are
  extracted from free text with RE2 and bounded input.
- **Streaming is real for JSON** (`ijson`): memory is bounded by the largest record. SARIF is read
  twice (rule metadata, then results) because SARIF does not say which a file lists first.
- **Parsing runs in the scanner sandbox.** `docker/ingest-parser` holds only the parser modules (no
  API, no database layer, no credentials); `core.runner.run_tool` runs it with the same no-network,
  read-only, all-capabilities-dropped flags as every scanner, through a pseudo-adapter, so there is
  no second sandbox to keep as strict as the first. In-process parsing exists for tests and local
  development and is an explicit opt-out, never the default.

## Consequences

- An import is stored as a scan (`source_type="import"`, `Scan.tools` holds the parser name), so
  anything that reads "the findings of a scan" works on one. Two places must not treat it as a scan
  someone ran and exclude it: "the latest/previous scan of an asset" (the project overview and trend
  deltas) and the recent-scans list. Its own scan page still opens by id, and its history is listed
  under its Test (`GET /v2/tests/{id}/imports`).
- Retention deleting an import's scan leaves its `ImportRecord` (`scan_id` becomes null): the audit
  trail that an import happened and what it changed outlives the findings.
- A reverted `ImportRecord` is kept with `status="reverted"`; its Scan and findings are removed, so
  it no longer counts as the Test's previous snapshot.
- Reverting restores each touched Issue from `changes`. It only reverts the **most recent** import
  into a Test: reverting an older one would have to re-derive every later import's diff.
- The "other sources" rule makes `sync_issues_for_scan` slightly more expensive (one query per scan
  to find live sources). That is a correctness cost, accepted.

## What is NOT done here

- Parsers (SARIF, CycloneDX, SPDX, OSV) are Week 55; the endpoint is Week 54 task 7; the import
  screen is Week 56. This ADR and migration 0027 are the schema and the decision only.
- Per-source deduplication strategies (§42.3) are Week 58. Until then every source matches by the
  existing project-level fingerprints.
- A component inventory (Week 67): an SPDX/CycloneDX file that lists packages but no
  vulnerabilities produces no Occurrences yet.
