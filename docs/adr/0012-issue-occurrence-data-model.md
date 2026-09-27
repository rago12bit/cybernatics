# ADR-0012: Split Finding into Issue (stable identity) and Occurrence (one sighting)

Status: Implemented (2026-09-27, Week 28). Verified live end to end; see docs/v2-week28-verification.md.

## Context

`core/persistence/models.py` today has `Scan` → `ToolRun` → `FindingRow`, and `FindingRow` is scoped entirely to
one `scan_id`. Every scan is an island: there is no way to ask "is this the same SQL injection we saw last
week?", "did the fix work?", or "is this new in this pull request?" without re-deriving it from scratch each
time, because nothing persists a finding's identity *across* scans — only its fingerprint (`core/correlation`)
within one.

v2 needs all three of those questions answered: incremental/PR scanning (§20.1 of the plan), the fix-verification
loop (§21.2), and the trend data the UI shows ("5 fixed, 2 new, 1 returned", §28.1). None of it is possible
without something that outlives a single scan.

## Decision

Split the concept in two:

- **Issue** — one vulnerability, identified once, that persists across scans of the same project. Carries the
  current state (`new` / `open` / `fixed` / `reintroduced`), first-seen and last-seen timestamps, and (later,
  Week 62) risk acceptance.
- **Occurrence** — one sighting of an Issue in one scan. What `FindingRow` is today, minus the parts that are
  really Issue-level (state, first-seen). An Occurrence always belongs to exactly one Issue and one scan.

```
Scan ──< ToolRun
Scan ──< Occurrence >── Issue
```

### Issue identity (matching)

Reuses the fingerprint from ADR-0004 as the primary key, plus a fallback so moving a function to another file
doesn't manufacture a spurious "new" Issue and a spurious "fixed" one:

1. **Primary:** the existing `Finding.fingerprint` (package-level exact match for SCA; normalized
   CWE+path+snippet hash for code). If two Occurrences in successive scans share a fingerprint, they're the
   same Issue.
2. **Fallback, code findings only:** `sha256(cwe + rule_family + normalized_snippet)` with no path component,
   so a function moved to a new file still matches. Used only when the primary fingerprint has no match in the
   project's existing open Issues, to avoid over-merging unrelated findings that happen to share a snippet hash
   with no CWE context.

Matching is scoped to one project (one `Scan`'s lineage, i.e. repeated scans of the same `source_ref`), not
global — a `CWE-89` in `payments-api` and one in `internal-wiki` are different Issues even with an identical
snippet.

### Lifecycle

```
new/open → fixed (no matching Occurrence in the next full scan of the same project)
fixed → reintroduced (a matching Occurrence reappears later)
```

`accepted_risk` and `not_a_risk` states are deferred to Week 62 (risk acceptance), matching the plan's own
sequencing — v2's Phase 8-9 don't need them yet, and adding an incomplete version now would be a state machine
Week 62 has to migrate away from.

### What does NOT change in Week 28

- `ToolAdapter`, `execute_tool`, correlation, redaction, `finalize()` — none of it. Issue/Occurrence sits above
  the existing pipeline; a scan still produces `Finding` objects exactly as it does today, and the persistence
  layer is what learns to turn a batch of them into Occurrences against existing or new Issues.
- The CLI's one-shot `scan()` path keeps returning `Finding`s with no persistence; Issue/Occurrence only applies
  where scans are stored (the API/worker path), matching how `raw_object_key` already only exists there.

## What was actually built, and where it differs from the design above

- **`FindingRow` was not renamed to `Occurrence`.** It gained `issue_id` and `issue_state` columns instead of
  becoming a new table under a new name. A rename would have touched every reader of `findings` (the API, the
  CLI JSON/HTML/PDF exporters, the web app, the golden-fixture tests) for zero behavioural gain in one week; the
  table already *is* an Occurrence in every way ADR-0012 describes, just under its original name. If a future
  week needs `Occurrence` as a distinct, separately-queryable concept (e.g. the plan's `IssueGroup`, §41.2 of the
  later system-of-record design), rename then, with a reason that isn't just "the ADR said so".
- **A real collision was found and fixed: Issue identity is scoped by `(asset, category, fingerprint)`, not just
  `(asset, fingerprint)`.** `fingerprint()` (ADR-0004) doesn't hash category, by design — `correlate()` checks
  category compatibility separately via `same_defect()` before ever comparing fingerprints. Used alone for Issue
  identity, that means two findings of *different* categories (say a SAST rule and a secrets rule) can hash
  identically when both lack a CWE and land on the same redacted line, and would otherwise collide on the
  database's uniqueness constraint. Caught by a real test failure the first time two such findings landed in the
  same scan (`tests/unit/test_issues.py::test_different_categories_never_collapse_even_with_the_same_raw_fingerprint`),
  not by inspection.
- **No `/v2` API namespace.** Standing up a parallel versioned API and freezing `/v1` read-only, as the plan's C5
  proposes, is a bigger structural change than one week justifies, and nothing yet depends on `/v1` staying frozen
  (the VS Code extension and GitHub Action are still pre-Marketplace). Instead, `GET /scans/{id}` gained an
  additive `issue_counts` field and each finding an additive `issue` field; existing clients that don't know about
  either simply ignore them. Revisit real API versioning when there's a second client (the plan's own GitHub App
  in v2, or the Marketplace-published extension) that needs `/v1`'s exact shape to keep working while `/v2` moves.
- **Only "new" and "reintroduced" are surfaced as UI badges**, not "fixed" — a fixed Issue has no Occurrence in
  the current scan to attach a badge to, so showing it needs a history view (the plan's scan-comparison screen,
  §28.6) that doesn't exist yet. `ScanReport` shows a one-line "N new, M reintroduced since the last scan of this
  project" summary instead, quiet when there's nothing to say.
- **The historical backfill is a standalone script (`scripts/backfill-issues.py`), not baked into the Alembic
  migration.** The migration (`migrations/versions/0004_issues_assets.py`) only creates tables and columns.
  Turning 13 real pre-existing scans' stored JSON into a lifecycle history needs the same `core.issues.sync()`
  logic the live pipeline uses, replayed oldest-scan-first per asset — that's application logic that will keep
  changing, and Alembic migrations are meant to stop changing once shipped. Run once with `--apply`; dry-run by
  default.

## Consequences

- A migration must backfill: every existing `FindingRow` becomes one Occurrence under a new, freshly-minted
  Issue (there's no history to reconstruct "first seen" from, so first-seen = the existing scan's timestamp).
  Done via `scripts/backfill-issues.py`, run live against the 13 pre-Week-28 scans in this environment: 5 assets,
  1,468 issues, 4,652 occurrences, with the same repo's repeat scans correctly collapsing to `open` instead of
  each counting as `new`.
- The API's finding-list endpoint returns Occurrences (one row per scan, unchanged), each carrying which Issue it
  belongs to and that Issue's current state. A dedicated Issues endpoint (list issues for a project, independent
  of any one scan) is not built yet — nothing in the current UI needs it before the scan-comparison and
  fix-first screens (§28.1, §28.6) exist to consume it.
- Nothing here requires multi-tenancy (ADR-0013) to land first, but both touch `core/persistence/models.py`, so
  Week 28 (data model) intentionally comes before Week 29 (tenancy) to avoid migrating the same tables twice.
- Only a `"completed"` scan syncs issues (`core/pipeline.py`). A `"partial"` or `"failed"` scan leaves every
  finding's `issue_id` unset: absence during a partial scan doesn't mean fixed, it might mean the tool that
  would have found it never ran.
