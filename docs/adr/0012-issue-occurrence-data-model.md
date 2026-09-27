# ADR-0012: Split Finding into Issue (stable identity) and Occurrence (one sighting)

Status: Accepted (2026-09-27). Design only — implementation is Week 28.

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

## Consequences

- A migration must backfill: every existing `FindingRow` becomes one Occurrence under a new, freshly-minted
  Issue (there's no history to reconstruct "first seen" from, so first-seen = the existing scan's timestamp).
- The API's finding-list endpoints need to decide whether they still return Occurrences (one row per scan) or
  Issues (deduplicated across the project's scan history) — left to Week 28's implementation, but the plan's own
  UI (§28.1, "5 fixed 2 new 1 returned") assumes Issues are the default view once this ships.
- Nothing here requires multi-tenancy (ADR-0013) to land first, but both touch `core/persistence/models.py`, so
  Week 28 (data model) intentionally comes before Week 29 (tenancy) to avoid migrating the same tables twice.
