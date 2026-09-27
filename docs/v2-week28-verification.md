# Week 28 verification: Issue/Occurrence data model (ADR-0012)

Everything below was run for real on 2026-09-27: a live Postgres, a live FastAPI + Celery worker (both rebuilt
with this week's code), and real HTTP requests through the actual sandboxed scanner containers — not mocked, and
not inferred from the unit tests alone (those exist too, 772 passing, and are listed at the end).

## What shipped

- `core/assets.py` — normalizes a scan's source into the identity a repeated scan is matched against.
- `core/issues.py` — pure identity-matching and lifecycle logic (`new` → `open` → `fixed` → `reintroduced`), no
  database access, so it's unit-testable without Postgres.
- `Asset` and `IssueRow` tables (`migrations/versions/0004_issues_assets.py`); `Scan.asset_id` and
  `FindingRow.issue_id`/`issue_state` added.
- `core/persistence/repo.py`: `get_or_create_asset`, `sync_issues_for_scan`, and `add_findings` extended to
  stamp each stored finding with its issue.
- `core/pipeline.py`: every completed scan now syncs issues after `finalize()`, before persisting.
- API: `GET /scans/{id}` gained `issue_counts`; each finding in `GET /scans/{id}/findings` gained `issue`.
- Web: an "Issue" badge on new/reintroduced findings, and a one-line summary on the scan report. Silent for the
  steady `open` state and for scans with no tracked history.
- `scripts/backfill-issues.py`: a one-time, dry-run-by-default backfill for scans that predate this week.

## Live end-to-end proof (real API, real worker, real Postgres)

Uploaded the same tiny archive four times in a row through the real `/scans/upload` endpoint, changing its
content between uploads, and read the result back through the real `/scans/{id}/findings` endpoint each time.

| Step | Change | Result |
|---|---|---|
| 1 | `subprocess.run(cmd, shell=True)` | New issue created, state `new` |
| 2 | same file, unchanged | Same issue id, state `open` |
| 3 | fixed (`shell=False`) | Original issue: `fixed`, real `fixed_at` timestamp. A different, low-severity Bandit rule (always fires on `import subprocess`) became a separate `new` issue |
| 4 | `shell=True` again | Original issue: same id, state `reintroduced`, `fixed_at` cleared |

Confirmed directly against Postgres (not just the API's word for it) after each step:

```
select id, category, severity, state, first_seen_at, last_seen_at, fixed_at from issues;
```

All four uploads correctly resolved to **one** `assets` row (same filename → same asset), and all four
`scans` rows pointed at it.

## The bug this caught

Two findings with **different categories** (a SAST rule and a Secrets rule) landing on the same redacted line
with no CWE hash to the *same* primary fingerprint — `fingerprint()` (ADR-0004) doesn't encode category, by
design, because `correlate()` checks category compatibility separately before ever comparing fingerprints. Used
on its own for Issue identity, that collision violated the new `(asset, fingerprint)` uniqueness the first time
a real test exercised it (`tests/unit/test_pipeline.py::test_raw_output_is_withheld_when_secrets_were_found`,
an existing Week-5 test, not one written for this feature). Fixed by scoping Issue identity to
`(asset, category, fingerprint)` instead, plus a regression test that recreates the exact collision. See
ADR-0012's "what was actually built" section for the full writeup.

A second bug, in the backfill script only (not the live pipeline): the first version's dry-run mode reported
every repeat scan of an asset as 100% "new" again, because it never carried forward in-memory state across an
asset's own scan history. Fixed; the corrected dry-run output was cross-checked against the `--apply` run and
matched exactly (1,468 issues either way) before anything was written for real.

## Historical backfill, run for real

Ran against every one of the **13 real, pre-Week-28 scans already in this environment** (from Weeks 22–26):

```
Would backfill: 5 assets, 3388 issues, 4652 occurrences, across 13 scans.   <- first (buggy) dry run
Would backfill: 5 assets, 1468 issues, 4652 occurrences, across 13 scans.   <- after the fix, matches --apply
Backfilled:     5 assets, 1468 issues, 4652 occurrences, across 13 scans.   <- --apply, confirmed against Postgres
```

Repeat scans of the same repository correctly collapsed into repeat sightings of the same issues (e.g.
`nodejs-goof`'s three scans: 304 new on the first, 0 new and 8 fixed on the second, 8 reintroduced on the third)
instead of each scan being double- or triple-counted as entirely new.

## Automated tests

```
pytest -q --cov=core --cov=api    # 772 passed, core/ 95.41% (core/issues.py and core/assets.py: 100%)
ruff check . && black --check .   # clean
mypy                               # clean (core/, api/)
cd web && npx tsc --noEmit && npx vitest run && npm run build   # 119 passed, build succeeds
```

## What's deferred, on purpose

- No `/v2` API namespace — see ADR-0012.
- No dedicated Issues-list endpoint independent of a scan; nothing in the UI needs it yet.
- No `accepted_risk` / `not_a_risk` states — the plan schedules those for Week 62 (risk acceptance) and adding a
  partial version now would need migrating away from it later.
- The "fixed" count isn't shown in the persisted scan summary (only live, in the ephemeral WebSocket event) — a
  fixed Issue has no Occurrence in the scan that would carry it, so showing it needs the scan-comparison screen
  (plan §28.6), not built yet.
