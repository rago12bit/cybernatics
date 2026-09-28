# Week 34 verification — issues experience (plan §28.3, §30.4, §32)

Honest record of what was built, run, and clicked through — for Week 34: a virtualized issues
table with filters/saved views/bulk triage, an issue detail screen (why-ranked, taint-path stepper,
Shiki code view, history), triage flows (not-a-risk/accept-risk with an audit trail), and
novice/expert mode.

## A real, pre-existing bug found and fixed along the way

Building triage meant, for the first time, an action that *depends* on one Issue meaning exactly
one vulnerability. Testing it against this session's own real scan data (VAmPI, via the live
Postgres deployment) surfaced a genuine, previously-invisible bug in `core/correlation/engine.py`'s
`fingerprint()` (Week 27-ish, ADR-0012/ADR-0004) and `core/issues.py`'s `fallback_key()`: two
**different** findings sharing one tracked Issue.

- **Root cause 1**: Trivy's Dockerfile checks quote no snippet at all. `fingerprint()`'s formula for
  a snippet-less finding was `cwe|path|placeholder|line` — with no CWE and the same line, two
  *different* rules (`DS002` "runs as root", `DS026` "no HEALTHCHECK") hashed identically.
- **Root cause 2, worse and only found by generalizing the first fix and re-checking the real golden
  fixture data**: an IaC linter quoting the *entire resource block* verbatim for every rule that
  fires against it (Trivy's Terraform checks) means even a **real, non-empty, non-placeholder**
  snippet isn't unique — ten genuinely different misconfiguration findings on one `aws_s3_bucket`
  resource shared one snippet and collided too. This wasn't a hypothetical: re-running this repo's
  own `tests/golden/correlation/expected.json` regression snapshot after the first fix immediately
  showed 12 remaining duplicate fingerprints in real scanner output, which is what drove the broader
  fix rather than stopping at the narrower one.
- **The fix**: both `fingerprint()` and `fallback_key()` now always fold the finding's rule id(s)
  (`evidence.rule_ids`) into their hash, not only when the snippet is unusable. This never affects
  cross-tool merging of the *same* defect — `correlate()`'s clustering already decided which findings
  belong in one merged group, via other signals, before either function ever runs — it only stops
  *different* defects that happen to share a location/snippet from colliding.
- **Verified**: the golden snapshot (real scanner output, not synthetic) now has 38 entries and 38
  unique fingerprints, zero collisions, confirmed by an explicit test after regenerating it. Two new
  regression tests (`test_code_fingerprint_distinguishes_different_rules_with_no_snippet`,
  `test_code_fingerprint_distinguishes_different_rules_sharing_one_quoted_block`) reproduce both
  real cases directly. `tests/unit/test_issues.py`'s `fallback_key` tests were rewritten for the new,
  intentionally different behavior (it no longer gives up and returns `None` for a placeholder/empty
  snippet — it anchors on the rule id instead, which is *more* useful: a redacted-secret finding can
  now be tracked across a file move too, not just abandoned).
- Found live: while testing the new `/assets/{id}/issues` endpoint against real Postgres data,
  marking VAmPI's "root user" Dockerfile finding as not-a-risk silently also hid its unrelated "no
  HEALTHCHECK" finding. Confirmed via direct API inspection (`fingerprint` and `issue.id` identical
  for two differently-titled findings), root-caused, fixed, and the exploration-triaged issue was
  reopened afterward to leave the demo data clean. Both the API and worker Docker images were
  rebuilt and the migration re-run against the live Postgres so the fix is live in the running
  deployment, not just the source tree.

## Backend — new endpoints, all reusing existing data paths

- `GET /assets/{id}/issues` — the asset's latest scan's findings, filtered to the *active triage
  queue* by default (untouched issues, plus any accepted issue whose expiry has passed — "reappears
  automatically," per §28.3) or to an explicit `triage=` list. Same `query_findings`-style
  severity/category/sort/pagination as the existing scan-scoped endpoint; the only new work is the
  triage join (`core/persistence/repo.py`'s `list_asset_issues`).
- `GET /assets/{id}/issues/{issue_id}` and `.../history` — one issue's full Finding for its detail
  screen, and a real event timeline built from `IssueRow.first_seen_at`/`fixed_at` plus the
  tamper-evident audit log (`AuditEntry.target == issue_id`) — nothing synthesized.
- `POST /assets/{id}/issues/{issue_id}/triage` and `.../bulk-triage` — `not_a_risk` (reason
  required), `accepted` (expiry required), `reopen`. Every action writes a real audit entry
  (`core/persistence/repo.py`'s `triage_issue`, reusing the Week 29/30 backfill's
  `append_audit_entry`) — exactly §28.3's "Both write to the audit log." Bulk triage reports partial
  failure per issue rather than aborting the whole batch.
- New `issues` table columns (migration `0009_issue_triage.py`): `triage_status`, `triage_reason`,
  `triage_expires_at`, `triaged_at`, `triaged_by` — deliberately separate from the existing
  ADR-0012 `state` column (lifecycle vs. human decision are orthogonal). No RLS changes needed:
  `issues` already carries the tenant-isolation policy from migration 0005, and it covers new
  columns automatically. **Migrated against the real live Postgres deployment**, not just SQLite —
  confirmed via `\d issues` that the columns, index, and existing RLS policy are all present and
  correct.
- 13 new backend tests (`tests/unit/test_issue_triage_api.py`, `test_project_overview.py`'s
  existing suite unaffected) plus the 2 correlation regression tests above — all against real
  SQLite through the actual FastAPI `TestClient`, not by calling repo functions directly. Full
  suite: **869 passed, 2 skipped**; `ruff`, `black --check`, and `mypy` clean on every changed file.

## Frontend — built, then clicked through end to end

`components/IssuesTable.tsx` (plan §31: real `@tanstack/react-table` for the column model —
selection, severity, title/location, triage status, rule id — combined with
`@tanstack/react-virtual` for windowed row rendering, not a hand-rolled scroller), severity and
triage-status filter chips, sort, bulk-select with a triage action bar, and saved views (named
filter presets in `localStorage` per project — no per-user backend exists yet, same honest
simplification as the API token itself; see "what this doesn't claim" below).

`components/IssueDetail.tsx`: the why-ranked panel (reused from Week 33's `design-system/why-ranked.tsx`,
carrying the real `risk_factors` text), a taint-path stepper
(`design-system/taint-stepper.tsx` — "static until Phase 9 supplies real paths," per Week 34's own
line item: the one real step shown is the finding's own location, never an invented intermediate
hop), a Shiki code view (`design-system/code-view.tsx`, real syntax highlighting, theme-synced to
the design system's light/dark via a `MutationObserver` on `data-theme` rather than fighting Shiki's
own dual-theme CSS-variable convention), a real event history, and the triage actions themselves.

`design-system/mode.tsx` (novice/expert, plan §30.4): a `localStorage`-persisted per-viewer toggle
controlling exactly what this session's own instructions asked for concretely — row density on the
issues table, the plain-language explanation's default open/closed state, and whether rule ids are
shown or one click away. It does not change the landing page after sign-in (no per-user sign-in flow
exists yet to hang that on).

### Verified live, not just built

A disposable local FastAPI+SQLite server (a freshly `secrets.token_hex`-generated test token, never
the user's real one) seeded with 6 findings across two projects, driven by hand in the built-in
browser:

- **Issues table**: severity/triage filter chips, sort, real data rendering with the correct
  severity shapes.
- **Bulk triage → "Mark as not a risk"**: reason dialog required and enforced (Confirm stays
  disabled without one), the issue disappeared from the active queue immediately after confirming,
  and reappeared correctly under the `triage=not_a_risk` filter with its status tag.
- **Issue detail**: the why-ranked panel showed the real risk score and factors; the taint stepper
  showed the one real step, correctly labeled "Where this happens" (not "How the input gets there")
  since there's only one; the Shiki code view rendered real syntax-highlighted Python.
- **Expert mode toggle**: "What this means" auto-collapsed and a real "Rule IDs" section appeared —
  confirmed live, not just that the code compiles.
- **Reopen**: banner cleared, both triage actions re-enabled, and — the strongest single piece of
  evidence that the whole audit-backed history mechanism works — the History panel showed all three
  real events in order: "First seen," "Marked as not a risk," "Reopened."
  **Accept risk**: date input filled via a form-level set (native `<input type=date>` doesn't take
  raw keystrokes reliably in this automation harness — a tooling limitation, not a product one; the
  `expires_at`-required validation was independently confirmed by the disabled Confirm button before
  that, and by the backend's own passing test), confirmed "Risk accepted — until 31/12/2026," and a
  fourth real history entry appeared.
- Caught and fixed live: `IssuesTable`'s "N finding**s**" text was unconditionally plural even for
  a count of 1; fixed and re-verified in the same session (distinct from, but same class of bug as,
  Week 33's).

All CI-equivalent checks (`npm run typecheck`, `npm test`, `npm run build`, `npm run build-storybook`)
were re-run from a clean `npm ci`, matching what the `web` CI job actually runs, not just what
worked with a locally-mutated `node_modules`. Throwaway server state (SQLite db, work directories,
the two dev processes) was torn down after verification.

## What Week 34 does not claim

- **Saved views are per-browser, not per-user**: same limitation as the API token
  (`sessionStorage`) and Week 33's project switcher — no real per-user identity/settings backend
  exists yet. A real "shared team view" needs that first.
- **The taint-path stepper shows one real step, never a fabricated multi-hop path.** A richer,
  illustrative multi-step example exists only in Storybook, explicitly labeled as such. Phase 9
  (Weeks 36-40) is where a real taint engine makes multi-step paths a real, per-finding thing.
- **j/k and the rest of the issues-table keyboard shortcuts are still not wired here.** The Week 33
  shortcuts dialog already marks them "reserved"; that stays true this week too. The existing scan
  report's `FindingsTable.tsx` has its own separate j/k handling (with the Week 31-documented
  desync bug against the old "Top 10 by risk" widget) — unifying keyboard navigation properly across
  both the new issues table and the old scan report is real, separate work this week didn't attempt,
  rather than a partial, bug-prone version of it.
- **Novice/expert mode does not change the landing page after sign-in** (§30.4's table also lists
  this) — there is no per-user sign-in flow yet for that setting to route.
