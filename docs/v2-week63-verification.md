# Week 63 verification: the priority engine v3 (plan Phase 15, §44.3, §55.7)

This is a factual record of what was built, run and measured. Decision:
[ADR-0047](adr/0047-priority-engine.md). Week 63 does not end a milestone; M14 and `v2.3.0` come
after Week 64.

## What was built

- **Engine** (`core/priority/engine.py`, pure): weights per factor as exponents, the KEV floor
  scaled by its weight, business context that only lowers, P1-P4 bands, and every factor recorded
  with its weight and multiplier.
- **Storage** (migration 0035): `priority_policies` (versioned, forced RLS) and four new columns on
  `issues`. Every existing Issue is backfilled with its latest occurrence's v2 score, one organization
  at a time.
- **Writers**: ingest (scan, import, DAST, manual finding), runtime confirmation, assistant verdict,
  hypothesis promotion, and the background recomputation (`bulwark.recompute_priority`, or in the
  API process when there is no worker).
- **API**: `GET/PUT /v2/projects/{id}/priority`, `POST …/priority/preview`, `issue.priority` on
  every issue response, `?priority=` on the issues table, sorting by priority, and SLA basis
  `priority`.
- **Web**: the **Priority** page (business context, a slider per factor, the before-and-after top 50,
  Issues leaving it, band counts, recompute progress, history), a Priority column and P1-P4 filter
  on the issues table, weights in "Why it's ranked here", and severity or priority band on the SLA
  page.

## Found and fixed along the way

1. **Business context inflated whole projects into P1.** The first design boosted exposed projects
   (internet-facing ×1.2, restricted ×1.3, critical ×1.3). In the browser, on a seeded 2,500-Issue
   project, that moved 770 Issues to P1 and tied the whole top 50 at 100. Context now only lowers,
   and unset means the worst case. On the same project, describing it as an internal, low-criticality
   wiki took P1 from 84 to 9. All 9 left are CISA KEV entries, whose floor ignores context by design.
2. **A promoted hypothesis never stored its risk score** (since Week 43), so it sorted last. It now
   does, and gets a priority.
3. **Found in the browser:**
   - The new table column broke the issues table's grid: titles were pushed right and "Rule"
     wrapped. The grid now has the column, with narrower tracks on phones.
   - A global label style rendered every factor description as uppercase monospace.
   - The History table made the page scroll sideways on a phone.
   - The sliders did not report a server field error to assistive technology. A web test caught
     this one.

## Checked against real systems, not mocks

- **The v2 score is reproduced exactly.** More than 1,000 findings (every severity, CVSS or not,
  KEV, EPSS from 0.04% to 90%, no exploit data, no CVE id, code findings by confidence, three
  reachability states, every assistant verdict) are scored by `core.risk.score_finding`, then by the
  engine with v2's weights. Every score is equal.
- **Real Postgres with forced RLS**, as the worker role: 53 integration tests pass, one of them new.
  Another org sees no policy. A recompute run the way the worker runs it re-ranks only its own
  project. The preview sees no other org's Issues, and the band filter runs in Postgres. With RLS
  turned off on `priority_policies`, the new test fails.
- **Migration 0035 on Postgres** with seeded data from two orgs:
  - An Issue with occurrences scored 40 (older) and 85 (newer) got 85 and P1.
  - A score of 59 got P3, at the boundary.
  - An Issue with no occurrence stayed unranked.
  - The second org was backfilled too.
  - Downgrade to 0034 removed the columns, and upgrading again worked.
  - The backfill statements, run as the worker role, update 0 rows without the org scope and every
    row with it. That is why the migration sets the scope per organization (the container's owner
    role is a superuser, so the migration run itself does not prove this).
- **A real browser against the real API** (SQLite, 2,500 seeded Issues, Next dev server):
  - Preview, save, then "Waiting to apply…" followed by "Applied to 2,500 issues; 1,586 changed
    band".
  - The issues table sorted by the new priority.
  - An issue's panel read "P4 · 15/100" with each factor's weight and multiplier. The arithmetic was
    checked by hand: 100 × 0.95 × 0.95 × 1.1 × 0.36 × 0.8 × 0.8 × 0.65 = 14.9.
  - An SLA by priority band saved as version 1.
- **Speed at this size** (SQLite, one process, 2,500 Issues): recompute 227 ms, preview 169 ms.
- **Unit tests:**
  - 53 new tests covering the engine, validation, the lock, a stale lock taken over, two saves
    racing, superseded and failed jobs, a job taken over mid-run, ingest under a policy, rescoring,
    the preview, org isolation, and the SLA by band.
  - Removing the lock check, or the unique-version guard, fails a test.
- **Web**: 298 tests (10 new, including axe), `tsc` clean.

## What this does not prove

- **Scale.** No project larger than 2,500 Issues was measured, and none on Postgres. The preview loads
  every open Issue's latest occurrence in one request.
- **The Celery path was not run with a live worker.** The task is a thin wrapper around the same
  `service.recompute` the tests and the browser run exercised.
- **The lock was not seen holding in the browser.** A 2,500-Issue recompute finished before a second
  save could be sent. The 409 is covered by API tests.
- **The new factor strengths are judgment calls**, as v2's were, and are not validated against
  outcomes.
- Recomputation uses EPSS and KEV as stored at scan time, not today's feeds.
- CI results for this commit have not been observed (nothing pushed).
