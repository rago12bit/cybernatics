# ADR-0047: Priority is v2's score made a policy; context only lowers it; recomputation holds a lock

Status: Accepted (2026-10-05), Week 63 (plan §44.3, §55.7, change C17).
Builds on [ADR-0046](0046-sla-and-risk-acceptance.md) (SLA policies, versioned by insertion) and the
v2 risk score ([risk-score.md](../risk-score.md), `core/risk/score.py`).

## Context

v2's risk score was one fixed formula. Plan C17: a payments service and an internal wiki should not
rank the same issue the same way. §44.3 asks for weights per factor, the project's business context,
a preview of how the top 50 would reorder before saving, a background recomputation that two edits
cannot race, and every rank still explaining itself. Week 61 also left SLA deadlines by *priority
band* waiting for this.

## Decision

**One engine, weights as exponents.** Every factor is a multiplier relative to "no effect", and a
project's weight for it is an exponent: `multiplier ** weight`. 1 is the factor as designed, 0
ignores it, 2 doubles its pull either way. Known exploitation (CISA KEV) stays a floor, scaled:
`90 × weight` (80 when nothing imports the package). Factors: severity, EPSS, KEV, reachability, taint
confirmation, runtime (DAST) confirmation, tool agreement, path context (test, example, docs,
vendored code), the triage assistant's verdict, and the business context. The arithmetic, factor
order and rounding are v2's, so with the new factors at 0 and no context the engine gives the v2
score exactly; a test holds that over more than a thousand findings.

**No policy, no change.** A project without a saved policy keeps the v2 score stored on each
occurrence (priority version 0); migration 0035 copies it onto every existing Issue, organization by
organization. The starter (every factor at 1) is offered on the Priority page, not imposed.

**Business context only lowers.** Internet-facing, data sensitivity and criticality default to the
worst case when not set; saying a project is internal, handles public data or matters little lowers
its scores. The first design boosted exposed projects instead. On a 2,500-Issue project in the
browser it put 770 Issues in P1 and tied the whole top 50 at 100, which made bands meaningless and
handed the order to the tie-breaker. Context scales every Issue of a project alike, so it moves
scores, bands and SLA deadlines, not the order within the project. The KEV floor ignores it:
known-exploited stays at least 90 unless the KEV weight is lowered.

**Stored per Issue.** `issues.priority_score`, `priority_band` (P1 ≥ 80, P2 ≥ 60, P3 ≥ 30, P4) and
`priority_factors` (each with its weight and the multiplier it applied), so the issues table sorts
and filters by priority in SQL and an SLA can key on the band. They are written at ingest (every
scan, import, DAST campaign and manual finding goes through `repo.add_findings`), when an Issue is
confirmed at runtime or gets an assistant verdict, when a hypothesis is promoted, and by
recomputation.

**Saving recomputes in the background, under a lock.** A `priority_policies` row is versioned like
SLA policies, and it records its own recomputation: pending, running, done, failed, or superseded.
While the newest version's job is pending or running, another save gets HTTP 409. A job that has made
no progress for ten minutes is taken over and stops at its next batch. Two saves that both pass the
check still cannot both land, because (project, version) is unique. The job re-ranks every Issue of
the project in batches of 500, a commit each, from the stored occurrence, with no scanner, feed or
network. It runs on the worker; with no worker, the API runs it after responding.

**Preview before saving.** `POST …/priority/preview` ranks the open queue under the current rules
and the proposed ones: the new top 50 with ranks and scores before and after, the Issues leaving it,
and counts per band. The page only offers Save for weights it has just previewed.

**SLA by priority band.** An SLA policy's basis is `severity` or `priority`; with `priority`, bands
are P1-P4 and the deadline follows the Issue's band, in Python and in the SQL filter alike.

## Consequences

- The v2 score on each occurrence is unchanged and still drives exports, the CI gate and policy
  input; priority is what the issues table ranks by. The two agree until a project saves weights.
- Recomputation uses the EPSS and KEV values stored at scan time, not today's feed. A rescan
  refreshes them.
- Band thresholds are fixed for now. The SLA's priority bands key on them, so changing them later
  moves deadlines.
- Measured on SQLite in one process, at 2,500 Issues: recompute 227 ms, preview 169 ms. Larger
  projects were not measured. The preview loads every open Issue's latest occurrence in one request.
- The new factors' strengths (taint ×1.1, runtime ×1.25, non-production path ×0.6, context
  0.65-0.9) are judgment calls, like v2's, kept in `core/priority/engine.py`. None is validated
  against outcomes.
