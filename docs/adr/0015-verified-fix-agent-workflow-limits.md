# ADR-0015: Verified-fix agent — wall-clock limits, per-attempt timeouts, and an inconclusive state

Status: Accepted (2026-09-27). Design only; not yet implemented. Records the safety limits the verified-fix
agent's Temporal workflow must have from its first version, before the workflow itself is built.

## Context

The v2 plan's verified-fix agent proposes a patch, then loops (up to three times): rerun the specific rule that
flagged the finding, rerun the full scanner suite, run the project's own unit tests, and only then request human
approval. Each of those steps, for a real project, can run inside a Firecracker microVM — meaning a single fix
attempt can spin up a sandboxed environment, install dependencies, and execute an arbitrary, untrusted-until-
verified test suite, up to three times per finding.

A hung test suite (an infinite loop, a test that waits on a network call that will never resolve, a fixture that
deadlocks) inside that loop is not a hypothetical: it is what test suites occasionally do even in well-maintained
projects. Multiplied by three retries and by however many findings are queued for verified-fix concurrently, an
unbounded workflow is a direct path to resource exhaustion and a real cost spike, not just a slow response.

## Decision

Three limits, all present from the first version of the workflow, not added reactively after an incident:

1. **A wall-clock timeout on the entire Temporal workflow**, covering all three attempts together. If verified-fix
   for one finding is still running past this timeout, Temporal cancels it outright.
2. **A separate, shorter wall-clock timeout on each individual attempt** (patch → rerun rule → rerun scanners →
   run tests), enforced independently of the overall workflow timeout. Without this, one hung attempt can consume
   the entire workflow budget before a second or third attempt ever starts, silently turning "up to three tries"
   into "one long hang."
3. **A concurrency cap on verified-fix workflows per tenant**, enforced by Temporal's workflow execution limits
   or an equivalent queue-depth check before starting a new one. This bounds the worst case (many findings
   triggering verified-fix at once) independently of any single workflow's own timeout.

A workflow that is cancelled by either timeout resolves to a distinct terminal state — **`inconclusive`**, not
`failed`. A timeout is evidence that verification didn't finish in time, not evidence that the patch was wrong;
conflating the two would show the user a false "this fix doesn't work" when the true story is "we don't know."
The UI and API must surface `inconclusive` as its own state, not silently fold it into `failed`.

## Alternatives considered

- **Overall workflow timeout only, no per-attempt timeout.** Rejected: a single hung attempt (e.g. a deadlocked
  test fixture) would exhaust the whole budget, and every subsequent attempt would report as skipped for a
  reason indistinguishable from "ran and failed" unless the per-attempt boundary exists separately.
- **Rely on Firecracker/microVM resource limits (CPU/memory quotas) alone, no wall-clock timeout.** Rejected:
  resource quotas stop a runaway process from consuming unbounded CPU or memory, but do nothing for a process
  that is idle-blocked (waiting on a network call, a lock, a fixture) rather than resource-hungry — that failure
  mode burns wall-clock time and workflow slots, not CPU, so only a timeout catches it.

## Consequences

- Whichever week implements the verified-fix agent must pick and document concrete numbers for both timeouts and
  the concurrency cap as part of that week's own verification (the same way Week 28's verification doc records
  real numbers, not just the mechanism) — this ADR fixes the *shape* of the limits, not the specific values,
  since sensible values depend on real test-suite runtimes this project hasn't measured yet.
- The workflow's audit trail (whatever records what verified-fix attempted) must record which of the three limits
  ended a given run, not just that it ended, so a pattern of hitting the per-attempt timeout on a specific
  project's test suite is visible and actionable rather than looking identical to an outright failure.
- This ADR does not address cost limits beyond concurrency (e.g. a per-tenant or per-day spend cap on verified-fix
  usage) — that is a billing/quota concern for whichever week wires verified-fix into the product's plan limits,
  not a workflow-safety concern this ADR covers.
