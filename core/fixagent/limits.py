"""Concrete numbers for ADR-0015's three safety limits (plan §21.2). ADR-0015 fixed the *shape*
(an overall timeout, a separate per-attempt timeout, a per-tenant concurrency cap, and a distinct
`inconclusive` terminal state) and explicitly deferred real values to whichever week implements the
workflow -- this is that week.

Numbers, and why:

- **Per-attempt: 10 minutes.** One attempt is propose-patch (one LLM tool-calling round, seconds to
  low minutes) + rerun-the-rule (one scanner, one file: seconds) + rerun-all-scanners (a full scan of
  a small-to-medium repo: often 1-3 minutes, per this project's own scan timings) + optionally run
  tests (the genuinely unbounded part -- ADR-0015's whole worry). 10 minutes gives real projects'
  test suites room without letting one hung fixture consume the entire budget.
- **Overall: 30 minutes.** Three attempts at up to 10 minutes each, plus the fixed overhead (clone,
  context gathering, human-approval wait is EXCLUDED from this clock -- seebelow) rounds to 30, not
  a bare 3x30=30 coincidence: attempts are not expected to all hit their timeout in normal operation,
  so 30 minutes is "three real attempts plus slack," not "the worst case with no slack at all."
- **Concurrency: 3 per organization.** A verified-fix run makes real LLM calls (cost, already capped
  separately by `core.llm.budget`) and spins up real sandboxed containers (resource cost). Three
  concurrent runs per org is enough that a team fixing several findings at once isn't blocked on each
  other, without one organization being able to flood the worker pool.

**The human-approval wait does not count against the overall timeout.** `run()` starts the timeout
clock at the first patch attempt and stops it once verification reaches "awaiting approval" --
otherwise a human taking an hour to review would itself trigger `inconclusive`, which is exactly the
false "we don't know" ADR-0015 warns against for a workflow that in fact finished cleanly and is
simply waiting on a person. Modeled in the workflow as two separate timers, not one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class WorkflowLimits:
    per_attempt_timeout_s: int = 600  # 10 minutes
    overall_timeout_s: int = 1800  # 30 minutes, verification phase only (excludes approval wait)
    max_attempts: int = 3
    max_concurrent_per_org: int = 3

    @staticmethod
    def from_env() -> WorkflowLimits:
        env = os.environ
        return WorkflowLimits(
            per_attempt_timeout_s=int(env.get("BULWARK_FIXAGENT_PER_ATTEMPT_TIMEOUT_S", "600")),
            overall_timeout_s=int(env.get("BULWARK_FIXAGENT_OVERALL_TIMEOUT_S", "1800")),
            max_attempts=int(env.get("BULWARK_FIXAGENT_MAX_ATTEMPTS", "3")),
            max_concurrent_per_org=int(env.get("BULWARK_FIXAGENT_MAX_CONCURRENT_PER_ORG", "3")),
        )
