# Week 65 verification: the rules engine (plan §45, threat T26)

A factual record of what was built, run and measured. The decision is
[ADR-0049](adr/0049-rules-engine.md).

## What was built

- **Rules.** WHEN a trigger, IF a Rego condition, THEN up to eight actions, for one project or
  every project, with a confirmation threshold. Versioned, audited, deletable (history kept).
- **Triggers.** Issue found, back, fixed, assigned; retest requested or decided; SLA due soon or
  breached; risk acceptance expiring within seven days (new: announced once by the expiry sweep) or
  expired; scan or import completed; no scan for N days; schedules (hourly, daily, weekly, UTC).
- **Conditions.** Rego bodies against `input.issue`, `input.project`, `input.event`, evaluated in
  batches by OPA with `http.send`, `net.lookup_ip_addr` and `opa.runtime` removed and no network.
- **Actions.** Assign, set a priority band (a new override that wins wherever a band is read), add
  tags, mark ready for retest, request a verified fix, notify Slack, Discord and the outbound webhook.
- **Safety.** Dry run over the last seven days, bulk confirmation, a depth limit of three, the AI
  budget and a daily cap on fix requests, the `rules:write` scope, an audit entry per run and per
  change, and redelivery that never acts twice.
- **The outbox dispatcher** (`core.dispatch`), every ten seconds on the worker, under a per-org
  advisory lock; the rules sweep every five minutes.
- **Screens.** An Automation page (held runs first, rules as WHEN / IF / THEN, "Test this rule", on
  and off, delete, run history) and an Owner panel on the issue page (assignee and a priority by
  hand, naming the rule when a rule set them). Creating and editing rules on screen is Week 66.
- **API.** `/v2/rules` (catalogue, CRUD, enable, test a draft or a rule), `/v2/rule-runs` (list,
  confirm, dismiss) and `/v2/issues/{id}/assignee` and `/priority`.
- **Migration 0037.** `automation_rules` and `rule_runs` under forced RLS; assignee and priority
  override on Issues; when an acceptance's expiry warning went out; waiting outbox events marked
  dispatched.
- **OPA in the app image**, pinned to 1.21.0 and checked against the published SHA-256.

## Found and fixed along the way

1. **Found by the tests:**
   - Runs first de-duplicated by subject within a cause. Two assignments of the same Issue in the
     same minute (a person, then a rule) are one cause, so the second was silently skipped. Runs now
     record (event, subject) pairs; the depth-limit test caught it.
   - An action that failed rolled back the session, and with it the uncommitted record of the run
     it belonged to: the run vanished. The run is now committed before it acts.
   - A quiet stretch was keyed to the second; two scans in the same second looked like one stretch.
     It is keyed to the full timestamp.
2. **Found in the browser:**
   - Confirming a held run did not update the rule's "last acted" time.
   - The history said "Priority set by hand by the rule …"; it now says "Priority set by the rule …".
3. **Found while reading the code:** issue titles go into Slack and Discord messages, and titles
   come from scanners reading other people's code. Slack text is now escaped (`<!channel>` cannot
   ping a channel) and Discord gets an empty `allowed_mentions` (`@everyone` pings nobody).

## Checked against real systems

- **OPA 1.21.0** evaluates every condition in the unit tests (no mock). `http.send`, `opa.runtime`
  and `net.lookup_ip_addr` fail to compile with OPA's own message; line numbers in errors are the
  condition's own.
- **Speed.** One `opa eval` for 1, 100 and 500 inputs: median 12, 12 and 15 ms (p95 14, 13, 15 ms)
  on this Mac. A scan with 500 new Issues through a rule that matched 50 of them: 551 events
  dispatched, 50 priorities set, one run and 52 audit entries, in 0.1 s on in-memory SQLite.
- **Postgres under forced RLS** (throwaway pgvector container, worker role): 55 integration tests
  pass, one new. A rule fires from the outbox through the advisory lock (a second dispatcher holding
  the lock gets nothing); another org sees no rules, runs, tags, Issues or events, cannot open the
  rule, and its dispatcher finds nothing. With RLS turned off on `automation_rules`, the new test
  fails.
- **Migration 0037 on Postgres:** three waiting events in two orgs were marked dispatched; downgrade
  removed the tables and columns; upgrading again worked. `alembic check` reports nothing for the new
  tables or columns (its other differences predate this week).
- **The app image** builds for arm64 with the checksum verified, and `opa version` runs inside it.
- **In a browser against the real API** (SQLite, a thread standing in for Celery beat, three named
  tokens; Meera holds `rules:write`):
  - Three rules existed before a second scan brought five new Issues. "Critical issues go to Priya,
    as P1" assigned, set P1 and tagged the one new critical Issue; "Tag every new issue" (threshold
    3) held its five.
  - The Automation page showed the held run first with its five Issues; "Apply to all 5" tagged them.
  - "Test this rule" said "would have matched 2 issues in the last 7 days" -- including the critical
    Issue from before the rule existed, which the rule itself (correctly) never touched.
  - The issue page named the rule for the assignment and the P1, with "computed P3"; its history
    named both rules. Reassigning to Arjun from the dropdown saved and showed Arjun.
  - At phone width the Automation page has no sideways scroll of its own (the shell's header still
    overflows, as before this week).
- **Totals.** Backend unit tests: 2,610 pass (19 new for rules), coverage 92%; `ruff` (apart from
  the older import-order warning), `black` and `mypy` clean. Web: 312 tests (5 new, with axe), `tsc` clean.

## What this does not prove

- **No Celery worker ran.** The dispatcher and sweep tasks wrap the same `drain` and `sweep` the
  tests and the browser run used.
- **Request a verified fix** was tested with the agent's start replaced: Temporal was not running.
- **Notify** was tested with Slack and Discord replaced; nothing was posted anywhere.
- **Rule latency under sustained load** (plan §60) was not measured; the figures above are one batch.
- "Admin" is a token scope until roles exist (Week 75).
- The rule editor, its template gallery, notification channels and ticket actions are Week 66.
