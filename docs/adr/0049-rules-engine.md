# ADR-0049: Rules run on the outbox, conditions are Rego, and bulk or chained actions stop for a person

Status: Accepted (2026-10-06), Week 65 (plan §45, threat T26; the plan's ADR-020). Builds on the
outbox (plan §41.1, every domain event written in the same transaction as its change), the OPA
policy gate ([policy.md](../policy.md), `core/policy/opa.py`) and
[ADR-0048](0048-engagements-retests-collaboration.md) (people are personal tokens until Week 75).

## Context

Plan §45: "automation teams configure without writing code" -- WHEN an Issue is found, IF it is P1
in a payments project, THEN assign it, set its priority, file a ticket, notify a channel. Threat T26
names what goes wrong: loops, mass closure and runaway fix requests. Since Week 54 every change has
written an outbox event, but nothing read the outbox.

## Decision

**Rules read the outbox.** A dispatcher (`core.dispatch`, every ten seconds on the worker) hands each
batch of new events to its subscribers -- the rules engine now, notifications next week -- and then
marks the batch dispatched. Delivery is at least once; one organization at a time, under a Postgres
advisory lock held on a connection of its own (a session's connection can change at each commit).
Migration 0037 marks every event already waiting as dispatched, so the first rule does not fire on a
month of history. A rule never fires on events from before it was created.

**Triggers** are Issue events (found, back, fixed, assigned, retest requested or decided), SLA due
soon and breached, a risk acceptance expiring within seven days (announced once each by the expiry
sweep) or expired, a scan or import completing, and two the sweep fires without an event: no
completed scan or import for N days (once per quiet stretch) and schedules (hourly, daily or weekly,
UTC, once per slot). "Advisory matched" arrives with the advisory engine (Week 68).

**Conditions are Rego**, evaluated by the OPA the policy gate already uses: one policy language. A
condition is the body of one rule, written against `input.issue`, `input.project` and `input.event`;
Bulwark wraps it in a fixed module and evaluates a whole batch in one `opa eval`
(`hits contains i if { some i, item in input.items; match with input as item }`), so a scan's five
hundred new Issues are one process, not five hundred. The condition is untrusted code even from an
Admin: `http.send`, `net.lookup_ip_addr` and `opa.runtime` are removed from OPA's capabilities, the
network allow-list is empty, `opa` runs with an empty environment and a ten-second limit, and a
condition may not declare its own package or imports. A field with no value is absent from `input`,
never filled with a guess.

**Actions**: assign (to a person's @handle), set a priority band, add tags, mark ready for retest,
request a verified fix, and notify. A band set by hand or by a rule is stored apart from the computed
one (`issues.priority_override`) and wins wherever a band is read -- the issues table, the SLA when
it is by priority -- and no recomputation clears it. That is how a rule "applies a stricter SLA":
named per-Issue SLA policies were not built. Ticket and group actions come with ticketing (Week 66).
Each action reports per subject whether it changed something, changed nothing, was skipped or
failed, with why; one failing does not stop the others. `notify` sends one message per run, not one
per Issue.

**Safety (T26).**
- *Dry run.* "Test this rule" replays the last seven days of the trigger's events (or the current
  state, for the sweep's triggers) through the condition, without acting: "would have matched 37
  issues; 1 of its 4 runs would wait for an Admin". It reads each Issue as it is now, and says so.
- *Bulk confirmation.* Matches are grouped by cause: the scan or import that caused them, else the
  event type, project and minute. A cause that would have a rule act on more Issues than its
  threshold (25 by default, 1 to 1,000) applies nothing: the run is held, and an Admin applies or
  dismisses it. Later matches from the same cause join the held run.
- *Depth limit.* An event a rule caused carries the chain's depth; a rule set off at depth 3 does not
  run and a `depth_limited` run says so. An action that changes nothing announces nothing, so a rule
  cannot re-fire itself on its own no-op.
- *Idempotence.* Each run records the (event, subject) pairs it handled; a redelivered batch is
  recognised and never acted on twice.
- *AI budget.* A fix request is refused when the organization's monthly token budget is spent, or
  when the rule already requested `max_per_day` (default 3, at most 20) fixes in the last day.
- *Admins only.* Writing, testing, enabling and deleting rules and deciding held runs need the new
  `rules:write` scope. Reading rules and runs is `scans:read`.
- *Audit.* Every rule change is a hash-chained entry with the whole definition and a new version;
  every run is one too (`rule.run.applied`, `.held`, `.confirmed`, ...), and each change a rule makes
  to an Issue is its own entry by `rule:<id>`, which the Issue's history names.

**Runs** have their own table (`rule_runs`): rule and version, cause, depth, status, the subjects,
the event keys and each action's result. A run is committed before it acts, so an action that fails
rolls back only its own work, never the record that the run happened. Deleting a rule keeps it and
its runs, and dismisses its held runs.

*Amended 2026-10-12 (load test).* A run whose actions only change Bulwark's own rows (assign,
priority, tag, retest, group) applies them in one transaction with its audit entries and its result
(`repo.audit_in_one_commit`), each action in a savepoint: a failing action still undoes only itself,
and its audit entry goes with it. Before, every change and every audit entry was its own commit,
which held one dispatcher to about 520 events a second; now about 880. A run with a ticket, a fix
request or a notification still commits per action: those reach outside, or commit on their own.

**OPA ships in the app image**, pinned to the release CI uses and checked against its published
SHA-256 for amd64 and arm64.

## Consequences

- Rules act seconds after the event (the dispatch interval), not inside the transaction that caused
  it. A crash between acting and marking the batch only means the batch is seen again.
- "Admin" is a token scope until roles exist (Week 75).
- The dry run's count is today's view of last week's events; an Issue fixed since still counts.
- Grouping by minute is a heuristic: a burst of SLA crossings in one sweep is one cause, but two
  unrelated assignments in the same minute in one project share a cause too. That only affects when
  confirmation is asked for, not whether an action runs twice.
- Rule evaluation latency at p95 under load (plan §60) was not measured this week.
