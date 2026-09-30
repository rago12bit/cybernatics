# ADR-0027: Verified-fix agent

Status: Implemented (2026-09-30), Week 42 (plan §21.2) — "the flagship v2 feature." Builds on
ADR-0015 (workflow safety limits, design-only), ADR-0017 (GitHub App), ADR-0020/0021 (call graph,
taint analysis), and Week 41's model gateway (ADR-0026).

## Context

The plan describes a loop: propose a patch for one Issue, verify it for real (rerun the rule, rerun
every scanner, optionally the project's own tests), and only then ask a human to approve opening a
pull request — never auto-merged. It asks for this to be implemented as a Temporal workflow
specifically, the first one in a codebase that has used Celery for scan fan-out since v1.0. Nothing
of this existed before this week: no `core/agent/`-style module, no PR-creation code anywhere
(confirmed before writing this — `core/github_app.py` only mints tokens and posts PR comments), and
ADR-0015 (Week 28) had deliberately fixed only the *shape* of the safety limits, leaving concrete
numbers to whichever week built the real thing.

## Decisions

### Temporal, stood up and validated live, not stubbed

The user chose the full option over deferring Temporal to plain Celery orchestration. `temporalio`
is a new dependency (`fixagent` extra, plus `dev`). Every claim below about Temporal's behavior was
checked against a real local Temporal server (`temporal server start-dev`, then
`temporalio.testing.WorkflowEnvironment` for the test suite) before being relied on:

- **Worker-restart durability** (the plan's own stated reason for choosing Temporal): started a
  workflow, killed the worker process mid-run, started a brand-new worker with no shared memory,
  and it resumed and completed correctly from Temporal's own event history — not assumed from
  Temporal's documentation, actually done.
- **The three ADR-0015 scenarios that don't need real wall-clock minutes to test** (approve, reject,
  max-attempts-exhausted, overall-timeout) run against `WorkflowEnvironment.start_time_skipping()`,
  a real (disposable) Temporal server whose clock fast-forwards through workflow timers —
  `tests/unit/test_fixagent_workflow.py` exercises the actual `VerifiedFixWorkflow.run()` code, not
  a reimplementation of its control flow. The fourth (a genuinely hung *activity* exceeding its own
  `start_to_close_timeout`) is covered by Temporal's own documented `ActivityError` semantics and
  code review, not a live timing test — that one proved awkward to script reliably in this
  environment; see docs/v2-week42-verification.md.
- **Two real integration mistakes were caught building this**, not assumed away: a workflow file
  containing top-level side-effecting code gets re-executed by Temporal's workflow sandbox on
  import (a first throwaway script called `asyncio.run()` at module scope and broke); and a
  workflow/activity file needs its heavy, non-deterministic imports (`anthropic`, `sqlalchemy`,
  `subprocess`) kept OUT of module-level imports and lazily imported inside each `@activity.defn`
  function instead, or the sandbox's determinism checks complain about the workflow module itself.

`docker-compose.yml` gets `temporal`/`temporal-ui`/`fixagent-worker`, all behind a new
`--profile fixagent`, pointing Temporal's own Postgres storage at the SAME Postgres instance
`bulwark` already runs (separate databases, auto-created) rather than a second Postgres container.

### The five allowlisted tools: four are real, one is deliberately not a tool

`read_file`, `search_code`, `get_call_path` are real, path-contained functions
(`core/fixagent/tools.py`) the model can call freely while composing a patch — validated live
against real, on-disk Python source, including confirming path-containment rejects `../` escapes,
absolute paths, and empty input. `propose_patch` is the terminal call that ends the turn.

`run_verification` — the fifth tool the plan names — is **not** exposed as something the model can
call mid-turn. Verification means applying an untrusted patch to a real checkout and executing
scanners (and optionally the project's own tests) against it: a materially heavier, more
security-sensitive operation than reading text. The workflow (`core/fixagent/workflow.py`), not the
model, decides deterministically when that happens — after a turn ends, always, every attempt —
rather than leaving "when do we mutate and execute a sandboxed checkout" to model discretion. This
is a real interpretation choice, not an oversight: the plan's flow diagram shows verification as
workflow-level control flow (loop-back arrows into "propose patch" carrying feedback), consistent
with this reading.

### Tool-calling is new infrastructure, hosted-only, and extends `client.py` rather than replacing it

No tool-calling code existed anywhere in this repository before this week (confirmed: `LLMClient
.complete` is single-shot text in, text out). `AnthropicClient.complete_with_tools` is new but
additive — every existing caller of `complete()` (Week 12/13's remediation feature, Week 41's
gateway) is untouched. Only the hosted (Anthropic) backend implements it: native tool-calling is a
provider-specific protocol, and building it against the local Ollama backend too would have doubled
this week's newest, least-proven surface for a capability privacy mode doesn't strictly need (a
verified-fix run already touches a live GitHub App and the public internet via a PR; "the code never
leaves the machine" isn't the promise verified-fix makes in the first place). Consequence: verified
-fix does not currently work as a *local-only* pipeline the way Week 41's remediation suggestions
now can.

Every tool result the model sees is scrubbed for secrets (`core.llm.scrub`) and redacted for PII
(`core.llm.pii`) before being sent — the same two layers Week 41 built, reused rather than
duplicated. The system prompt states, in the same plain terms `prompts/fix/v1.md` already uses, that
tool output is data from an untrusted repository, never instructions. A repair-style retry exists at
the contract level (an invalid `propose_patch` call is told "rejected: <reason>" as its own tool
result and the model gets to try again within the same turn budget) but the **rejected reply is
never itself echoed back**, for the same reason Week 41's one-repair-attempt design avoids it: a
rejected reply already failed validation, so feeding it back would open a second-order injection
channel.

### Verification reuses `core.scan.scan()` wholesale; "changed files" is a filter, not new scan scope

Nothing in this codebase can scope a scan to a subset of files (confirmed: `ToolAdapter.applies_to`
filters by language, not by file list). Rather than build that, `rerun_rule`/`rerun_scanners`
(`core/fixagent/verify.py`) run a full `core.scan.scan()` of the whole patched checkout and filter
the result: `rerun_rule` checks whether the finding's own fingerprint still turns up when only the
originating tool runs again; `rerun_scanners` checks whether any finding on the *changed* file(s) has
a fingerprint that wasn't already present in the pre-patch baseline. A real, non-obvious fact
surfaced while testing this: `core.scan.scan()` always recomputes `Finding.fingerprint` via
`correlate()`, even for a single, unmerged finding — a fingerprint hand-assigned on a fake `Finding`
in a test is silently discarded and replaced with the correlator's own value, so verifying "the same
defect is gone" only works when the rescanned content actually hashes the same way (same path,
snippet, CWE, rule ids) as the original. This is real, useful discipline, not a workaround: it means
the check is honestly tied to what a real rescan would report, not to a label a test (or, worse, a
future caller) could set arbitrarily.

### A second, more permissive sandbox for tests — not a mode of the scanner sandbox

`core/runner.py`'s scanner sandbox is `--network=none`, read-only, non-root, all capabilities
dropped: correct for reading code, useless for installing a project's own dependencies and running
its test suite. `core/fixagent/sandbox.py` is a deliberately separate, more permissive function
(network on, writable tree, default Docker capabilities rather than `--cap-drop=ALL`) rather than a
runtime branch inside the existing one — validated live against a real `python:3.12-slim` container
(`pip install pytest`, a real passing run, then a real failing one, both with real captured pytest
output). This is explicitly the plan's own "hardened Docker runner, for now": ADR-0015 already
named Firecracker (Phase 11, not yet built) as the eventual, properly-isolated execution environment
for this; picking a precise minimal capability set for arbitrary language ecosystems' build tooling
is real, ecosystem-specific work this pass does not attempt, and the gap is disclosed rather than
papered over with a guessed-at middle ground.

Gated by two independent conditions, both required: the caller opts in (`run_tests: true` plus an
image and command), and the asset is "verified owner" — defined as `Scan.github_installation_id is
not None`, i.e. it was scanned via an installed GitHub App, which is GitHub's own proof that the
installer has admin rights on that repository. No new ownership-verification column was added; this
reuses data that already exists for exactly the reason the plan's wording implies (`hardened Docker
runner... verified-owner repositories only`). Asking for `run_tests` on a non-verified asset is a
normal request, silently downgraded to "no tests," never a 4xx — the same shape decision Week 40's
Dependencies screen made for an unopted-in `syft`.

### GitHub PR creation via the Contents API, not local git

`core.gitfetch.clone_repo` deletes `.git` from every checkout it makes (an existing, unrelated
isolation choice) — there is no local git history a verified-fix checkout could commit from. Since
every patch this feature ever produces touches exactly one file (`core.llm.contract.validate_patch`
already enforces that, reused as-is), the GitHub REST Contents API (`create/update a file` in one
call, given its current sha) is sufficient and far simpler than the lower-level git-data blob/tree/
commit API a multi-file change would need. `core/fixagent/github_pr.py`'s five-call sequence (read
the default branch, read its head sha, create a branch ref from it, read the target file's current
sha on that branch, update it, open the PR) was built by reading GitHub's documented, long-stable
REST v3 contract, and is unit-tested against a fake, sequenced `Transport` (the same injection
pattern `core.ci.github.upsert_comment` already uses) — but **not validated against a real, live
GitHub App installation**: this environment has no App credentials to test against. This is an
honest, disclosed gap, not a hidden one; see docs/v2-week42-verification.md.

### Persistence: a new table, not an overload of `IssueRow.triage_status`

`IssueRow.triage_status`'s own docstring already says it is "a human decision layered on top of
[scan-derived] state" — conflating "an automated agent is mid-attempt, or awaiting human approval"
with that would blur two concepts this schema has deliberately kept separate since Week 34. A new
`verified_fix_runs` table (migration `0012`) carries `org_id` directly and gets the same
`tenant_isolation` RLS policy `assets`/`scans`/`llm_usage` already have (validated live against a
real Postgres container: inserted a row as one org, confirmed a different `app.current_org` sees
zero rows, then confirmed the migration's down/up cycle is clean). `latest_patch`/
`verification_record` are JSON blobs, matching `FindingRow.data`/`RemediationCache.payload`'s
established "keep the full document" pattern — the fix-review screen renders one run's whole record
at once, nothing here needs server-side filtering.

### ADR-0015's three numbers, picked and documented (`core/fixagent/limits.py`)

Per-attempt: 10 minutes. Overall: 30 minutes, **excluding** the human-approval wait (started as its
own, separately-timed phase in the workflow, so a reviewer taking an hour doesn't itself trigger
`inconclusive` — the plan's own worked example, in fact: "took 2 attempts," a normal, unhurried
review). Concurrency: 3 per organization, enforced by `core.fixagent.store.count_running_for_org`
before starting a new run — checked, not merely asserted, since the whole point of a cap is refusing
the (n+1)th request, not just counting. A fourth, pragmatic (not an ADR-0015 limit) 7-day approval
timeout exists so a run nobody ever reviews doesn't live in Temporal forever; it resolves to
`inconclusive` with its own distinct `ended_reason` (`approval_timeout`), never folded into the
other three.

### The fix-review screen matches the plan's own mockup (§28.4), with one named cut

Verification record before the diff ("trust before content," the plan's own words) — implemented
exactly that way in `VerifiedFixPanel.tsx`. Failed attempts are shown, not hidden (`attemptSummary`
surfaces the first failed attempt's own feedback). The action that opens a pull request is labelled
"Open pull request," not "Approve," matching the plan's UI copy exactly, even though the API call
underneath is the same `/approve` signal. **"Edit" (revising the patch by hand before submitting) was
not built** — the plan's mockup shows three actions (`[Reject] [Edit] [Open pull request]`); this
ships two. Editing a pending patch would need a new mutate-in-place endpoint and workflow signal this
pass didn't build, and reasoning about a human-edited-then-verified patch (was the *edited* version
actually reverified, or only the AI's original?) is a real design question of its own, not a small
addition — deliberately deferred, not silently dropped.

## Consequences

- The verified-fix agent is real, hosted-only, and gated behind a compose profile — a base
  deployment is completely unaffected until an operator opts into `--profile fixagent` and sets a
  hosted LLM key.
- Local/privacy-mode users get Week 41's remediation *suggestions* but not verified-fix, since
  tool-calling is hosted-only this pass.
- The next real gaps, if this feature area grows further: MLX/local tool-calling (mirrors ADR-0026's
  own Ollama-only cut), a precise capability set for the test-execution sandbox (mirrors ADR-0015's
  own Firecracker deferral), an "Edit" action on a pending patch, and end-to-end validation against a
  real GitHub App installation once one is available to test against.
