# ADR-0022: Taint findings attach to Issues, feed scoring, and reach the UI

Status: Implemented (2026-09-29, follow-up within Week 38). Closes the three items ADR-0021
deferred: "Taint paths attached to Issues; reachability v2 feeds scoring; UI: the taint-path
stepper goes live" (plan's own Week 38 line item).

## Context

ADR-0021 built the taint engine itself but stopped at `core.taint.analyze()` returning an in-memory
`list[TaintFinding]` — nothing connected it to an actual scan's `Finding`s, to risk scoring, or to
the UI. This closes that gap.

## Decision

### Enrichment, not a new finding type

`core/taint/reachability.py::attach_taint_paths()` never creates a `Finding`. It matches an
existing SAST `Finding` (already produced by Semgrep, Bandit, or another SAST tool) to a taint
sink by exact `(path, start_line)`, and only then attaches the path — the same role
`core.reachability`'s package-level reachability already plays for SCA findings: "is something
another tool already flagged actually reachable," never "here is a vulnerability nothing else
found." A SAST finding whose own location has no matching taint sink is returned completely
unchanged.

### The confidence field, not a new scoring formula

`core/risk/score.py::score_finding` already has a rule for exactly this situation: a finding with
no CVE/EPSS/KEV data (true of essentially every SAST finding) uses `scoring.confidence` directly as
its likelihood. Rather than adding a second, parallel "taint reachability" multiplier that would
need to be kept consistent with the existing CVE/EPSS/KEV/confidence logic, `attach_taint_paths`
raises `confidence` to a fixed `TAINT_CONFIRMED_CONFIDENCE = 0.9` (never lowers it) when a concrete
path is found, and lets the existing formula do the rest. Measured effect on a synthetic
HIGH-severity SAST finding: risk_score 56 → 71 once a real taint path is attached — a meaningful,
correctly-directed change, not a cosmetic one.

`scoring.reachable` is set separately, through the same `Assess` composition `core.reachability`
already uses: `core/postprocess.py::finalize()` builds one combined `assess` callable that tries
`TaintIndex.assess` (SAST) then falls back to `ReachabilityIndex.assess` (SCA) — the two never both
apply to the same finding, so trying taint first costs nothing when a finding is SCA.

### No new database table

`FindingRow.data` (`core/persistence/models.py`) already stores a `Finding`'s full `to_dict()`
output as JSON. Adding `taint_path: tuple[TaintPathStep, ...]` to the `Finding` dataclass
(`core/models/finding.py`) means every taint path persists automatically through that existing
column — no migration, no new table. `CodeGraph`/`FunctionSummary` themselves are still not
persisted (ADR-0021's own deferral stands); only the final, already-attached path on a `Finding`
is.

### Per-step code snippets are captured at scan time, not fetched later

The plan's own UI mockup (§28.3) shows the code view changing as each step is clicked, including
steps in files other than the sink's own. There is no "fetch arbitrary file content" API, and
building one is a larger, separable piece of work. Instead, `attach_taint_paths` takes the scanned
workspace's root path (still on disk at that point in the pipeline — `core/scan.py`/
`core/pipeline.py` call `finalize(..., root=target)`) and reads a few lines of context around each
hop directly, storing it on `TaintPathStep.snippet`. This is the one point in the whole pipeline
where the checked-out source is guaranteed to still exist; capturing it here is strictly cheaper
than building a new on-demand file-serving endpoint, at the cost of a fixed, non-configurable
context window (2 lines either side) rather than letting the UI request more.

### The UI stepper already existed, built ahead of the data

`web/design-system/taint-stepper.tsx` was built in an earlier week explicitly "static until Phase 9
supplies real paths," rendering the finding's own location as the one honest step until then. This
change is almost entirely on the data side: `IssueDetail.tsx` now maps `finding.taint_path` (when
non-empty) into the stepper's existing `TaintStep[]` shape, defaults the active step to the sink
(not step 1 — matching the plan's own mockup, where the code view opens on the dangerous call), and
passes each step's own path/line/snippet to `CodeView` as it's clicked. The one real component
change: the sink's ◄ marker used to be tied to whichever step was currently clicked (`activeIndex`),
which meant it would move away from the sink the moment a user clicked a different step and lose
its meaning; it's now driven by `TaintStep.isSink`, a fact about the data, independent of what the
user has clicked.

### Backward compatibility with data persisted before this change

A `Finding` written to the database before this change has no `taint_path` key in its stored JSON.
Both the Python (`finding_from_dict`'s `d.get("taint_path", ())`) and TypeScript
(`finding.taint_path ?? []`) sides default it to empty rather than raising — found directly by an
existing accessibility test whose fixture predated this field and crashed on `undefined.length`
until the fallback was added, not by inspection.

## Consequences

- A repository's real, currently-unpatched SQL injection or command injection reachable from an
  HTTP entrypoint now visibly outranks an otherwise-identical but unreachable finding — the
  "Why it's ranked first: Reachable from POST /login, a public route" line from the plan's own
  mockup is now real output, not illustrative copy.
- The taint engine's own precision limits (ADR-0021: no FastAPI typed-parameter sourcing, no
  object-field taint, not path-sensitive) apply here unchanged — a finding this doesn't enrich is
  not "confirmed unreachable," it is "no confirmed path found," and its score is unaffected either
  way, the same "unknown, not false" discipline the rest of this project already holds to.
- The next real gap is Postgres persistence of the graph itself, for a consumer that needs to query
  it directly rather than through a `Finding` it already produced — still not this week's problem.
