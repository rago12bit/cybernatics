# ADR-0016: Detect upstream scanner output drift via pinned versions and scheduled bump tests, not daily schema polling

Status: Accepted (2026-09-27). Design only; no new automation implemented yet. Applies to all current and future
`ToolAdapter` implementations (currently Bandit, Semgrep, Gitleaks, Trivy, OSV-Scanner, plus opt-in Grype,
Checkov, gosec, Dockle), and to the import-format side of ingestion.

## Context

Bulwark wraps the output of a growing number of upstream open-source scanners. None of them publish a formal,
versioned output schema to validate against — their "schema" is whatever the currently-installed version happens
to emit. When an upstream tool changes its output shape (a renamed field, a new severity string, a restructured
JSON envelope) between releases, the adapter that parses it can silently misparse or drop findings without
raising any error, and nothing currently in the pipeline would notice before a user does.

A proposal to catch this via "automated daily schema validation against the upstream repositories" is solving
the right problem with a mechanism that doesn't fit it: there is no upstream schema to validate against, and
daily polling doesn't match how often these tools actually release (most cut a new version every few weeks to
months, not daily).

## Decision

Two changes, layered:

1. **Pin exact tool versions in the scanner Docker images**, if not already fully pinned, so an adapter never
   silently starts parsing a different tool version than the one it was written and tested against. Drift then
   only happens on a deliberate version bump, never on an unattended `latest` pull.
2. **A scheduled CI job (weekly, not daily) that bumps one tool's pinned version at a time in an isolated branch
   and runs the existing golden-fixture adapter tests against it.** If the new version's output breaks parsing or
   changes shape in a way the golden fixtures catch, the job fails loudly and opens a tracked issue, instead of
   the drift surfacing as an unexplained drop in findings in production. This reuses the adapter test
   infrastructure that already exists rather than building a second, parallel validation system.

Weekly cadence, not daily: matches how often these tools actually cut releases, and avoids spending CI minutes
re-checking versions that haven't changed.

## Alternatives considered

- **Daily validation against upstream repositories' published schemas, as originally proposed.** Rejected: most
  of these tools don't publish a formal output schema at all (their output shape is implicitly whatever the code
  emits), so there is nothing concrete to validate against short of actually running the tool — which is exactly
  what the golden-fixture bump job does, on a cadence that matches real release frequency instead of an arbitrary
  daily poll.
- **Do nothing extra; rely on user bug reports to catch drift.** Rejected: for a security tool, a silent drop in
  findings is a false sense of safety, which is a worse failure mode than a visible error — the whole point of
  catching this proactively is to fail loudly in CI instead of quietly in someone's real scan.

## Consequences

- Each `ToolAdapter`'s existing golden-fixture tests become dual-purpose: they already verify correctness today,
  and now also gate the scheduled version-bump job. A `ToolAdapter` added without golden fixtures is not covered
  by this drift detection, so fixtures are a checklist item for any new adapter, not optional test coverage.
- The version-bump job runs against a branch, never main directly — a version bump is only fast-forwarded once
  its own fixtures pass, keeping this consistent with how dependency bumps are handled elsewhere in the project.
- This does not cover drift in *imported* formats (SARIF, other scanners' native JSON ingested rather than
  executed by Bulwark itself) — that surface has no pinned version to bump in the first place, since Bulwark
  doesn't control when an external CI pipeline upgrades the tool producing that import. Import-format drift stays
  a runtime validation concern (reject/flag unrecognized shapes on ingest) rather than something a scheduled job
  can pre-empt.
