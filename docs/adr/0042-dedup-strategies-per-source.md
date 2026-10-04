# ADR-0042: Deduplication is chosen per source, versioned, and changed only through a dry run

Status: Accepted (2026-10-04), Week 58 (plan §42.3, §55.1; "ADR-018" in the plan's own numbering --
renumbered to this repository's sequence, as ADR-0038 explains). Builds on
[ADR-0004](0004-fingerprinting-and-correlation.md) and
[ADR-0040](0040-one-ingest-path.md); the DAST identity it relies on is
[ADR-0041](0041-dast-and-network-identity.md).

## Context

Every finding is matched to an Issue by one rule: its fingerprint (ADR-0004), with a path-free
fallback for code. That is right for source code, where a defect moves, and arbitrary for everything
else. A Nessus export has a stable plugin id and a host; a pen tester's tool may have neither; an SCA
report has an exact package and version. DefectDojo lets a project choose how each *source* is
deduplicated, and the plan (§42.3) asks for the same, with one non-negotiable property: **changing
it must be previewed** -- "switching Nessus to `tool_id` would merge 212 issues into 97 and split none"
-- because a deduplication change rewrites Issue identity, the thing every state, ticket and triage
decision hangs on.

## Decision

### Five strategies, as key functions (`core/dedup/strategies.py`)

A strategy turns a Finding into a key; findings with equal keys are one Issue.

| Strategy | Key | For |
|---|---|---|
| `fingerprint_v2` | the finding's existing fingerprint | SAST (and the default) |
| `tool_id` | category, source, the rule id(s), and where (file, URL, or package without version) | tools with stable ids |
| `hash_fields` | source plus the chosen fields (a closed list of thirteen) | tools without stable ids |
| `tool_id_or_hash` | `tool_id`, or `hash_fields` for a finding with no rule id | mixed quality |
| `package` | the SCA fingerprint (ecosystem, package, version, vulnerability id) | SCA |

`package` is `fingerprint_v2` for a package -- an SCA fingerprint already is that key -- and is
selectable so a package source's setting says what it means. Every other key is namespaced
(`dd1:<strategy>:<sha256>`): it cannot collide with a fingerprint, and the `1` versions the key scheme.
`hash_fields` takes a closed list of fields, not free text, so a setting cannot be a way to read
anything off a finding and a dry run can always explain it.

### A setting is per (project, source) and versioned by insertion

`dedup_settings` (migration 0029, tenant-isolated): a change is a new row with the next `version`,
never an edit, so the table *is* the history -- who, when, why, and what it did (`effect`). With no
row a source uses `fingerprint_v2`, which is what every Issue was matched by before settings existed,
so **nothing changes until someone chooses**. The strategy each parser suggests
(`IngestParser.default_dedup`: `tool_id` for the DAST and network parsers, `package` for the SCA
ones) is only a recommendation shown beside the choice.

A *source* is whatever tool the finding says reported it (`evidence.reported_by[0]`). For a SARIF
import that is the driver's name (`semgrep-oss`), not the parser's; a native Semgrep scan's source is
`semgrep`. They are different sources with different settings, and the screen lists the names that
actually occur in the project.

### Applied before matching, for imports and native scans alike

`core.dedup.settings.rekey` overrides a finding's key just before it is matched to an Issue -- in
`apply_import`/`preview_import` and in `sync_issues_for_scan` -- so a source is matched the same way
however its findings arrive, and an import preview shows the counts the setting will produce. A
chosen key also **switches off the path-free fallback**: that fallback matches findings across files,
which is exactly what a project that put `path` in its key said it does not want.

### The dry run, and what applying does (`core/dedup/change.py`, `service.py`)

Existing Issues are re-keyed by the same rule, judged by each Issue's **latest occurrences** (the
findings of the last scan that saw it); older history stays attached to the Issue it was recorded
against. For a source's Issues:

- one new key: the Issue takes it (**re-key**);
- several keys among one Issue's occurrences: it is **split** -- it keeps the key most of them have,
  and each other key becomes a new Issue, a copy of this one as it is now;
- one key across several Issues: they are **merged** -- the oldest survives, the others' occurrences
  move to it and they disappear.

`preview_change` reads and writes nothing and returns counts, examples and a **digest** of the exact
plan. `apply_change` takes the digest, recomputes the plan inside one transaction under a lock on the
project's Issues, refuses (409) if it differs -- the project moved since the preview -- and otherwise
applies it, records the next setting version with its effect, stages a `dedup.changed` outbox event,
commits, and appends the audit-chain entry. The preview is `ingest:read`, the apply `ingest:write`.

What a change never loses, tested: every occurrence (they move between Issues; none disappear);
external ticket links and verified-fix runs of an Issue that is merged away (they move to the
survivor, except a second ticket on the same tracker); and no open Issue is ever hidden behind a
decision made about another one -- if the members of a merge disagree about triage, the merged Issue
is **reopened for triage** and the preview counts those merges.

`wait_for_dedup` on `POST /v2/ingest` is now real: it holds the response until the import has been
matched (it leaves `queued`/`processing`), up to 20 s, and `dedup_complete` on an import is false
exactly while it is still queued or processing.

## Consequences

- An Issue that two tools reported (`reported_by` has more than one entry) belongs to neither
  source's setting and is left alone, with a count in the preview. Cross-source merging is not a
  strategy.
- A merge is not reversible one-for-one -- the merged-away Issues' own first-seen dates and triage
  history are folded into the survivor. Choosing the previous strategy again *splits* what it can and
  loses nothing, but it does not resurrect the exact Issues that disappeared. The screen says so.
- The `tool_id` key for a package omits the version, so the same vulnerability in two versions of one
  package is one Issue under it and two under `package`. That is its definition, and the dry run shows
  the effect on real data (benchmarks/results/dedup-strategies-2026-10-04.json): on DefectDojo's Snyk
  sample it merges 3 Issues into 2.
- The dry run reads the latest occurrences of every Issue of the source; on a very large project that
  is a scan of its findings. It has not been measured at scale.

## What is NOT done here

- **No precision or recall.** The plan's evaluation is "hand-labelled duplicate pairs from three tools
  across ten repositories". That corpus does not exist; `benchmarks/dedup_strategies.py` measures only
  what each strategy *changes* on real reports (a `tool_id` that merges more is not thereby better),
  and the evaluation says so. Until the corpus exists, the dry run and the person reading it are the
  safety, not a measured accuracy.
- The matching settings screen offers the strategies and fields; it does not suggest a strategy from
  the data, and it cannot yet scope a change to one engagement.
