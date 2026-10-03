# Weeks 54-56 verification -- Ingest and reimport (plan Phase 13, §41.1/§42, Milestone M12)

Honest record of what was built, run, and measured. Weeks 54 (ingest endpoint and reimport), 55
(standard parsers) and 56 (import screen and fuzzing) were done as one body of work in eight tasks,
because each depends on the one before. The design decisions are in
[ADR-0040](adr/0040-one-ingest-path.md); the user-facing description is
[docs/ingest-api.md](ingest-api.md).

## What was built

| # | Task | Result |
|---|---|---|
| 1 | Schema and ADR-0040 | `engagement_tests`, `import_records`, `outbox_events` (migration 0027); amends ADR-0039 |
| 2 | Repo layer and RLS | helpers plus a two-tenant leak test for all three tables |
| 3 | Reimport engine | `core.imports.reimport.plan_reimport`: new / unchanged / reopened / closed (+ `detached`) |
| 4 | Ingest service | preview, apply (idempotent, row-locked), revert; native scans moved onto the same decision |
| 5 | Parser framework and SARIF | `IngestParser`, registry, sandboxed parsing (`docker/ingest-parser`) |
| 6 | CycloneDX, SPDX, OSV; fuzzing | three more parsers, an XXE corpus, an Atheris harness |
| 7 | Ingest API | `POST /v2/ingest` and six more endpoints, worker job, scopes, migration 0028 |
| 8 | Import screen and close-out | the §55.1 screen, docs, this record |

## Bugs found and fixed along the way

Most of these were found by running things for real, not by reading code. Several would have shipped
green on SQLite and mocks.

1. **A cross-tenant leak that predates this work** (the serious one). A database session could run as
   *another organization* after a commit. Row-Level Security reads `app.current_org` from the
   *connection*, but a session hands its connection back to the pool on every commit and takes
   whichever is free next, and the org had been set once per session at session level -- so it landed
   on a connection the session might never see again and stayed there for the next session to
   inherit. Reproduced on real Postgres with two overlapping sessions: the first one's next statement
   after a commit ran as the second org (it could read, and write into, the other tenant). It needs
   concurrent requests from different organizations, which is why every single-session test missed it;
   single-org self-hosting was never exposed. Fixed in `core/tenancy.py` (the org is re-applied,
   transaction-local, at the start of every transaction); five regression tests interleave sessions on
   a two-connection pool, one reads back real rows, and **all five fail without the fix**. See the
   changelog entry.
2. **A whole report collapsed into one Issue.** Parsed findings have no fingerprint until
   `correlate()` runs; reimport matches by fingerprint, so four findings all matched the empty one.
   Found by the first end-to-end API test (my unit-test helper correlated, hiding it). Now an explicit
   step, `core.imports.prepare`; removing it fails 7 tests.
3. **Uploaded secrets would have been stored.** A scan's Gitleaks redacts at the source; an uploaded
   file carries no such guarantee. `redact_secret_findings` now runs before correlation, so no function
   of a secret is fingerprinted either. Removing it fails 3 tests.
4. **Every applied upload leaked onto disk**: `apply_import` clears the path the job then needed to
   delete. Found by an assertion that the upload directory is empty afterwards.
5. **Findings were inserted before the Issues they reference.** SQLite does not enforce foreign keys
   and never noticed; Postgres refused. Found only by running against real Postgres.
6. **The parser sandbox's input directory had to be the shared scratch path**, because in the worker
   container the Docker daemon is on the host (as `run_tool` already does for its output).
7. **JSON and XML disagreed on a real file**: XML lost every finding's file path, and counted the
   document's own subject as a component. Found by comparing the two on a real Grype file; they are
   now byte-identical.
8. **The periodic scratch cleanup would have deleted a previewed upload while a person was deciding.**
   It removes anything under the uploads directory after two hours, and a preview keeps its file until
   confirmed. Ingest uploads now live in their own directory with a lifetime tied to the import's status
   (`core.maintenance.expire_stale_imports`: a preview nobody confirms in 24 h is cancelled and its file
   deleted; an import a worker never finished is failed rather than left "in progress"; finished imports
   are never touched). Found by reading what else touched that directory, not by a failing test.
9. Smaller: `google-re2` has no `IGNORECASE` constant (caught at import by the tests); a maintenance
   RLS test asserted on the whole database and failed on rows other tests left; the shared SARIF
   mapper dropped region-less results and missed lower-case CWE tags.

## Validated against real, live things -- not mocks

- **Real files from real tools.** Syft (CycloneDX JSON and XML, SPDX 2.3), Grype (CycloneDX 1.7 with a
  `vulnerabilities` section, as JSON and XML), Semgrep (SARIF) and OSV-Scanner, generated by the
  project's own images (`tests/golden/ingest/README.md`). Grype's JSON and XML give identical findings
  (19 each). A real Semgrep SARIF imports to exactly what the native path reads from it, and OSV-Scanner
  output through the new parser equals the native adapter's.
- **Real Postgres under Row-Level Security** as the non-superuser `bulwark_worker`: 53 integration
  tests pass together. They cover the three new tables (another org cannot read, enumerate, dispatch or
  forge rows), the whole ingest flow over HTTP, another org getting 404 on every import endpoint, two
  orgs importing interleaved, and **two simultaneous uploads of one file applying exactly once** (it
  fails 3 of 3 times if the row lock is removed).
- **The real sandbox container.** Parsing runs in `bulwark/ingest-parser`: same findings as in-process;
  hostile, oversized and truncated files refused inside the container; a container that cannot start
  reads as an error, never an empty report; and from inside it the network, DNS, `/app` and `/etc` are
  all unreachable, the user is non-root, and the database layer is not in the image.
- **XML attacks**: external entity (file and network), external DTD, parameter entity, billion laughs,
  quadratic blowup and a harmless internal entity are all refused in under 2 s, nothing from
  `/etc/passwd` surfaces, no connection is attempted -- in-process and inside the container.
- **Ground-truth property tests** for the reimport decision: Hypothesis replays random import sequences
  into two Tests and compares every count against an independent set-arithmetic oracle; no strict
  prefix of any real report ever reads as complete; mutated real reports and arbitrary bytes never raise.
- **Mutation checks.** Each deliberate regression makes the tests fail: ignoring other sources, ignoring
  `close_missing`, widening the close scope, stdlib XML, swallowing truncation errors, letting an SBOM
  close issues, dropping redaction, dropping correlation, removing the row lock, and (in the screen)
  changing the confirmation wording, saving on upload, and showing counts before the format is confirmed.
- **Fuzzing, for real (but briefly).** Atheris was built from source in a Linux container
  (`scripts/fuzz-ingest-docker.sh`) and run for 90 s per parser seeded from the real files: **1.80 million
  executions** (SARIF 901,207; CycloneDX 168,919; SPDX 670,743; OSV 62,759), **no crash or hang**, each
  corpus growing (65-232 entries).
- **A real browser against the real stack.** The import screen was driven in a browser against the real
  API on the real Postgres with the real parser container: a Semgrep SARIF previewed as "3 new" and was
  imported ("Imported: 3 new, 0 reopened, 0 closed"); a second report previewed as "0 new, 2 unchanged,
  0 reopened, 1 closed", imported with the same numbers, and the database showed 1 fixed / 2 open;
  Undo restored all three; an unrecognised file asked which format it was and showed no counts; a
  truncated file failed with a readable message and an Import button never appeared.
- Backend: `ruff`, `black`, `mypy` (234 source files) clean; 1942 unit tests pass (1803 at the start of
  Week 54), 2 skipped. Web: 236 tests (+16), `tsc` clean, `npm run build` clean.

## What this does NOT prove (read before relying on it)

- **The fuzzing is a smoke run, not a campaign.** 90 s per parser found nothing, which is weak evidence.
  The nightly CI job (`fuzz-ingest`) is written and the harness is proven to run, but that job has never
  executed on a CI runner; the real depth comes from it running for weeks.
- **Each format is exercised against the producers I could run.** CycloneDX and SPDX: Syft and Grype
  only (other generators, e.g. cdxgen or Trivy, may use features not seen). SARIF: real Semgrep output
  plus a hand-written file *shaped like* CodeQL's (results before rules, `ruleIndex`, lower-case CWE
  tags, `security-severity`); no real CodeQL file was tested. OSV: OSV-Scanner results only -- a bare
  OSV advisory record is deliberately not importable.
- **SPDX imports no findings, by design**, and reads only SPDX 2.x JSON (not tag-value, RDF or 3.0). An
  SBOM becomes useful as a component inventory in a later week; until then it is recognised, validated,
  and cannot close anything.
- **"Your own runners switch to the same ingest path" is true at the decision-and-writer level, not the
  HTTP level.** Native scans now call the same `plan_reimport` and the same Issue writer (and emit the
  same outbox events), but a scan does not POST to `/v2/ingest`. The plan's wording could mean either;
  this is the version that removes the duplicated logic without routing every scan through an upload.
- **The outbox has no consumer.** Events (`issue.created`, `issue.reopened`, `issue.closed`,
  `scan.completed`, `import.reverted`) are written in the same transaction as the change, which is the
  property that matters, but nothing dispatches or prunes them yet; the first consumers are the SLA,
  rules and notification weeks. Until then the table only grows.
- **Per-source deduplication (plan §42.3) is not built** (Week 58). `wait_for_dedup` is accepted and
  `dedup_complete` is always true; every source matches by the same project-level fingerprints, and the
  screen's Matching row is read-only text for that reason. `source` only accepts `upload`.
- **The screen is thinner than the wireframe in two places.** Issues are listed by the first eight
  characters of their id (there is no human-friendly `ISS-311` numbering yet), and "Into [Change]" edits
  a Test name and a choice of engagement type rather than browsing existing engagements (that list
  arrives with Week 64). It was verified in a real browser once and by 15 jsdom tests with axe; there is
  no Playwright journey (Week 74).
- **Issue identity is still project-level and fingerprint-based**, so two tools describing one defect in
  different words import as two Issues until the matching work in Week 58.
- **`detached` is not shown as a fifth big number** on the screen (it appears as a sentence), because the
  plan's wireframe has four.
- **The §39.5 gate item that needs a live model is still open** (the fix agent's verification record on a
  real pull request), unchanged from Week 53.
- **Preview expiry is 24 hours, fixed.** It is a constant in the maintenance task, not a setting, and
  the sweep is covered by unit tests but has not run under a live Celery beat.
