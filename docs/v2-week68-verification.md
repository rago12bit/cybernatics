# Week 68 verification: the advisory engine (plan §46.2, §55.5)

A factual record of what was built, run and measured. The decision is
[ADR-0052](adr/0052-advisory-engine.md); the comparison with osv-scanner is
[evaluation-advisory-matching.md](evaluation-advisory-matching.md).

## What was built

- **Feeds** (§46.2), every six hours on the worker: OSV's data for PyPI, npm, Go and Maven (the
  whole dump the first time, then only the records `modified_id.csv` lists as changed), CISA KEV,
  and CVEs NVD changed recently (no key). Each source's state -- last run, last success, records,
  last error -- is kept and shown.
- **Matching** with OSV's range semantics over each ecosystem's version order, as osv-scanner
  matches, kept as impacts per vulnerability, library version and project; re-run for a project
  when its SBOM is recorded, and for changed vulnerabilities when the feeds update.
- **The Advisories page**: every vulnerability affecting a current SBOM, the newest first and,
  within a day, known-exploited and most severe first; filters (not acted on, Issues created, known
  exploited only) and search; the state of the feeds.
- **The impact view** (§55.5): KEV status and due date, the sentence ("An affected version is in N
  projects across M business units. K of them import it from application code."), every project
  with version and fix, whether its code imports the library, owner, exposure and its Issue; the
  fix line; "Create Issues in N projects, grouped under …"; what is no longer affected; details and
  references.
- **Issues in one click**: per project, through an "Advisories" Test re-imported whenever the
  vulnerability's impacts change there -- so they deduplicate with osv-scanner's Issues, close
  when an SBOM no longer has an affected version, and reopen if it comes back; grouped per
  vulnerability, assigned to the project's owner, filed to the project's tracker.
- **Notifications**: the first time a vulnerability affects the organization, the team channels (a
  new `advisory` kind, off/instant/digest) and the affected projects' owners.
- **Project owners**, set on the project page.
- **Component search** lists each version's advisories.
- **Migration 0040.** Shared advisory tables; `advisory_impacts` and `advisory_states` under forced
  RLS; `assets.owner`.

## Found and fixed along the way

1. **By comparing with osv-scanner** (see the evaluation): timestamps with other than 3 or 6
   fractional digits silently dropped most of PyPI's records; npm and Go versions that are not
   strict semver; GIT ranges; PyPI legacy versions; the version list compared as text.
2. **By the unit tests:** the verdict cache was keyed by advisory, not by package entry, so one
   range's "no" was reused for the package's other ranges (paramiko). The cross-check now also runs
   through the database path, so this kind of bug shows up there.
3. **By the benchmark:**
   - Recording one project's SBOM re-matched those libraries in every project and rewrote every
     impact row; matching after a recording is now limited to that project and writes only rows
     whose answer changed. New impacts and announcements are written in bulk.
   - The morning list built every vulnerability's full header, with its own KEV and NVD queries,
     and read every open impact before keeping 100: 17 s at 19,000 vulnerabilities. It now sorts
     from a few bulk reads, without the long text, and counts details for the page only.
4. **On this machine:** python.org's Python had no CA certificates configured, so HTTPS failed.
   Fetches now verify against certifi's bundle (installed with httpx) instead of failing -- and
   never skip verification.
5. **In the browser:**
   - The issue page labelled the advisory's own text "AI" (it does so for any finding whenever no
     AI explanation exists); the label now appears only on AI-written text.
   - The long KEV badge widened the page on a phone; it wraps.
   - The heading's own CVE was repeated as an alias; the project owner's label was in the global
     upper-case style.
   - The list sorted by first-seen time alone; known-exploited and severity now order each day.
6. **By reading the code:** advisory reference URLs come from outside; only `http(s)` addresses are
   kept, and the page filters again before rendering a link.

## Checked against real systems

- **osv-scanner 2.6.0**, offline, on the same OSV snapshot: see the evaluation.
- **Live sources, once each** (6 October 2026): CISA KEV, 1,734 entries; NVD's API without a key,
  one page, 1,643 CVEs changed in the last day, 7 s; OSV incremental for Maven with the cursor moved
  back a day, 13 changed records fetched one by one, none different from the snapshot.
- **Postgres 16, migration 0040** up, down to 0039 and up; RLS enabled and forced on
  `advisory_impacts` and `advisory_states`, not on the shared advisory tables.
- **RLS:** `tests/integration/test_advisories_rls_docker.py` passes as `bulwark_worker`; with RLS
  off on either table it fails; all 59 RLS tests pass.
- **Scale** (`scripts/bench-advisories.py`, Postgres under forced RLS as `bulwark_worker`): see
  below.
- **Browser**, the real API with the real Maven, PyPI and Go data and the real KEV list, six seeded
  projects: Log4Shell first in the list (known exploited, critical, 4 projects); its impact view
  (the importing project first, owner, fix 2.15.0 or 2.3.1); Issues created in 4 projects, each
  linked; the payments project's Issue critical, P1 100/100 (CVSS 10, KEV, reachable), assigned to
  its owner; the owner set on the project page; phone width; component search showing each
  version's advisories.

## Scale

`scripts/bench-advisories.py` on Postgres 16 as `bulwark_worker` under forced RLS, with all four real
OSV dumps loaded.

- **Ingesting** the four dumps the first time: 31 s (npm's 230,000 records 24 s). Reading them again
  unchanged: 11 s, nothing written.
- **300 projects**, each SBOM 1,000 packages with 5% drawn from advisory-named packages at range
  boundary versions (far more vulnerable than real SBOMs): 647,125 open impacts, 14,057
  vulnerabilities.

  | | p50 | p95 |
  |---|---|---|
  | recording one SBOM, matching included | 0.59 s | 1.41 s |
  | the morning list (100 rows) | 968 ms | |
  | the list, known exploited only / search | 665 / 712 ms | |
  | the impact view of a vulnerability in all 300 projects (1,300 uses) | 49 ms | |

  A full re-match of the organization (what a large feed update does): 30.6 s, on the worker.
- **Stress**, 50 projects with 30% of each SBOM vulnerable: 466,952 open impacts; recording and
  matching one SBOM p50 3.0 s, p95 4.4 s; full re-match 44 s; impact view 107 ms.

Before the fixes above, the list took 17 s and the impact view 1.2 s at this scale.

## Tests

- Backend: `test_advisories.py` (8: reading OSV, writes only on change, matching following the
  inventory, the list and the impact view, Issues in one click with a ticket and their closing and
  reopening, owners and the team hearing of it, the feeds, one Issue with osv-scanner's).
- Web: `advisories.test.tsx` (3, with axe).
- Integration: `test_advisories_rls_docker.py`.

## Not done, or not proven

- PyPI, npm, Go and Maven only.
- Reachability is import-level (v1); no call-path evidence per vulnerable function.
- The incremental OSV path ran live once, on 13 records; the full first run of npm's 218 MB dump was
  run from the downloaded file, not fetched by the task.
- Ticket filing for advisory Issues was exercised against the recorded Jira responses only (no live
  Jira), as in Week 66.
- "Draft VEX for the others" is Week 69.
