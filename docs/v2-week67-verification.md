# Week 67 verification: component inventory (plan §46.1)

A factual record of what was built, run and measured. The decision is
[ADR-0051](adr/0051-component-inventory.md).

## What was built

- **The inventory.** Every package of every SBOM, by library and version, per project: from a full
  scan's Syft SBOM, and from every CycloneDX (JSON or XML) and SPDX 2.x file imported, with or
  without a vulnerabilities section. One row per library per organization (`libraries`), one per
  library version per project per SBOM (`components`), the latest SBOM of each source marked
  current. A pull-request scan is not recorded. Reverting an import makes the previous file's
  packages current again.
- **What each component says:** its manifests, direct or transitive, its license, and for Bulwark's
  own scans whether the application's code imports it (reachability v1, now run for every SBOM
  package, not only those with findings).
- **Version order per ecosystem** (`core/versions.py`): PyPI, npm, Go, Maven, and version
  conditions such as `>=2.0,<2.17.1`.
- **Search:** `GET /v2/components?purl=&version=&project_id=` and `GET /v2/libraries?q=&ecosystem=`.
- **The Components page** (header link): a library box that suggests libraries by name as you
  type, a version condition, the answer in one sentence, the versions in use (which match, which do
  not, which could not be compared), and every project with its version, dependency type, whether
  its code imports the library, its exposure and where the library was found. The query is in the
  URL. Without a query it lists the most-used libraries. Phones get one block per project.
- **Backfill.** An hourly task records the latest SBOM of projects scanned before this week and
  recounts each library's use.
- **Migration 0039.** `libraries` and `components`, under forced RLS.

## Found and fixed along the way

1. **Found by comparing with Maven itself:** my first Maven comparator, written from memory of
   `ComparableVersion`, disagreed with Maven 3.9.16 on 537 of 34,017 random pairs. Maven 3.9 opens a
   sub-list before a qualifier unless it starts the list (`1.0.alpha` is `1-alpha`). Read off the
   jar's bytecode, rewritten: 0 disagreements.
2. **Found by comparing with osv-scanner** (during Week 68's work, fixed here because the order is
   shared): osv-scanner reads npm and Go versions leniently (`19.03.0`, `2.62`, `9.6.0b1`), and OSV's
   own data contains them. Bulwark now reads them the same way; for strict semver nothing changes
   (still 0 disagreements with npm's `semver` on 6,000 pairs).
3. **Found by the benchmark:** listing libraries aggregated every component row -- 94 ms at 6,000
   rows, so seconds at millions. Libraries now keep their project and version counts.
4. **Found in the benchmark itself:** its first generator drew libraries from a heavy-tailed
   distribution with repeats, so a "1,500-package" SBOM held about 350. That run was stopped and
   discarded; the reported numbers are from SBOMs of exactly 1,500 distinct libraries.
5. **Found in the browser:**
   - The app header is one row that never wrapped: the new Components link pushed it past 1,024 px,
     and on a phone it was already wider than the screen. It now wraps.
   - Short table cells broke mid-word ("Transitiv/e", "Intern/et"); the project column had the
     global table-header background. Fixed.
6. **Found by the tests:** a second import into the same Test went to a new Test in my test (the
   form field is `test_id`, not `test`); the Maven case for "could not be compared" was wrong --
   Maven, like Maven itself, reads any string as a version.

## Checked against real systems

- **Postgres 16 (pgvector image), migrations 0039** up, down to 0038 and up again; `libraries` and
  `components` have RLS enabled and forced.
- **RLS:** `tests/integration/test_inventory_rls_docker.py` (2 tests) pass as `bulwark_worker`. With
  RLS switched off on `libraries`, or on `components`, the test fails; restored, it passes.
- **Speed** (`scripts/bench-components.py --projects 1000 --packages 1500`), one organization, as
  `bulwark_worker` under forced RLS: 3,000,608 component rows (1,500,305 current), 40,001 libraries,
  seeded through the real write path in 1,048 s. 20 runs each:

  | Query | p50 | p95 |
  |---|---|---|
  | `log4j-core <2.17.1` (211 projects, 7 versions) | 5.9 ms | 29.8 ms |
  | the most-used library, every version | 15.6 ms | 28.9 ms |
  | the most-used library, `>=1.0,<3.0` | 2.5 ms | 14.2 ms |
  | a library nobody uses | 0.3 ms | 0.3 ms |
  | name search `artifact-1` | 2.6 ms | 24.1 ms |
  | most-used libraries, no query | 1.4 ms | 1.6 ms |

  The version count uses `ix_components_library_current` (0.33 ms in `EXPLAIN ANALYZE`). These are
  the core queries; the API adds serialization of up to 2,000 rows.
- **Browser** (the real API on SQLite, six seeded projects in two business units): the most-used
  list; typing `log4j` suggested log4j-core; with `<2.17.1` the answer read "is in 4 projects
  across 2 business units: 3 internet-facing, 1 importing it from application code", with 2.17.1
  marked outside the condition; the shared URL reproduced it; at 375 px the page was 375 px wide
  and the "could not be compared" note showed. No console errors.

## Tests

- Backend: `test_versions.py` (11, including 2,518 Maven and 6,000 npm pairs from the real
  implementations), `test_inventory.py` (7: scans, PR scans, merging, backfill, imports and revert,
  search, other orgs, libraries).
- Web: `components.test.tsx` (3, with axe).

## Not done, or not proven

- Files imported before this week are not in the inventory; their uploads are gone.
- "Imported by application code" covers Python and JavaScript only (reachability v1).
- The library list's counts can lag a deleted project by up to an hour.
