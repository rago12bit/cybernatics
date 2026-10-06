# ADR-0051: The component inventory -- one row per library, SBOMs by source, versions in each ecosystem's order

Status: Accepted (2026-10-06), Week 67 (plan §46.1). Builds on the Week 40 SBOM summary
(`core/sbom/syft.py`, `Scan.sbom_summary`), the Week 52 import path (ADR-0040) and reachability v1
(`core/reachability`).

## Context

Plan §46.1: "Every package from every SBOM (Syft for native scans, uploaded CycloneDX or SPDX for
imports), stored per asset per scan by package URL (purl) and version. That answers the question
every team asks the morning a big CVE drops: 'where do we use this?' ... Index on purl so this
answers in under a second across the whole organization." Until now each scan kept its SBOM as one
JSON blob for the Dependencies screen, and an imported CycloneDX or SPDX file without a
vulnerabilities section was read, counted and thrown away.

## Decision

**A library is one row per organization** (`libraries`): its ecosystem plus its name as that
ecosystem compares names -- PEP 503's normal form for PyPI, lower case for npm, exact for Go and
Maven -- so `Flask_Login` and `flask-login` are one library. Names are kept the way OSV writes them
(Maven as `group:artifact`), so Week 68's advisories find a library by the name an advisory gives.

**A component is a library at a version in one project's SBOM from one scan or import**
(`components`), with the manifests it was found in, whether it is a direct dependency, its license,
and -- for Bulwark's own scans -- whether the application's code imports it (reachability v1, the
same verdict dependency findings already get: yes, no, or "can't tell", never a guessed no). Each
row says which SBOM it came from: `scan` for Bulwark's scans, `test:<id>` for files imported into a
Test. `current` marks each source's latest SBOM, decided from the database (the source's newest
scan by time), so two scans finishing out of order, or an import being reverted, leave the right
one current. Older rows stay with their scan as history and go when the scan goes.

**What is recorded:** the SBOM of a completed full scan of a project's real state (a pull-request
scan describes code that may never merge -- the same rule as Issue history), and every CycloneDX
or SPDX file imported, with or without vulnerabilities. Packages cross the parser sandbox as a
bounded list the API re-checks, like findings. Projects scanned before this week are filled in from
their latest SBOM by an hourly task; files imported before it cannot be, because their uploads were
deleted once applied.

**Versions are compared the way the library's ecosystem orders them** (`core/versions.py`): PEP
440 through `packaging`; for Maven the algorithm of Maven's own `ComparableVersion`, read off Maven
3.9.16's bytecode; and for npm and Go, semver read as leniently as osv-scanner reads it (its
osv-scalibr parser: `1.2` is `1.2.0`, `19.03.0` is `19.3.0`, `9.6.0b1` is a prerelease), because
OSV's own npm and Go data hold such versions and Week 68's matching must agree with osv-scanner on
them; for strict semver the order is semver 2.0.0's. Each is tested against the real
implementation -- 2,518 pairs compared by `maven-artifact` 3.9.16 and 6,000 by npm's `semver`
7.8.5, out of 34,017 and 6,000 checked during development with no disagreement. A PyPI version that
is not PEP 440 (`latest`), or a library of an ecosystem not yet supported, is reported as "could
not be compared" and counted neither in nor out. Week 68's range matching uses the same keys, so
the search and the advisory engine cannot disagree.

**The search** (`GET /v2/components?purl=&version=<2.17.1`) finds the library by its key, counts
its current versions with one indexed aggregate (`ix_components_library_current`), checks each
distinct version against the condition once, and only then reads the matching rows. It answers with
the projects, their business units, how many are internet-facing (the project's priority context;
"not set" said separately) and how many import the library from application code. Listing
libraries (`GET /v2/libraries`, the search box) reads each library's project and version counts,
kept as SBOMs are recorded and recounted hourly, so it never aggregates every component.

Amended in Week 68 ([ADR-0052](0052-advisory-engine.md)): a PyPI version that is not PEP 440 is no
longer "could not be compared" but ordered as setuptools' legacy versions, before every PEP 440
version, as osv-scanner orders it.

## Consequences

- Speed, measured (`scripts/bench-components.py`): 1,000 projects, each with two SBOMs of 1,500
  libraries (3,000,608 component rows, 1,500,305 current; 40,001 libraries), on Postgres 16 under
  forced RLS as an application role. Every search the screen makes answered in under 30 ms at the
  95th percentile -- "log4j-core <2.17.1" across 211 projects in 5.9 ms at the median. Recording an
  SBOM of 1,500 libraries took about 0.3 s at first, growing to about 0.75 s by 3M rows.
- "Imported by application code" is reachability v1: Python and JavaScript only, and an import is
  not a call to the vulnerable function. Go and Maven components say "can't tell". Imported files
  say nothing about it either.
- The counts in the library list can lag behind a deleted project by up to an hour; the search is
  always exact.
- Only PyPI, npm, Go and Maven versions are compared. Other ecosystems are stored and searchable by
  name, and every version condition on them is reported as not comparable.
