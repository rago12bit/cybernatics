# ADR-0052: The advisory engine -- OSV's data, osv-scanner's matching, impacts kept, Issues in one click

Status: Accepted (2026-10-06), Week 68 (plan §46.2, §55.5). Builds on
[ADR-0051](0051-component-inventory.md) (the inventory and `core/versions.py`),
[ADR-0040](0040-one-ingest-path.md) (imports and reimport) and
[ADR-0050](0050-notifications-and-ticket-sync.md) (groups, tickets, notifications).

## Context

Plan §46.2: "Ingest OSV (every ecosystem), GitHub Security Advisories, CISA KEV additions, and NVD
on a schedule. Match by purl and version ranges, using OSV's range semantics (SEMVER, ECOSYSTEM,
GIT). Getting range matching right is the hard part; test it against osv-scanner on the same SBOMs.
Each new advisory produces an impact view (§55.5): affected assets, reachability, owners, and
one-click creation of Issues grouped by advisory. Global deduplication by library: one advisory
affecting 30 repositories becomes one Issue group with 30 Occurrences, not 30 unrelated rows."

## Decision

**Sources.** OSV's per-ecosystem data for PyPI, npm, Go and Maven -- which carries GitHub's reviewed
advisories, the PyPI and Go databases and the OpenSSF malicious-package reports, so GitHub needs no
token -- CISA's KEV catalog, and CVEs NVD changed recently (its public API, no key, requests spaced
for its 5-in-30-seconds limit). The first OSV run reads the ecosystem's `all.zip`; later runs read
`modified_id.csv` newest first down to the last change seen and fetch only those records. Fetches go
to three fixed HTTPS hosts, certificates verified against certifi's bundle, sizes bounded; a failing
source is recorded on its feed state and the rest carry on. Every six hours on the worker. Advisory
data is public and shared by all organizations (no `org_id`, no RLS); a KEV download with fewer than
100 entries never replaces the catalog.

**One vulnerability, one key.** OSV publishes the same vulnerability under several ids (GHSA-x,
PYSEC-y, CVE-z as aliases). `vuln_key` is a record's lowest CVE alias, else its lowest id or alias;
OSV aliases are symmetric, so the records of one vulnerability share it, as osv-scanner's groups do.
Everything an organization sees is per `vuln_key`.

**Matching follows osv-scanner, and where it does not, the ecosystem.** OSV's evaluation: a range's
events in version order, the last at or below the version decides. Versions in each ecosystem's
order (ADR-0051). Where osv-scanner behaves in a particular way the data depends on, Bulwark does
the same, each found by comparing the two:
- npm and Go versions read leniently (osv-scalibr's semver parser), because OSV's data has
  `19.03.0`, `2.62` and `9.6.0b1`;
- PyPI versions that are not PEP 440 in setuptools' legacy order, before every PEP 440 version;
- an affected entry with a GIT range is matched by its explicit `versions` list alone.
Where osv-scanner departs from the ecosystem's own definition, Bulwark keeps the ecosystem's:
Maven versions as Maven 3.9.16 orders them (`9.0.0-M1` is `9.0.0.M1`), a PyPI version in the
`versions` list when PEP 440 says it is equal (`6.0.0` is `6.0`), and Go module paths in their real
case. Each of these means Bulwark reports a vulnerability osv-scanner misses, never the reverse; the
cross-check (`scripts/osv-crosscheck.py`, `docs/evaluation-advisory-matching.md`) lists every one.
A version or range that cannot be compared is kept as "may be affected" (`certain = false`), never
dropped.

**Impacts are kept, not searched.** `advisory_impacts` holds each vulnerability at each library
version in each project's current SBOM, with the fixed version that applies. Matching runs for what
changed: after an SBOM is recorded (for that project only, in its own transaction after the
inventory commits, so a failure never undoes the inventory), and after a feed update (for the
changed vulnerabilities, every record sharing their key, in every organization; everything when
more than 5,000 changed). Only rows whose answer changed are written. An impact no longer true is
resolved, and reopens if it comes back.

**"Each new advisory produces an impact view."** The first time a vulnerability affects an
organization, an `advisory_states` row and an `advisory.matched` outbox event: the team channels
(a new team notification kind, `advisory`) and each affected project's owner hear of it once.

**The impact view (§55.5)** -- the vulnerability, KEV status, and for each project: version, fix,
whether its code imports the library (reachability v1), owner, exposure, and its Issue. Projects
whose code imports the library come first. "Not by application code" is as far as the words go:
the screen never says code is unreachable.

**Issues in one click.** Creating Issues marks the vulnerability adopted. Each affected project then
holds an "Advisories" Test whose content is, at every moment, a finding per adopted vulnerability per
affected library version -- imported through the ordinary path, so the Issues deduplicate with
osv-scanner's for the same package and CVE, and close when a later SBOM no longer has an affected
version (a scan's evidence, never a ticket's), and reopen if it returns. In each project the Issues
of one vulnerability form an issue group named after it, so a project with ticket settings gets one
ticket; the project's owner is assigned. "One Issue group with 30 Occurrences" is, in Bulwark's
model, one vulnerability with an Issue in each of 30 projects, grouped per project for tickets and
gathered on one impact view.

**Owners.** A project has an owner: a person (until user accounts, Week 75, a personal token), set by
@handle on the project page.

## Consequences

- Only PyPI, npm, Go and Maven. The plan says every ecosystem; others are a matter of a version order
  each (Cargo, NuGet, RubyGems, Packagist are next).
- Reachability is v1, import-level, Python and JavaScript only. Only Go's database names vulnerable
  functions; call-path evidence per advisory is not attempted.
- Malicious-package records (222,000 of npm's 230,000) are stored and matched: a project that has one
  sees it as critical.
- NVD is used only for the CVSS and description of CVEs whose OSV records carry none; its API
  without a key is slow by design (a page per 6.5 seconds).
- "Draft VEX for the others" (§55.5) is Week 69.
