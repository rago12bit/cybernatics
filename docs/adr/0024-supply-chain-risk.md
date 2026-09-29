# ADR-0024: Supply-chain risk — malicious-package severity, license policy, typosquats, Scorecard

Status: Implemented (2026-09-29, Week 40), core detection and CLI done; the Dependencies screen UI
is explicitly deferred — see "Deferred" below.

## Context

Plan §20.5 names four checks: dependency health (OpenSSF Scorecard), malicious packages (OSV's
`MAL-` advisories), typosquatting, and license compliance against the SBOM — plus a "dependency
view" showing direct versus transitive packages, which path pulls in a vulnerable one, and the
smallest upgrade that fixes it. This closes Milestone M8 (Weeks 37–40: reachability, Issue
lifecycle, policy gates, supply-chain risk), tagged `v1.3.0`.

## Decision

### Malicious packages needed a severity fix, not a new pipeline

Before this week, running `osv-scanner --offline-vulnerabilities` (already Bulwark's default SCA
tool) against a package with a reported `MAL-` id already produced a `Finding` — OSV's database
includes OSSF's malicious-packages reports as ordinary records, confirmed live against
`api.osv.dev` (`reuests`, a real typosquat of `requests`, returns `MAL-2022-7441`). The bug: such a
record carries no CVSS score and no severity label, so it fell through to `normalize()`'s default —
`INFO`, the *lowest* severity — exactly backwards from what a confirmed malicious package deserves.
`core/adapters/osv_scanner.py` now detects a `MAL-` id in a group's aliases and forces `CRITICAL`
severity, `1.0` confidence, and a title/remediation that says "malicious package," not "upgrade to
fix." `core/policy/input.py` exposes this as `malicious` (always present, `false` by default, the
same shape as `in_cisa_kev`), and the starter library gained a sixth rule: no malicious packages,
ever, the same reasoning as its existing "no secrets, ever" rule.

### License policy needed license data to exist somewhere first

`core/policy/input.py::issue_document` already read `package["license"]` — ADR-0023 left the field
wired but unpopulated, honestly noting it needed this week's SBOM work. `core/sbom/syft.py` now
parses each CycloneDX component's own `licenses[]` (both the `expression` and `license.id`/`.name`
forms) into a new `SbomPackage`, and `core/sbom/enrich.py::apply_licenses` joins that onto a
finding's `package` by (ecosystem, name, version) — enrichment only, the same discipline
`core.taint.reachability` established: a package the SBOM has no license for is left unchanged, not
given a fabricated `"unknown"`. `bulwark ci compare` gained `--sbom PATH`; the GitHub Action reuses
its existing `sbom: true` input rather than adding a second one, and the "Generate SBOM" step moved
earlier (before "Compare and gate", not after) since gating is now something the SBOM can feed, not
only an artifact produced alongside it.

### Typosquat detection is genuinely new, not an enrichment

Nothing else in Bulwark looks at a package's *name* on its own, so `core/supplychain/typosquat.py`
produces new Findings directly from an SBOM's packages: a name within Levenshtein distance 1–2 of a
popular package in the same ecosystem, and not itself that name. The reference set
(`popular_packages.json`) is a small, hand-curated seed per ecosystem — there is no single canonical
"top N packages" API the way EPSS/KEV are canonical feeds, so this is honestly a starting point, not
a live popularity ranking.

### Scorecard is scoped to direct dependencies and split from the policy gate

`core/supplychain/scorecard.py` resolves a purl to its GitHub source repo via deps.dev
(`api.deps.dev/v3alpha/purl/<purl>`) and fetches that repo's own weekly Scorecard run
(`api.securityscorecards.dev/projects/<repo>`) — both validated against their live endpoints
(`github.com/psf/requests`, `github.com/sirupsen/logrus`) before any Python was written around
them, the same discipline ADR-0023 used for OPA. Two deliberate scope limits:

- **Direct dependencies only** (the plan's own wording): both because that is what an organization
  can act on directly, and because it bounds a scan to one request pair per direct dependency, not
  one per transitive package, which can number in the hundreds.
- **A separate command (`bulwark supply-chain analyze`), not folded into `ci compare`**: a
  typosquat or a Scorecard score is not a deny/allow policy decision the way a severity threshold or
  a Rego rule is — it is a report. Forcing it through the pass/fail gate would mean inventing a
  policy for data that is not itself a violation. It runs over an SBOM directly and writes a JSON
  report; a future policy could read that report's own fields the same way it reads `issue.license`
  today, once there is a real reason to gate on it.

Both cross network boundaries the sandboxed scanner runner deliberately does not (`core.risk.feeds`
already draws this same line for EPSS/KEV): API/worker side only, cached (a week for Scorecard,
matching its own refresh cadence), and best-effort — a network error yields `None`/an empty result,
never a failed scan.

### Direct-versus-transitive and "smallest safe upgrade" are two different, reusable pieces

`core/sbom/syft.py::summarize` now also derives `direct_purls`/`transitive_purls`/`graph`/`roots`
from CycloneDX's own `dependencies[].dependsOn` array — real only when the lockfile format Syft read
already recorded the tree (validated against a real `bulwark/syft:1.52.0` run: a component's
bom-ref is its purl plus a `?package-id=...` qualifier, not the bare purl, which the summarizer
translates before building the graph). `core/supplychain/dependency_view.py::path_to` walks that
graph to answer "which path pulls in this package." Separately, `core/scoring/versions.py`'s
`smallest_safe_upgrade` fixes a real, if minor, existing bug: both `osv_scanner.py` and `grype.py`
picked `fixed[0]` — whichever fixed version a scanner listed first, not the smallest — and a real
OSV record can list a version out of order, or list git commit hashes alongside real releases (this
codebase's own golden fixture has both cases). The fix compares dotted-numeric versions and refuses
to order a mixed list rather than silently mis-comparing a hash against a release.

## Deferred: the Dependencies screen UI

Plan §46/the supply-chain UI: a screen showing the dependency graph, the path to a vulnerable
package, and the smallest safe upgrade. Not built this session. The data it would render is real and
already tested (`Sbom.graph`/`.roots`, `dependency_view.path_to`, `scoring.versions.
smallest_safe_upgrade`, the `supply-chain analyze` JSON report) — this is a rendering problem, not a
data problem, the same relationship ADR-0023's deferred policy editor has to the policy engine it
would sit on top of.

## Consequences

- A malicious package now fails a default-severity gate the same way a leaked credential does,
  regardless of what severity label (if any) the underlying OSV record carries.
- License policy, typosquat detection, and Scorecard enrichment are all real and usable today from
  the CLI/Action without any UI — an organization runs `bulwark sbom`, then `bulwark ci compare
  --sbom` and/or `bulwark supply-chain analyze`, the same "mechanism before UI" shape ADR-0023 used
  for policy-as-code.
- The next real gaps are the Dependencies screen UI and, separately, wiring Syft into the hosted
  pipeline's own scan flow so license data exists there without a separate manual step — neither is
  this week's problem.
