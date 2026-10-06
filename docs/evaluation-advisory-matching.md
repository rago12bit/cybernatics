# Advisory matching, checked against osv-scanner (Week 68, plan §46.2, §60)

Plan §46.2: "Getting range matching right is the hard part; test it against osv-scanner on the same
SBOMs." This is that test: what was run, what agreed, and every case that did not.

## Method

`scripts/osv-crosscheck.py`, seed 68:

1. **The same data for both.** OSV's per-ecosystem dumps for PyPI, npm, Go and Maven, downloaded
   once on 6 October 2026 (the `all.zip` files, 276 MB). osv-scanner reads them as its offline
   database (hard links in its cache layout, `--offline --offline-vulnerabilities`, so it downloads
   nothing); Bulwark ingests the same files through `feeds.update_osv`.
2. **The hard versions.** For up to 1,000 packages per ecosystem that advisories name, every version
   at a range boundary (each `introduced`, `fixed` and `last_affected`) and up to three listed
   affected versions: where range matching goes wrong. One CycloneDX SBOM per ecosystem.
3. **Both matchers, both paths in Bulwark.** osv-scanner 2.6.0 (Google's release binary,
   SHA-256-verified) on each SBOM. Bulwark twice: `affects()` directly, and the real path -- the
   SBOM recorded as a project's inventory, matching run by the inventory, impacts read back from the
   database -- so the stored answer is checked too, not only the function.
4. **Compared per package and version**: the set of advisory ids each says apply.

## Results

| Ecosystem | Advisories in the dump | Package versions | Agree | Differ | Matches, Bulwark | Matches, osv-scanner |
|---|---|---|---|---|---|---|
| PyPI | 26,080 | 4,903 | 4,888 | 15 | 83,769 | 83,717 |
| npm | 229,998 | 1,584 | 1,583 | 1 | 2,031 | 1,720 |
| Go | 9,491 | 4,960 | 4,879 | 81 | 131,902 | 131,412 |
| Maven | 7,168 | 10,274 | 10,269 | 5 | 166,976 | 166,908 |
| **All** | | **21,721** | **21,619 (99.5%)** | **102** | **384,678** | **383,757** |

**osv-scanner never reports an advisory Bulwark misses.** In all 102 differences Bulwark reports
more. Bulwark's stored matches equal its direct evaluation everywhere except one Go package (below).
The full report, every difference listed, is `benchmarks/advisories/osv-crosscheck-2026-10-06.json`.

## Every difference

- **Go, 80: module paths with capitals** (`github.com/QuantumNous/new-api`). osv-scanner lowercases a
  Go package URL, as the purl specification suggests, and then finds nothing, because OSV records
  Go modules in their real case and Go module paths are case-sensitive. Bulwark keeps the case and
  matches. Probed directly: osv-scanner reports no vulnerability for that module at any version.
- **Go, 1: a record whose package name is a URL** (`https://github.com/filebrowser/filebrowser`).
  Bad data in the source; no package URL can name it, so it is in neither tool's results through an
  SBOM (Bulwark's direct evaluation matched it; its stored path, like osv-scanner, could not).
- **Maven, 5: Maven's own order.** `9.0.0-M1` and `9.0.0M1` against a range starting at
  `9.0.0.M1`, and Liferay's `7.3.1-1` against one starting at `7.3.1-ga2`. Maven 3.9.16's
  `ComparableVersion`, asked directly, says `9.0.0-M1 == 9.0.0.M1` and `7.3.1-1 > 7.3.1-ga2`: the
  versions are inside the ranges. osv-scanner's Maven ordering differs from Maven's here; Bulwark
  follows Maven.
- **PyPI, 15: versions PEP 440 calls equal.** Each is an affected entry with a GIT range, which both
  tools match by its explicit list of versions only; the list has `6.0` and the SBOM has `6.0.0`
  (or `2.0`/`2`, `2.8.0rc0`/`2.8.0-rc0`). osv-scanner compares the list as text (after dropping a
  leading `v`), Bulwark as versions; PEP 440, and PyPI, say they are the same release. All 52
  advisory matches behind these 15 were checked to be exactly this case.
- **npm, 1: a capitalised name** (`OpenClaw`, 311 advisories). Bulwark compares npm names in lower
  case (npm's own rule for new names, and the purl specification's); osv-scanner compares exactly.

## What the comparison changed in Bulwark

The first runs disagreed far more, and each cause was fixed rather than explained away:

1. **Timestamps.** OSV writes up to nine fractional digits; Python 3.10 reads three or six. Every
   record with another number was silently dropped (most of PyPI's). Now parsed with any number.
2. **Lenient semver** for npm and Go, as osv-scanner reads it: `19.03.0`, `2.62`, `9.6.0b1` are in
   OSV's own Go data.
3. **GIT ranges**: an entry with one is matched by its version list alone (probed: osv-scanner flagged
   0 of 40 versions inside such an entry's ECOSYSTEM range but missing from its list, 39 of 40 for
   entries without a GIT range).
4. **PyPI legacy versions** (not PEP 440, such as Debian's `0.8.3ubuntu7.5`): ordered before every
   PEP 440 version, as setuptools did, instead of "could not compare".
5. **The version list compared as versions**, so `v1.6.5` is found in a list holding `1.6.5`.
6. **The stored path:** a verdict cache keyed by advisory instead of by package entry reused one
   range's "no" for the package's other ranges (OSV lists a package once per range); found by the
   unit tests, and the database comparison above was added so this class of bug is caught here too.

## Limits

- Four ecosystems; the plan says every one.
- The sample is boundary versions of advisory-named packages: harder than real SBOMs, not
  representative of them. Real projects' SBOMs were not available to compare.
- osv-scanner was run on CycloneDX SBOMs, not lockfiles; its lockfile readers were not compared.
- One snapshot of OSV's data, one osv-scanner version (2.6.0).
