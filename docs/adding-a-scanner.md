# Adding a scanner (and what Week 22 measured)

The design plan claims a new scanner is about 40 lines of adapter. Week 22 added four (Grype, Checkov, gosec,
Dockle) to test that, and the honest result is: **true only after a refactor, and only for tools that fit the
assumptions.**

## The measurement

Code lines = non-blank, non-comment, non-docstring lines in the adapter file, imports included, formatted by black
(100 columns).

| Adapter | First, in the style of the existing ones | After `core/adapters/helpers.py` |
|---|---|---|
| gosec | 47 in the class + ~17 of imports and constants | 45 |
| Checkov | 48 + ~17 | 48 |
| Dockle | 47 + ~17 | 42 |
| Grype | 60 + ~17 | 45 |
| Bandit (existing, migrated as a check) | 75 | 33 |

- The first versions were 76 to 89 lines of file each, about **twice** the claim. The repeated part was parsing
  safety, the canonical `Finding` shape, snippet hashing and severity normalisation.
- `JsonAdapter` (safe parsing, one bad record never loses the rest) and `make_finding` (the canonical shape) now hold
  that. Adapters are **42 to 48 lines** for the four new ones: close to the claim, not under it. Grype and Checkov
  are dense because their output has more to map. Bandit shrank from 75 to 33 and its golden test passes unchanged.
- A test (`test_a_new_scanner_stays_small`) fails any tier-2 adapter over 50 code lines.

Time to add each scanner was not measured; do not read anything into it.

## What happened on a real repository

Scanning terragoat (a deliberately vulnerable Terraform project) through the API and worker with Trivy, Checkov and
Grype, all `ok`:

- **SCA:** Grype reported 468 findings, 365 of them (78%) also reported by Trivy; Trivy reported 561 dependency
  findings, 365 (65%) also found by Grype. The tools genuinely disagree, which is the point of running two.
- **IaC: no cross-tool merging.** Trivy reported 243 misconfigurations, Checkov 477, and **0** were merged. They use
  different rule ids and IaC findings carry no CWE or advisory id to correlate on, so overlapping findings show up
  twice. Correlation only understands dependencies (shared advisory) and code (file, CWE, nearby lines). Adding an IaC
  identity (for example resource address plus a mapped control) is open work.

## What did NOT need to change

Correlation and deduplication (a Grype finding for lodash merged with Trivy's and OSV-Scanner's on the shared
advisory id, verified against the real tools), scoring, taxonomy, redaction, storage, the API, all exports and the
UI's rendering. That is the part of the abstraction that held.

## What did not fit, found by doing it

1. **Output file names.** Checkov chooses its own file name inside `--output-file-path`. The runner assumed
   `result.json`. Now `ToolSpec.output_name`.
2. **Sandbox resources silently change results.** gosec's taint rules (G701, G702, G705) vanished when `/tmp` was 64 MB:
   the Go build cache did not fit, and gosec still exited normally with fewer findings. Now `ToolSpec.tmp_size`
   (512 MB for gosec), and an integration test asserts the taint rules appear. Any tool needing a toolchain deserves
   that test.
3. **Offline analysis is partial.** gosec type-checks code and cannot download modules. Non-vendored third-party
   imports are not analysed, so results on a typical Go project are a subset. The fixture has no dependencies.
4. **Scope differences.** Grype cannot include dev dependencies, unlike Trivy and OSV-Scanner here, so agreement
   counts on dev-only packages will not include it. Open-source Checkov reports no severity, so every check is MEDIUM
   (a judgment call in the severity matrix, not Checkov's opinion).
5. **The target is not always a source tree.** Dockle lints a built image, which is not in a repository. The
   abstraction assumed a directory. It now supports one archive named `bulwark-image.tar` (`RepoContext.
   has_image_archive`) and the `bulwark scan-image REF` command saves a **local** image with `docker save` and scans
   it. This is a workaround, not a redesign: a scanner whose input is a registry image or a running system still does
   not fit.
6. **Image cost.** The Grype image is 3.7 GB because the vulnerability database is baked in (the sandbox has no
   network); Checkov is 550 MB. This is why tier 2 is opt-in.
7. **Default safety.** Adding tools to the registry must not change what an existing scan runs.
   `DEFAULT_TOOLS` (the original five) is what the CLI, API, UI, extension and action run unless told otherwise.

## Steps to add one

1. `docker/<tool>/Dockerfile`: pin the version (by digest where the base allows), bake in any data, run as uid 10001,
   set env so it never calls home. Add it to `docker-compose.yml` (`scanners` profile) and CI.
2. `core/adapters/<tool>.py`: a `JsonAdapter` with `spec`, `build_command`, `records`, `to_finding`.
   Override `applies_to` if the tool is not language-based.
3. Register it in `core/scan.py` (`ADAPTERS`; not `DEFAULT_TOOLS` unless it earns it), add its row to
   `core/scoring/severity.py`, its name to `core/observability/metrics.py` `TOOLS`, and an entry in
   `scripts/gen-licenses.py` (a test fails if you forget).
4. Run it for real in the sandbox on a fixture, save the raw output as `tests/golden/<tool>/raw.json`, **read** the
   parsed result against the raw output, then save `expected.json`. Add an integration test that asserts something the
   tool must find.
5. If it has scope or resource quirks, write them down in this file.
