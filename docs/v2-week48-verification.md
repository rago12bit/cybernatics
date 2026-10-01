# Week 48 verification -- fuzzing, DAST self-scan, ASVS, supply-chain hardening (plan §22.3)

Honest record of what was built, run, and measured. See [ADR-0034](adr/0034-platform-self-verification.md)
for the design decisions, including which pieces of this week could not be executed from this
session and exactly why.

## What was built

- `tests/fuzz/fuzz_adapter.py`, `scripts/seed-fuzz-corpus.sh`, `.github/workflows/fuzz.yml`,
  `tests/fuzz_regressions/` (task 1): an Atheris harness per scanner adapter, seeded from
  `tests/golden`, a nightly CI job with a fixed time budget, and the "every crash becomes a
  regression test" replay mechanism. `tests/unit/test_correlation_properties.py` (task 1): three
  Hypothesis property tests for fingerprinting (whitespace invariance, CWE sensitivity, symmetric
  matching), fully local.
- `.github/workflows/ci.yml`'s new `zap-baseline` job, `web/public/.well-known/security.txt`,
  three new security headers in `web/proxy.ts` (task 2).
- `docs/ASVS-SELF-ASSESSMENT.md` (task 3): a full ASVS 4.0.3 Level 2 self-audit, V1-V14, plus three
  real fixes it drove (`BULWARK_FORCE_HTTPS` for HSTS, `core/ingest.py`'s new depth limit, the
  `dependency-audit` CI job).
- `.github/workflows/scorecard.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`,
  SHA-pinned + least-privilege `ci.yml`/`fuzz.yml` (task 4).

## Validated against real, live things -- not mocks

- **A manual boundary-case probe of all nine fuzzable adapters**, against real `parse()`
  implementations: empty input, truncated JSON, non-UTF8 bytes, wrong-shaped JSON, deeply nested
  arrays, huge numbers, single-quoted pseudo-JSON. Zero crashes -- every adapter already logs a
  warning and returns no findings rather than raising. Confirmed this is a genuine finding, not a
  silent exception being swallowed, by checking the actual exception path raised nothing through
  `except Exception` in the probe script itself.
- **The fuzz-regression replay mechanism, proven with a synthetic crash file**: a hand-crafted
  "crash" placed in `tests/fuzz_regressions/bandit/`, confirmed discovered and replayed by
  `test_fuzz_regressions.py`, then removed -- proving the wiring works before being left empty for
  real findings, not merely asserted to work.
- **Atheris's real macOS build failure**, reproduced directly: `pip install atheris` fails with
  "Failed to find libFuzzer; you may be building using Apple Clang," confirming the disclosed
  platform limitation rather than assuming it from Atheris's own documentation.
- **A real ZAP baseline scan, four times, against a real production build** (`npm run build && npx
  next start`, `NEXT_PUBLIC_DEMO_ONLY=1` -- not the dev server, whose HMR/CSP noise doesn't reflect
  production): first run found 3 missing cross-origin headers (0 FAIL, 8 WARN against dev mode; 4
  WARN against the real production build once dev-mode noise was excluded); each header was added
  one at a time and the scan re-run until the specific warning cleared -- `Cross-Origin-Embedder-
  Policy`, then `-Opener-Policy` (which only appeared once COEP was fixed), then `-Resource-Policy`
  (which only appeared once COOP was fixed) -- confirming ZAP's rule 90004 reports this family of
  headers incrementally, not all at once. Final state: 0 FAIL-NEW, 4 WARN-NEW, all four scoped to
  `/_next/static` assets.
- **Every header fix, confirmed not to break the app**: a full page load (`/`, `/self-host`) in a
  real browser after each header addition, console messages checked clean each time.
- **`web/public/.well-known/security.txt` and its `/security.txt` redirect**, both loaded in a real
  browser: the file serves with the correct content, and the redirect actually resolves to the
  canonical well-known path (confirmed via the network request list, not just the final URL).
- **The three ASVS-driven fixes**: `core/ingest.py`'s new path-depth limit, tested with a
  10-component-deep zip entry rejected under `Limits(max_depth=5)` and a 3-component entry correctly
  still extracted; the `dependency-audit` job's exact commands (`pip-audit --desc off`, `npm audit
  --omit=dev`) run locally -- the only vulnerabilities `pip-audit` found locally were in this
  session's own stale bundled `pip`/`setuptools` (not a real project dependency), confirmed by
  upgrading them and re-running (0 findings, exit 0) before adding that upgrade as an explicit CI
  step rather than trusting whatever pip version ships with `actions/setup-python`; `npm audit
  --omit=dev` against the web app's real lockfile: 0 vulnerabilities.
- **Every GitHub Action version referenced in `ci.yml`/`fuzz.yml`/`scorecard.yml`/`release.yml`**,
  resolved to its real commit SHA via the GitHub API directly (not guessed or copied from memory),
  matching the exact major version already in use so this is a pinning pass, not an undisclosed
  version upgrade riding along with it.

## Verified

- `test_correlation_properties.py` (4 property tests), `test_fuzz_regressions.py` (mechanism proven
  live, 0 permanent regressions currently stored), `test_ingest.py` (+2 depth-limit tests, 12 total),
  `web/tests/proxy.test.ts` (7 tests, new file -- `proxy.ts` had no test coverage at all before this
  week). Full suite re-run clean after every task: 1481 unit tests passed, 1 skipped (the empty fuzz
  regression corpus, correctly not a failure). `black --check .`, `ruff check .`, `mypy` all clean.
- Frontend: full suite (198 tests) re-run clean, `tsc --noEmit` clean.
- Every workflow YAML (`ci.yml`, `fuzz.yml`, `scorecard.yml`, `release.yml`, `dependabot.yml`)
  parsed successfully with `yaml.safe_load` -- syntactically valid, though this does not and cannot
  prove GitHub Actions' own semantic acceptance of a workflow that has never actually run (see below).

## What this does NOT prove (read before relying on it)

- **No Atheris run has ever executed**, on this machine or in CI. The fuzz harness and nightly
  workflow are written and reviewed, never fired. The empty `tests/fuzz_regressions/` directory
  reflects that honestly -- it is not evidence that fuzzing would find nothing.
- **`.github/workflows/scorecard.yml` has never run.** The OpenSSF Scorecard score this week claims
  to improve towards 8+ is not yet measured; the README badge will not resolve to a real number
  until the workflow fires for the first time (on the next push to `main`, or the next Saturday
  cron).
- **`.github/workflows/release.yml` has never run**, and this session did not trigger it: doing so
  means pushing a real container image to a real registry under a real version tag, with no way to
  verify GHCR push permissions or the SLSA generator's exact behavior from here. The job structure
  follows `slsa-framework/slsa-github-generator`'s documented contract as closely as could be
  verified without executing it -- not the same as having confirmed it works.
- **The ASVS self-assessment is not a certification.** It is a self-audit by the project's own
  maintainer-assistant, not an independent third-party review -- real value, but not the same
  evidentiary weight as an external audit.
- **Two real gaps remain open by disclosed choice, not oversight**: no authentication-attempt rate
  limiting, no general API abuse-prevention. Both are in `docs/ASVS-SELF-ASSESSMENT.md`'s summary
  table as real, tracked follow-up work.
- **Branch protection was not configured.** It is a GitHub repository setting (Settings → Branches),
  not something achievable from a workflow file, and this review did not request or receive the
  repository-admin access that would be needed to change it even if asked.
