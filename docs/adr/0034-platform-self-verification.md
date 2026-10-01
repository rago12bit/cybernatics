# ADR-0034: Verifying the platform itself

Status: Implemented (2026-10-01), Week 48 (plan §22.3).

## Context

Bulwark scans other projects for security issues. Week 48 is the project turning that same scrutiny
on itself: fuzzing its own parsers, running its own DAST tooling against its own web app, auditing
itself against OWASP ASVS, and scanning its own dependencies the same way it scans others'.

## Decisions

### Fuzzing infrastructure is real and reviewed; actually running it is not

`tests/fuzz/fuzz_adapter.py` (Atheris) cannot run on this project's macOS dev machine at all --
confirmed by trying, not assumed: Atheris needs a real Clang+libFuzzer build, and Apple's shipped
Clang deliberately omits libFuzzer. The harness, the golden-file-seeded corpus
(`scripts/seed-fuzz-corpus.sh`), the nightly CI job (`.github/workflows/fuzz.yml`, Ubuntu, where
Atheris ships a prebuilt wheel), and the "every crash becomes a regression test" mechanism
(`tests/fuzz_regressions/`, `tests/unit/test_fuzz_regressions.py`) are all real and were verified as
far as this machine allows: the regression-replay mechanism was proven with a synthetic crash file
before being left empty, and a manual boundary-case probe of all nine fuzzable adapters (empty
input, truncated JSON, non-UTF8 bytes, deeply nested structures) found no crash -- every adapter
already fails closed by logging a warning, not raising. Real coverage-guided fuzzing explores inputs
no hand-picked case would think to try, which is the entire reason this task exists; the corpus
starting empty is an honest state, not evidence of completeness.

### DAST against the platform's own web app found real gaps; they were fixed, not just logged

Running a real ZAP baseline scan against the actual production build (not the dev server, whose
HMR/CSP noise would misreport findings that don't exist in production) found three missing
cross-origin isolation headers on every real page: `Cross-Origin-Embedder-Policy`,
`-Opener-Policy`, and `-Resource-Policy`. Each was added to `web/proxy.ts` and verified twice --
once by re-running the ZAP scan until the specific warning cleared, once by loading the app in a
real browser to confirm nothing broke (this app loads no cross-origin fonts/images/scripts, so
`require-corp` had nothing to break). The warnings that remain are all scoped to `/_next/static`
assets, which intentionally skip the per-request middleware for performance -- a disclosed,
deliberate tradeoff that predates this week, not a newly-found gap left unaddressed.

### The ASVS self-assessment is scoped at the control level, with real citations, not a 280-row checkbox exercise

OWASP ASVS 4.0.3 Level 2 has on the order of 200+ individual numbered requirements. Rather than
producing a superficially complete table with 200+ rows of unverified or guessed status, 
`docs/ASVS-SELF-ASSESSMENT.md` organizes by ASVS's own V1-V14 chapters with one row per genuinely
distinct control area, each citing real file:line evidence gathered by actually reading the code
(not inferred from docstrings or assumed from architecture). Three real, previously-undiscovered
gaps were found and fixed as part of writing it, not left as findings for someone else to act on
later: HSTS was only ever set for the public demo build (fixed with an explicit
`BULWARK_FORCE_HTTPS` opt-in, not forced on for every production build, which would break the
documented plain-HTTP self-hosted path); Bulwark had no vulnerability scanning of its own
dependencies despite shipping that exact capability as a product feature (fixed: a new
`dependency-audit` CI job plus Dependabot); and SECURITY.md's claim of archive "depth limits" was
not actually implemented in `core/ingest.py` (fixed for real, not just corrected in the doc). Two
real gaps were found and deliberately left open, disclosed rather than hidden: no rate limiting on
authentication attempts, and no general API abuse-prevention beyond the existing LLM-cost limiter --
both judged lower-severity for the project's current single-operator trust model than for a
multi-tenant deployment, but real, tracked gaps either way.

### Supply-chain hardening: real, verifiable pieces shipped; the release pipeline itself is disclosed as unexecuted

GitHub Actions across `ci.yml` and `fuzz.yml` are now SHA-pinned (not floating major-version tags)
and carry explicit least-privilege `permissions: contents: read` blocks, matching the precedent
`.github/workflows/bulwark.yml` already set. `.github/workflows/scorecard.yml` runs OpenSSF
Scorecard weekly and publishes results publicly (the README badge). `.github/workflows/release.yml`
builds `bulwark/app`, generates SLSA Build Level 3 provenance via
`slsa-framework/slsa-github-generator`'s own reusable container workflow, and signs the image
keylessly with cosign (GitHub's own OIDC identity for the run, no stored private key) -- but this
workflow has never actually run: triggering it means pushing a real container image to a real
registry under a real version tag, which this session has no credentials for and would not do
without being explicitly asked to cut a release regardless. The job structure follows
slsa-github-generator's documented contract as faithfully as can be verified without running it;
the one deliberate exception to "always SHA-pin" is the generator reusable-workflow reference
itself, pinned by tag per that project's own stated requirement that callers reference one of their
published, audited releases, not an arbitrary commit.

## What is NOT done

- No real Atheris run has ever executed, on any platform, for this project. The nightly CI job has
  never fired.
- `release.yml` has never run. SLSA provenance and a signed image for a real Bulwark release do not
  yet exist.
- `scorecard.yml` has never run. The README's Scorecard badge will show nothing resolvable until it
  does.
- Branch protection rules (a Scorecard check, and a repository setting, not a workflow) were not
  configured as part of this ADR -- that is a GitHub repository-settings change, outside what a
  workflow file can do, and outside what this review changed.
- Rate limiting on authentication attempts and general API abuse-prevention remain open, disclosed
  gaps (`docs/ASVS-SELF-ASSESSMENT.md`'s own summary table), not silently accepted.
