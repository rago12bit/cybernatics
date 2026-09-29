# Week 39 verification — policy-as-code (plan §20.4)

Honest record of what was built, run, and measured — for Week 39: embedded OPA, a Rego starter
policy library, `opa test` in CI, and policy-driven pull-request check status / Action exit codes.
See `docs/adr/0023-policy-as-code.md` for the design decisions, including what was deliberately
deferred.

## What was built

`core/policy/`: a subprocess wrapper around the real `opa` binary (`opa.py`), an input-document
builder mapping existing `Finding` fields into the shape the plan's own example policy reads
(`input.py`), the five starter policies the plan names — no reachable KEV vulnerability, no
secrets, no new critical-severity issues, a license denylist, accepted risk capped at 90 days
(`starter/gate.rego`, with a full `opa test` suite in `starter/gate_test.rego`) — and the
high-level `evaluate_gate()` that ties them together (`gate.py`). `bulwark ci compare` gained a
`--policy PATH` option that folds policy denials into the same exit-code/comment/`$GITHUB_OUTPUT`
contract the severity threshold already used. `action.yml` gained a `policy-file` input, an
OPA-install step gated on it actually being set, and a `policy-violations` output.

## Validated against the real `opa` binary, not a mock

Every piece — syntax checking, evaluation, the starter library's own tests — was run against a real
`opa` v1.21.0 binary (downloaded, checksum-verified, and used to interactively validate the design
before any Python code was written), not a stubbed subprocess. The plan's own worked example
(§20.4's `deny contains msg if { ... in_cisa_kev ... reachable ... }`) was typed in and evaluated
against real input before `core/policy/opa.py` existed at all, to confirm the exact CLI flags and
JSON output shape (`opa eval -d policy.rego -I "data.pkg.deny" --format json`, stdin input via
`-I`/`--stdin-input`) before building around them.

## Real bugs found while writing the starter library's own tests

- **A `with` keyword placement error** (`count(deny with input as {...}) == 1`, invalid Rego —
  `with` must bind to a variable first, not appear inline inside a function call) — caught
  immediately by `opa test` itself refusing to parse the file, before it ever reached Python code.
- **An "unsafe variable" policy** (`deny contains msg if { false; msg := "" }` used in an early CLI
  test) actually compiles fine in Rego (body statement order doesn't gate safety analysis the way
  it might in an imperative language) — confirmed directly rather than assumed, after initially
  suspecting it would fail.
- **A genuinely unsafe policy** (an unbound `msg` used in the rule head with no assignment reachable
  in the body) does correctly fail `opa check`/`opa eval` with `rego_unsafe_var_error` — confirmed
  as the expected, correct OPA behavior for `core/policy/opa.py::check_syntax`'s own error path,
  not a bug.

## Verified

- 1049 backend tests passing (up from 1024 after Week 38's own follow-up: 25 new tests across
  `test_policy_input.py`, `test_policy_opa.py`, and the `--policy`/action.yml additions to
  `test_ci.py`/`test_action.py`), 2 skipped (unrelated), 94.3% coverage; `tests/integration/
  test_policy_opa.py` is skipped automatically when `opa` is not on `PATH`, the same convention
  `tests/integration/test_tools_docker.py` already uses for Docker; ruff/black/mypy all clean.
- `action.yml`'s own existing static-safety test suite (`tests/unit/test_action.py`: no
  `${{ }}`-interpolated shell injection, every third-party action pinned by commit SHA, every input
  wired to the step that uses it) passed unchanged against the new `policy-file` input, plus three
  new tests specifically confirming OPA is only installed when a policy is actually configured and
  the new output is correctly wired.
- The project's own CI (`.github/workflows/ci.yml`) now installs a checksum-pinned OPA v1.21.0 and
  runs `opa test core/policy/starter` as its own step, exactly the plan's "opa test runs the policy
  tests in CI" — not just something the Python test suite happens to also cover.
- A synthetic end-to-end run through `bulwark ci compare --policy`: a LOW-severity secret finding
  (which `--fail-on critical` alone would pass clean) correctly fails the check once a policy
  denying `category == "secrets"` is supplied, with the denial message appearing in the generated
  PR comment.
- **Not done**: the policy editor UI (Monaco editor, live evaluation against the last scan, "save
  disabled until opa test passes") — deliberately deferred, recorded in ADR-0023, not silently
  dropped. Also not done: Week 40's own license/SBOM data, without which the starter library's
  license-denylist rule is real, tested code with nothing yet to match against.
