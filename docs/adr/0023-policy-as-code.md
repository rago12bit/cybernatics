# ADR-0023: Policy-as-code — embedded OPA, a starter Rego library, and policy-driven PR gates

Status: Implemented (2026-09-29, Week 39), core engine and CI/Action integration done; the policy
editor UI (Monaco, live evaluation, save) is explicitly deferred — see "Deferred" below.

## Context

Every gate this project has had until now is a severity threshold (`fail_on`): fail the check if
any new finding is at or above some severity. That can't express "no secrets, ever, regardless of
severity" or "an accepted risk expires after 90 days" or "no denylisted license" — real
organizational rules that aren't about severity at all. The plan's answer (§20.4) is to embed Open
Policy Agent and let an organization write these as Rego, evaluated against the scan's own Issue
set, with `deny` messages driving the pull-request check.

## Decision

`core/policy/`, four pieces:

- **`opa.py`**: a thin subprocess wrapper around the real `opa` binary — `check_syntax`, `eval_deny`,
  `run_tests`.
- **`input.py`**: builds the OPA input document (`{"new_issues": [...]}`, the plan's own field name)
  from a scan's existing `Finding` dicts — no new data collection, only reshaping what already
  exists.
- **`starter/gate.rego`** + `gate_test.rego`: the plan's own five example policies, each its own
  `deny contains msg if {...}` block in one `gate.pull_request` package (Rego unions same-named
  rules automatically), with a full `opa test` suite.
- **`gate.py`**: `evaluate_gate()`, the one function both `bulwark ci compare` and (eventually) a
  policy editor call.

### OPA runs directly, not through the sandboxed scanner runner

Every other external tool in this project (`core.runner`, gVisor-sandboxed) exists to run against
*untrusted repository content*. OPA evaluates *this platform's own already-computed output* — a
scan's findings — against a policy that is either the bundled starter library or something an org
admin wrote. There is nothing here for a sandbox to protect against that `core.risk.score` (which
also runs directly, unsandboxed, over the same kind of data) doesn't already face. Running `opa`
as a plain subprocess, not a Docker-sandboxed adapter, is the same trust boundary this project
already draws elsewhere, applied consistently.

### The input schema only sends fields that already have a real source

`issue_document()` (`core/policy/input.py`) maps directly from an existing `Finding`'s own fields —
`severity`, `category`, `cwe`, `in_cisa_kev`, `reachable` (Week 38's own taint work), `entrypoint`
(read from a taint path's own entrypoint hop, when one exists). Two fields the starter library's own
example rules reference have no real source *yet* anywhere in this codebase, and are handled
honestly rather than faked:

- `license` — needs Week 40's SBOM/license work (plan §20.5). Until then, no `Finding`/`Package`
  carries a license at all, so the field is simply absent from the input document, never sent as
  `null` or `"unknown"`. The starter library's license-denylist rule is real, tested Rego — it is
  just dead code in practice today, the same way the UI taint stepper was real code fed no real
  data for several weeks before Week 37/38 landed.
- `triage_expires_at` — lives on `IssueRow` (a database row keyed by asset), not on the standalone
  `Finding` JSON a `bulwark scan --format json` file contains. `build_input()` accepts an optional
  `issues_by_fingerprint` map so the *hosted* pipeline (which has database access) can supply it;
  the standalone CLI/Action gate (which only ever sees two JSON files, no database) genuinely
  cannot, and does not pretend to.

### `bulwark ci compare --policy` folds into the existing exit-code contract, not a new one

`ci_compare` already had a well-defined contract (exit 0/1/2, `--fail-on`, a markdown comment, a
`$GITHUB_OUTPUT` block) that `action.yml`'s "Enforce the threshold" step and every downstream
consumer already understands. Adding `--policy` composes into that same contract rather than
inventing a parallel one: `failed = bool(severity_breaches) or bool(policy_denials)`, one exit code,
one markdown comment with a new "Policy violations" section only when there are any, one new
`policy-violations` GitHub Actions output (only emitted when `--policy` was actually passed — a
scan running without a configured policy gets no new noise in its output). A syntactically invalid
policy exits 2 (the same "unusable input" code `load_scan` already uses for a corrupt scan file),
not a silent pass.

### `action.yml`'s new `policy-file` input only pays for OPA when it's used

The OPA binary is only downloaded when `policy-file` is non-empty (`if: ${{ inputs.policy-file !=
'' }}`) — a repository that hasn't configured a policy pays nothing extra. The project's own CI
(`.github/workflows/ci.yml`) always installs a checksum-pinned OPA and runs `opa test
core/policy/starter`, exactly the plan's own "opa test runs the policy tests in CI"; the reusable
Action's own install is unpinned (no single fixed architecture to pin a checksum against, unlike
the project's own `ubuntu-latest` CI runner), a deliberate, smaller trade-off than the project's
own pipeline makes for itself.

## Deferred: the policy editor UI

Plan §28.6: "Monaco editor for Rego on the left, live evaluation against the last scan on the
right... Save is disabled until opa test passes." Not built this session. This needs real,
separable design work of its own — an org-scoped policy storage table and migration, two new API
endpoints (evaluate a draft policy against the latest scan; save one, gated on `check_syntax`
passing), and a new frontend page with a Monaco integration — comparable in size to everything
above it in this ADR, and better scoped on its own than appended to an already-large week. Today,
an organization can use policy-as-code in full by committing a `.rego` file to their repository and
pointing the Action's `policy-file` input at it — no UI is required for the mechanism itself to
work end to end, matching how OPA and most policy engines are actually used in practice.

## Consequences

- A finding's severity alone no longer decides everything: a LOW-severity secret now fails a
  configured gate the exact same way a leaked credential should, regardless of how any individual
  scanner happened to rate it.
- The starter library's license-denylist and 90-day-risk-acceptance rules are real, tested, and
  will start actually firing the moment their data sources land (Week 40's SBOM work; already-live
  for triage data in the hosted pipeline) — no code change needed when that happens, only real data
  flowing into fields that were always there.
- The next real gap is the policy editor UI itself, and, separately, Week 40's own license data —
  neither is this week's problem.
