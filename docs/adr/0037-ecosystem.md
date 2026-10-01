# ADR-0037: Ecosystem -- Plugin SDK, Integrations, pre-commit hook, documentation site

Status: Implemented (2026-10-02), Week 51 (plan §23).

## Context

Week 51 is the plan's own "Ecosystem" week: four tasks that each extend *where* Bulwark's findings
can come from or go to, rather than changing scanning or scoring itself -- a third-party scanner
(Plugin SDK), an organization's existing tools (Integrations), the moment before a commit even
happens (pre-commit hook), and a real documentation site instead of scattered markdown files. The
plan's own Cut Order names the Plugin SDK as the first of the four to drop if time runs short; all
four were built.

## Decisions

### Plugin SDK: entry points, not a registry Bulwark controls

A plugin is an ordinary pip-installable package declaring a `bulwark.scanner_adapters` entry point
(`importlib.metadata.entry_points()` -- the first use of entry-point discovery anywhere in this
codebase; `[project.scripts]` was the only prior packaging mechanism). It runs through the identical
sandboxed `docker run` a built-in scanner does, proves itself with the same four golden-file
conformance checks a built-in's own test suite runs (literally the same functions, extracted into
`core/plugins/conformance.py`, not a parallel reimplementation), and is trusted via a real keyless
Sigstore identity check (`cosign verify --certificate-identity=... --certificate-oidc-issuer=...`,
needing network -- the one place in the codebase a cosign container runs with it, kept out of the
otherwise fully offline `core/attest/cosign.py`). That signature is re-verified on *every* resolution,
not cached from whenever an organization allowlisted the plugin: the allowlist is trust in a
publisher's identity, not trust in a one-time image hash.

### Integrations: shared SSRF guard, asymmetric two-way sync

Webhook destinations (Slack, Discord, generic outbound) pass through the exact DNS-resolve-and-reject
logic `core.gitfetch.validate_git_url` already uses for cloning -- extracted into `core/netsafety.py`
so the two call sites provably share one security-critical primitive rather than two similar-looking
ones. GitHub Issues and Jira sync is deliberately asymmetric: Bulwark's own scan-derived state
(`IssueRow.state`) is the only thing that can mark an issue fixed; closing or reopening the external
ticket by hand only updates sync metadata (`ExternalIssueLinkRow.external_status`), never the
authoritative state. The alternative -- trusting the external system's status both ways -- would let
someone hide a still-present vulnerability by closing the wrong ticket.

### Pre-commit hook: a narrower, native complement, not a faster version of the same tools

Gitleaks and Bandit both run in Docker (300-600s timeouts) -- nowhere near a commit-time budget.
`core/precommit/` is pure Python with no subprocess for the scan itself: ~15 high-confidence,
vendor-prefixed secret patterns by regex, and 7 high-confidence checks over the stdlib `ast` tree for
Python files, explicitly scoped narrower than the full scanners they complement rather than
attempting to approximate them faster. The one real performance bug this surfaced -- reading staged
files via one `git show` subprocess per file -- was found by actually timing a 238-file commit (1.93s,
at the edge of the budget) and fixed by batching every blob into one `git cat-file --batch` call
(0.45s on the same commit), not by assumption.

### Documentation site: curate the existing `docs/` folder, don't fork a new one

`mkdocs.yml` points `docs_dir` at the repository's existing `docs/` folder and curates a `nav` across
it, rather than creating a separate site-source tree that content would need to be copied into (and
drift from). The already-thorough `docs/policy.md`, `docs/risk-score.md`, `docs/taxonomy.md` and
`docs/reachability.md` are reused verbatim; the "API reference generated from OpenAPI" requirement is
`docs/api.md`, which already was exactly that (`scripts/gen-api-docs.py`, now freshness-tested -- see
below) -- mapped straight into the nav instead of standing up a second OpenAPI renderer alongside it.
The 60-plus other files already under `docs/` (ADRs, weekly verification records, UX research) still
build and are reachable by direct URL; they're simply not in the nav, because they're engineering
history, not user-facing documentation, and enumerating them in an `nav:` block that needs updating
every week would be its own maintenance burden for no reader benefit.

### A gap found and closed along the way: generated docs had no freshness check

Regenerating `docs/api.md`/`docs/openapi.json` while building the docs site (sanity: do they still
match the live app?) surfaced that both had been stale for several weeks -- missing the Week 48-50
asset/threat-model/copilot/cost endpoints *and* this week's own `/plugins` and `/settings/
integrations`. Nothing had been checking them, unlike `docs/severity-matrix.md`, which
`tests/unit/test_correlation.py` already does. Fixed in two steps: regenerate (commit `2716b0f`),
then add the missing test (commit `10e0e9b`) by extracting `openapi_spec()`/`api_doc()` out of
`scripts/gen-api-docs.py`'s `main()` so a test can re-derive each file's expected content from the
running app and compare, rather than re-implementing the derivation a second time and risking the two
drifting apart from each other.

## What is NOT done

- **A plugin with no row in `core/scoring/severity.py`'s matrix has every finding normalize to
  `INFO`** regardless of the tool's own severity label -- registering a plugin's severities still
  means a change to Bulwark's own source, not something a plugin declares for itself.
- **No per-org private plugin registry.** A plugin is whatever's installed in the worker's Python
  environment; the allowlist is the only "org A can, org B can't" mechanism, not package visibility.
- **GitHub Issue and Jira ticket creation are unit-tested against a mocked transport, not live.**
  Creating a real issue or ticket needs the account owner's own token and would create a real,
  visible side effect on their account -- outside what this session verifies unprompted. The inbound
  half (a signed webhook closing a linked issue) *is* live-verified, since it needs no third-party
  credentials, only a crafted, correctly-HMAC-signed request against this project's own API.
- **Jira sync never drives a workflow transition** (per-project-configurable, no universal id to
  assume) -- it closes via a comment, not a real status change.
- **The pre-commit hook's SAST checks are Python-only.** Secrets patterns apply to any file; the
  `ast`-based checks do not generalize to JavaScript/Go/Terraform the way Semgrep/gosec/Checkov do in
  `bulwark scan` itself.
- **No GitHub Pages deployment for the documentation site.** `mkdocs build` runs in CI; publishing it
  needs Pages enabled in the repository's own settings, a repository-owner action this ADR doesn't
  take on its own.
