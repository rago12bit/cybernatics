# Week 51 verification -- Ecosystem: Plugin SDK, Integrations, pre-commit hook, documentation site (plan §23)

Honest record of what was built, run, and measured. See [ADR-0037](adr/0037-ecosystem.md) for the
design decisions, including every disclosed simplification.

## What was built

- **Plugin SDK** (`core/plugins/`): entry-point discovery (`bulwark.scanner_adapters`), a shared
  conformance kit built-ins now use too, keyless Sigstore verification (`core/plugins/signing.py`),
  a per-org allowlist (`PluginAllowlistRow`, migration `0024`), and a real, installable example
  package (`examples/bulwark-plugin-demo`).
- **Integrations** (`core/integrations/`): Slack/Discord notifications, HMAC-signed generic outbound
  webhooks, GitHub Issues and Jira two-way sync (`IntegrationSettingsRow`/`ExternalIssueLinkRow`,
  migration `0025`), a shared SSRF guard extracted into `core/netsafety.py`, and two inbound webhook
  receivers.
- **Pre-commit hook** (`core/precommit/`): native (no Docker) secrets regex rules and `ast`-based
  Python SAST checks, `bulwark precommit run/install/uninstall`, and a `.pre-commit-hooks.yaml` for
  the `pre-commit` framework.
- **Documentation site**: `mkdocs.yml` + `docs/index.md`, `docs/quickstart.md`,
  `docs/concepts/architecture.md`, `docs/plugins.md`, reusing `docs/policy.md`/`risk-score.md`/
  `taxonomy.md`/`reachability.md`/`api.md` as-is.
- Along the way: fixed a pre-existing gap where `tests/integration/*_rls_docker.py` wasn't fully
  wired into CI (two of four RLS test files were silently never run); fixed `docs/api.md`/
  `docs/openapi.json` having been stale for several weeks with no test to catch it.

## Validated against real, live things -- not mocks

- **A real podinfo image's real Sigstore signature.** `verify_plugin_image` against
  `ghcr.io/stefanprodan/podinfo:6.4.0` (a real, publicly signed image) succeeds; against the same
  image with the wrong declared identity, or against an unsigned image, it correctly raises
  `PluginSignatureError` -- all three paths exercised live, not mocked
  (`tests/integration/test_plugin_signing_live.py`).
- **A real third-party package, installed exactly as `pip install` would.**
  `examples/bulwark-plugin-demo` is installed in CI with `--no-deps` the same way a plugin author's
  own install would be; `discover_plugins()` finds it via a genuine entry point with no change to
  Bulwark's own source, and its adapter runs through a real `docker run`
  (`tests/integration/test_plugin_sandbox_execution_live.py`), including a deliberate signature
  mismatch (its declared identity doesn't match its own unsigned image) correctly failing.
- **Real DNS resolution for the integrations SSRF guard.** `validate_webhook_url` against
  `hooks.slack.com` and `discord.com` resolves and accepts their real public addresses; against
  `169.254.169.254` (the AWS/GCP metadata address) it correctly rejects
  (`tests/integration/test_integrations_webhooks_live.py`). Real HMAC-signed delivery proven over a
  real local `HTTPServer` socket, not a mocked transport.
- **A real, unmocked, HMAC-verified GitHub webhook round trip.** A crafted `issues` webhook payload,
  signed with real `hmac.new(secret, body, sha256)` the way GitHub itself would sign it, correctly
  closes a linked issue's sync status through the actual running FastAPI app; a tampered signature is
  correctly rejected with 401 (`tests/unit/test_integrations_api.py`).
- **Real Postgres RLS**, connected as the real `bulwark_worker` role: one org's integration
  credentials and external issue links are invisible to another org's session, and a brand-new
  connection with no `app.current_org` ever set sees zero rows from either table
  (`tests/integration/test_integrations_rls_docker.py`).
- **Real temporary git repositories and real `git commit`s, start to finish.** `bulwark precommit
  install` writes an actual `.git/hooks/pre-commit`; a real `git commit` with a staged fake AWS key
  genuinely fails (non-zero exit from the real hook, not a simulated check), fixing the file and
  restaging genuinely lets the commit through, and `git commit --no-verify` genuinely bypasses it
  (`tests/unit/test_precommit_cli.py`).
- **A real performance measurement that found and drove a real fix.** This project's own 238-file
  `core/` tree, copied into a fresh git repository and staged in full: the first working version took
  1.93s wall-clock (one `git show` subprocess per file), at the edge of the plan's 2-second budget.
  Switching to one batched `git cat-file --batch` call dropped the same real commit to 0.45s.
  `tests/integration/test_precommit_performance_live.py` pins both the pure scan time (<2s) and a
  looser wall-clock regression budget (<4s) against this same real file set.
- **The documentation site, actually built and actually opened in a browser.**
  `pip install -e ".[docs]"` then `mkdocs build` completes in under a second with zero warnings on
  any new or reused page (the handful of warnings that do print are pre-existing broken relative
  links in old, non-nav docs -- confirmed by name, not assumed harmless). Opened the built site in a
  real browser: the homepage's card grid and six-step pipeline list, syntax-highlighted code blocks
  and a working table of contents on the plugin guide, the full real generated API reference
  (including `/plugins` and `/settings/integrations`), the real policy cookbook, the architecture
  diagram rendering correctly from a nested `docs/concepts/` page via its relative `../` path, and
  MkDocs Material's built-in search returning real, correctly-ranked, deep-linked results for the
  query "allowlist" (13 matching documents, correct anchors).

## Verified

- 1779 unit tests passed, 1 skipped (up from Week 50's 1591: +38 Plugin SDK, +78 Integrations, +70
  pre-commit hook, +2 the API-docs freshness fix, +1 net from a pre-existing test fix along the way).
  `black --check .` and `ruff check .` clean repo-wide; `mypy` clean across 216 source files (up from
  197 at the end of Week 50).
- 9 new live integration tests this week (plugin signing x3, plugin sandbox execution x2,
  integrations webhooks x4), all passing against real Docker/network/DNS; 3 new RLS integration tests
  against real Postgres (`test_integrations_rls_docker.py`).
- The CI gap this week found: `tenancy-rls`'s job only ever ran two of the four
  `tests/integration/*_rls_docker.py` files; fixed to glob all of them.
- `scripts/gen-licenses.py --check` clean, including the new `docs` optional-dependency group
  (correctly excluded from `SHIPPED_EXTRAS`, the same as the pre-existing `dev` extra -- a
  documentation build tool, not something the application image ships).
- Coverage: 90.83% (`pytest tests/unit`), above the project's enforced 80% gate.

## What this does NOT prove (read before relying on it)

- **GitHub Issue and Jira ticket creation are mocked-transport tested, not live.** Nothing in this
  week's work has created a real issue or ticket on a real account -- that needs the account owner's
  own token and would be a real, visible side effect, which this session does not take unprompted.
- **A plugin's severity is `INFO` until someone edits `core/scoring/severity.py` by hand.** The
  allowlist controls whether a plugin can run at all, not what its findings are ranked as.
- **The pre-commit hook's SAST coverage is Python-only**, and its 15 secret patterns and 7 AST checks
  are a deliberately narrow, high-confidence subset chosen to be safe to block a commit on -- not a
  replacement for `bulwark scan --tools gitleaks,bandit` in CI, which still runs the real tools.
- **The documentation site isn't deployed anywhere.** `mkdocs build` is verified and wired into CI;
  publishing it to GitHub Pages needs the repository owner to enable Pages in the repository's own
  settings, which this work does not do on its own.
- **Everything from prior weeks' own disclosed limits is unchanged**: no mTLS to Postgres in the
  Helm chart, OpenBao dev mode only, the nftables egress backstop and gVisor/Firecracker sandboxing
  exactly as previously documented. Nothing in Week 51's work touches any of them.
