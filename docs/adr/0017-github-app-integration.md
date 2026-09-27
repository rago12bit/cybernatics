# ADR-0017: GitHub App integration for automatic PR scanning

Status: Implemented (2026-09-27, Week 30), except live verification against a real, registered
GitHub App — that half is gated on registering one, which is the user's action, not mine. See
docs/v2-week30-verification.md for exactly what was and wasn't proven live.

## Context

Bulwark already has a GitHub *Action* (`core/ci/*`, `docs/github-action.md`): a repo owner adds a
workflow file, CI runs `bulwark scan`, and `core/ci/github.py` posts a PR comment using the token
Actions hands that one workflow run. That requires the repo owner to write and maintain a workflow
file, and only runs when their CI actually executes it.

A GitHub *App* is a different, complementary mechanism: install it once on an org or repo, and
GitHub pushes webhook events (a PR opened, synchronized, ...) to a server Bulwark controls, with no
workflow file for the user to write at all. This is what the plan's Week 30 asks for.

## Decision

### Two-step GitHub auth, not the Action's borrowed token

The App authenticates itself to GitHub with a JWT it signs (RS256, its own private key), then
exchanges that for a short-lived (~1h) *installation* token scoped to exactly the repos/permissions
that installation granted (`core/github_app.py`: `app_jwt`, `installation_token`, cached in-process
per installation until near expiry). This is GitHub's own documented flow for an App acting on its
own behalf, as opposed to the Action's model of "the CI job already has a token, just use it."

### An installation IS a tenant, for now

There's no org-management API yet (ADR-0013 already deferred that). Rather than block the App
integration on building one, installing the App on an account creates that account's `Organization`
the first time a webhook mentions it (`GithubInstallation` maps `installation_id -> org_id`,
`core/persistence/repo.py`'s `get_or_create_installation`). Real membership/sign-in (§19.2) can
attach to this mapping later without changing it.

**`github_installations` deliberately carries no Row-Level Security policy**, unlike every table
that holds actual tenant content. Resolving *which* org a webhook belongs to has to happen before
any org-scoped query can run at all — RLS-gating the very table that answers "which org is this"
would be a chicken-and-egg deadlock. It's a directory table, like `organizations` itself: knowing
"installation X belongs to org Y" isn't a cross-tenant data leak the way a scan's findings would be.
Once resolved, `core.tenancy.set_session_org` scopes the rest of that session's writes correctly —
this is exactly the kind of subtle RLS interaction ADR-0013 didn't anticipate, caught here by
reasoning through the sequence before writing the webhook handler, not by a test failure.

### Scanning a PR's actual commits, not the default branch

`core/gitfetch.clone_repo` gained a `ref` parameter, but restricted to one specific, tightly-matched
shape: `refs/pull/<n>/head` — GitHub's own stable name for a PR's current head commit. A shallow
`git clone --branch` can't target it directly (that only resolves `refs/heads`/`refs/tags`), so the
ref path instead does `init` -> `remote add` -> a scoped `fetch --depth=1` -> `checkout FETCH_HEAD`,
keeping every one of the existing SSRF/hardening flags (IP pinning, no redirects, no credential
helper, ...) on every one of those four git invocations, not just the first.

### PR-triggered scans don't feed the asset's Issue lifecycle

A `pull_request` scan targets the *same* `Asset` a push-triggered scan of the repo would (same
`asset_key`), but `core/pipeline.py` only calls `sync_issues_for_scan` (ADR-0012) when `scan.ref is
None`. A PR previews code that might never merge; treating its findings as the asset's real current
state would corrupt fixed/reintroduced detection the moment the PR closes without merging — a
finding only present on the PR branch would show as "new," then falsely "fixed" the next time the
real branch is scanned and it's correctly absent. This is a real risk that isn't obvious until you
trace through what `sync_issues_for_scan` assumes about "absence means fixed."

### Result delivery reuses the Action's comment poster, not a second one

`core/ci/github.py`'s `upsert_comment` already exists, is tested, and only needs a token — it
doesn't care whether that token came from Actions' `GITHUB_TOKEN` or an App's installation token. The
App path builds its own comment body (`core/github_app.pr_comment_body`, a plain per-PR summary, not
a diff — see "what was actually built" below for why) and calls the same `upsert_comment`. No Check
Runs API this week; a PR comment is a smaller, already-built surface that does the job.

## Alternatives considered

- **Diff the PR against the base branch**, like the Action's `core/ci/compare.py` does. Rejected for
  this week: that needs a scan of the base branch to diff against, and running two scans per PR
  (base + head) doubles cost for a feature that's supposed to make scanning *more* automatic, not
  more expensive. `pr_comment_body` shows a plain summary of the PR's own findings instead. Real
  base-vs-head diffing for the App path is a reasonable future upgrade once there's a cheaper way to
  get a base-branch baseline (e.g., reusing the asset's last completed non-PR scan).
- **Check Runs API** instead of a comment. Rejected for this week: a genuinely nicer UI (shows in the
  PR's Checks tab, can annotate specific lines), but it's a new results-rendering surface to build and
  test, and this week's job is the App's plumbing (auth, webhooks, tenant resolution), not a new UI.
- **Bypass privilege for the worker to look up a scan's org_id itself**, instead of threading it
  through the enqueue call (as Week 29 already does for exactly this reason). Not reconsidered here;
  Week 29's `scoped_sessions` mechanism is reused as-is for PR-triggered scans, since the API always
  knows the org before dispatching regardless of *why* it's creating the scan.

## What was actually built, and where it differs from the design above

- Nothing significant differs from the design — this ADR was written after implementation (like
  ADR-0012/0013), so "design" and "built" line up more closely than usual. The real surprises were
  bugs, not design gaps; see the verification doc.
- One explicit limitation, stated plainly rather than glossed over: **live verification against a
  real, registered GitHub App was not possible this week.** Registering an App (getting an App ID,
  generating its private key, setting a webhook URL) is the user's action on their own GitHub
  account, the same way pushing to `origin/main` has stayed theirs through this whole project. What
  *was* verified live: real RS256 JWT signing/verification with a real (test) RSA keypair, the full
  webhook receiver against the real running API and Postgres (including real Row-Level Security),
  and — using a real, existing public GitHub pull request — the `ref`-based git clone path against
  the actual GitHub API, not a mock. What remains unverified: an installation token actually accepted
  by GitHub, and a PR comment actually posted and visible on a real pull request.

## Consequences

- The web app has no UI for this yet (no "connected repositories" page, no installation management)
  — API/webhook only, consistent with how this project's API has repeatedly shipped ahead of its UI.
- A caller who already knows the shared v1.0 bearer token cannot forge a webhook (a different trust
  mechanism, HMAC-verified against a secret only GitHub and this server know) — but per-installation
  authorization of *which* repos a given webhook may act on is entirely GitHub's own responsibility
  (the installation token itself is scoped by GitHub to only what that installation was granted).
- Uninstalling the App removes the `GithubInstallation` mapping but never the `Organization` or its
  scan/issue history (ADR-0013's durability guarantee, unchanged). Reinstalling gets a new
  installation id and therefore a new org — there is no way to prove it's "the same" account asking,
  so this doesn't attempt to guess.
- `core/config.py`'s three new settings are all optional and all-empty by default: an existing
  self-hosted deployment that never sets them is completely unaffected, and the webhook endpoint
  simply 404s.
