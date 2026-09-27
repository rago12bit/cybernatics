# Week 30 verification: GitHub App integration (ADR-0017)

Run for real on 2026-09-27, against the same live Postgres, FastAPI and Celery worker used in
Weeks 27-29 (rebuilt with this week's code). **Honest headline first:** there is no real, registered
GitHub App yet — that's the user's own action, not something I can do unilaterally, the same way
pushing to `origin/main` has stayed theirs all project. Everything below states plainly which half
of "GitHub App integration" that blocks, and which half it doesn't.

## What was verified live, against real infrastructure

**RS256 JWT signing and verification**, with a real (test-generated) RSA keypair — not a mock of the
crypto, the actual `cryptography`/PyJWT machinery `core.github_app.app_jwt` uses.

**The full webhook receiver, against the real running API and Postgres**, including real Row-Level
Security:

1. A real, HMAC-signed `installation` (`created`) webhook, POSTed to the live `/integrations/github/
   webhook` endpoint, produced a real `Organization` and a real `GithubInstallation` row — confirmed
   by a direct `psql` join, not just the API's 200 response.
2. A real, HMAC-signed `pull_request` (`opened`) webhook, referencing **an actual public GitHub pull
   request** (`octocat/Hello-World#11297`, confirmed to exist and resolve via GitHub's own API and
   `git ls-remote` before the test), was accepted, resolved to that installation's org, and queued a
   real scan — end to end through the real worker:

```
scan id:  292c916d-...
org_id:   7740c3c3-...       (resolved from installation 777, not the bootstrap default)
status:   completed
ref:                refs/pull/11297/head
github_repo:         octocat/Hello-World
github_pr_number:    11297
github_installation_id: 777
```

The worker's `git fetch --depth=1 origin refs/pull/11297/head` succeeded against the real GitHub —
this is the actual PR's head commit (`6f86422f...`, matching `git ls-remote`'s answer against the
real repo), not the default branch, proving `core.gitfetch.clone_repo`'s new `ref` path works against
real GitHub, not just the fake-subprocess unit tests.

3. **The PR-comment step failed gracefully and was logged, without failing the scan**, exactly as
   designed: `BULWARK_GITHUB_APP_ID` was set to a placeholder but no private key was configured, so
   `core.pipeline._post_pr_comment` logged `"scan ... is tied to a GitHub PR but the App isn't
   configured"` and returned — the scan itself still shows `status: completed`. This is real evidence
   the best-effort design works, not just an assumption from reading the code.

Test artifacts (the `777` installation, its org, the scan and its asset) were deleted afterward; the
13 real pre-Week-27 scans are untouched (confirmed by row count before and after, as in every
previous week's verification).

## What was NOT verified live, and why

- **An installation token actually minted and accepted by GitHub.** This needs a real App ID and a
  real private key from a registered App — there is no App registered. `installation_token`'s HTTP
  exchange, its caching, and its error handling are covered by unit tests with a fake transport
  (`tests/unit/test_github_app.py`), not a live call to `api.github.com`.
- **A PR comment actually posted and visible on a real pull request.** Same reason — this needs a
  real installation token first. `upsert_comment` itself was already live-verified in an earlier
  week's GitHub Action work; what's new and unverified here is *reaching* that call with a real token.
- **A webhook actually delivered by GitHub** (as opposed to one I constructed and signed myself).
  Signature verification is proven correct (real HMAC, real rejection of a wrong secret); what's
  unverified is GitHub's own delivery infrastructure actually reaching this server, which needs a
  public URL and a registered webhook — again, registration.

Once a real App exists (App ID, private key, webhook secret, installed on a test org), closing these
three gaps is a short follow-up, not new engineering: point the three settings at the real values and
either open a real PR or use GitHub's own "redeliver" button on a past webhook.

## Automated tests

```
pytest -q --cov=core --cov=api   # 811 passed (33 new), 95.08% coverage
ruff check . && black --check .  # clean
mypy                              # clean (core/, api/)
```

New: `tests/unit/test_github_app.py` (JWT signing/verification, installation-token caching and error
handling with a fake transport, webhook signature verification, PR-event parsing, comment-body
escaping); `tests/unit/test_github_webhook.py` (the webhook endpoint's application-level behavior —
signature rejection, `ping`, idempotent `installation` created/deleted, `pull_request` scoping to the
right org, ignored actions — all on SQLite); extensions to `tests/unit/test_gitfetch.py` for the
ref-based clone path (ref-shape validation, the 4-step init/remote/fetch/checkout sequence with every
hardening flag, failure cleanup) using a purpose-built fake subprocess double.

## Two real bugs found along the way

1. **`org.id` read before it existed.** `get_or_create_installation` built the new `Organization`,
   then immediately read `org.id` to set on the `GithubInstallation` row — but a SQLAlchemy column
   default (`core.persistence.models._uuid`) is only assigned during flush, not at object
   construction. The first attempt inserted `org_id = NULL`, failing the `NOT NULL` constraint. Fixed
   with an explicit `s.flush()` between creating the org and reading its id — the same category of
   bug Week 28's backfill script hit with `FindingRow.issue_id`, for the same underlying reason.
2. **The RLS chicken-and-egg** described in ADR-0017: an early draft would have put a Row-Level
   Security policy on `github_installations` itself, which would have made "look up which org this
   installation belongs to" require already knowing the org to look it up under. Caught by reasoning
   through the webhook handler's sequence before writing the migration, not by a test failure —
   `github_installations` ended up with no RLS policy at all, by design (see the ADR).

## What's deferred, on purpose

- No org-management API, no web UI for connected repositories or installations.
- No base-vs-head diff for the App path (a plain per-PR summary instead) — see ADR-0017's
  alternatives-considered section.
- No Check Runs API — a PR comment, reusing the existing GitHub Action's poster.
- No cross-process installation-token cache (each API/worker process mints its own on first use).
