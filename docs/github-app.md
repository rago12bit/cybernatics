# GitHub App integration

Installs once on an org or repository and scans every pull request automatically — no workflow file
to write or maintain (that's the [GitHub Action](github-action.md), a separate, complementary
integration: use the Action if you already have CI and want Bulwark as a step in it; use the App if
you want PRs scanned without touching your CI config at all).

**Status: implemented, not yet live-verified against a real App** (ADR-0017,
[docs/v2-week30-verification.md](v2-week30-verification.md)) — the steps below are what's needed to
close that gap; nothing here has been exercised against a real GitHub App yet.

## Register the App

1. GitHub → Settings → Developer settings → **GitHub Apps** → New GitHub App.
2. **Webhook URL**: `https://<your-bulwark-host>/integrations/github/webhook` (needs to be reachable
   from GitHub — a public host, or a tunnel such as `ngrok`/`smee.io` for local testing).
3. **Webhook secret**: generate one (`openssl rand -hex 24`) and set it both here and as
   `BULWARK_GITHUB_WEBHOOK_SECRET` below — this is what proves a webhook actually came from GitHub.
4. **Permissions**: Repository → Contents: Read-only, Pull requests: Read & write (for the result
   comment), Metadata: Read-only (mandatory).
5. **Subscribe to events**: Pull request, Installation, and Issue comment (for `/fix`,
   [docs/fix-on-pull-requests.md](fix-on-pull-requests.md)).
6. Create the App, then generate a **private key** (downloads a `.pem` file) and note the **App ID**
   shown on its settings page.
7. Install the App on the account/repos you want scanned.

## Configure Bulwark

Three environment variables, all optional (unset = the integration is simply off and the webhook
endpoint 404s):

```bash
BULWARK_GITHUB_APP_ID=123456
# The PEM's newlines, escaped as literal \n (most secret stores flatten multi-line values this way).
BULWARK_GITHUB_APP_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n"
BULWARK_GITHUB_WEBHOOK_SECRET=<the secret from step 3>
```

`docker-compose.yml` already wires these through to both `api` (receives webhooks) and `worker`
(posts the result comment once a scan finishes) — set them in `.env` and `docker compose up -d api
worker`.

## What happens

Opening or updating a pull request on an installed repo: Bulwark clones exactly that PR's head
commit (`refs/pull/<n>/head`, not the default branch), scans it with the default tool set, and posts
a summary comment on the PR once it finishes — reusing the same comment format the GitHub Action
uses. The first webhook for a new installation creates a Bulwark organization for it (there's no
separate org management yet, ADR-0013); every PR scanned through that installation shares it.

## Known limitations (Week 30)

- No UI for connected repositories or installations — API/webhook only.
- No diff against the base branch (the GitHub Action's `compare` step does that separately); the PR
  comment is a plain summary of that PR's own findings.
- No Check Runs annotation — a PR comment only.
- PR-triggered scans don't affect the "new/fixed/reintroduced" issue tracking (ADR-0012) shown for
  the repository's regular scans — a PR previews code that might never merge, so its findings aren't
  folded into that history.
