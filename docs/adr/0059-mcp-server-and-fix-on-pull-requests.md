# ADR-0059: An MCP server that acts as the person, labels untrusted text, and is read-only by default; `/fix` on pull requests, previewed, capped and never for forks

Status: Accepted (2026-10-08), Week 76 (plan §50, threat T29). Builds on
[ADR-0027](0027-verified-fix-agent.md) (the verified-fix agent), [ADR-0017](0017-github-app-integration.md)
(the GitHub App) and [ADR-0058](0058-identity-sso-scim-roles.md) (people and scoped roles).

## Context

Plan §50 asks for two ways for agents to use Bulwark:

- an MCP server with `list_issues`, `get_issue` (with the taint path and evidence),
  `get_verified_fix`, `search_components` and `run_scan`: "read-only by default, token-scoped and
  tenant-scoped under the same RLS", with snippets "wrapped and labelled as untrusted data" (T29);
- `/fix`, a pull request comment that runs the verified-fix agent on the issues the pull request
  introduced, for organization members with Member or higher, "never on pull requests from forks
  (the pull_request_target lesson)", with the estimated cost shown before anything is spent.

The v2 rules still hold: the model never originates an Issue outside the Hypotheses lane, never
changes a status without a person, and never runs without a budget.

## Decision

**The MCP server is a client of the API, not a second door to the database.** `bulwark mcp` (stdio,
the official Python SDK) calls the API with the person's personal token, read from
`BULWARK_MCP_TOKEN` and never from the command line. Every rule the API enforces -- scopes, the role on
each project, the guest database role, RLS -- applies unchanged, and nothing about tenancy is
reimplemented. The deployment's shared token is refused: an agent must be someone. Ids are checked
before they become a path, redirects are not followed, and a non-local API must be https, so the
token goes nowhere but the configured address.

**Read-only by default.** Four tools read. `run_scan` is offered only when the server is started
with `--allow-scans` *and* the token may write scans. No tool triages, accepts, closes or approves.

**Untrusted text is labelled, default-deny.** Every value in a result is wrapped as
`{"untrusted_text": ...}` unless its key is one Bulwark sets (ids, severities, dates, counts) *and*
its value looks like one; a key that is not an identifier (a file path used as a key) becomes a
`{key, value}` pair with the key wrapped. Inside a wrapper, characters that hide or reorder text are
shown as `<U+XXXX>`, terminal escapes as `<ESC ...>`, and long text is cut with a note. Each result
says in one sentence what the wrapper means. Tool descriptions describe; they never address the
agent. This informs the agent; it cannot stop one, which docs/mcp.md says plainly.

**`/fix` is a two-step conversation on the pull request.** `/fix` (the whole first line of a new
comment) gets a preview: up to five findings this pull request introduced (new in the pull request
scan, code, secrets or configuration -- a dependency bump is not a patch), the token cap
(`BULWARK_FIX_TOKENS_PER_FINDING` per finding), its price when one is configured, and the budget left.
Nothing runs. `/fix confirm <code>` starts one verified-fix run per finding; `/fix cancel <code>`
withdraws it. A code works once and for 24 hours, and a new preview replaces the old one.

**Who may.** GitHub says who wrote the comment and how they relate to the repository
(`author_association`: owner, member or collaborator, not contributor). Bulwark says what they may
do: an admin links a GitHub login to a person (only an admin, since a person naming their own login
could name someone else's; unique per organization without case), and that person's role on the
project must be Member or higher. Both are checked on the preview and again on the confirm, with the
pull request itself (open, not from a fork, head still the previewed commit), the budget, and the
concurrency limit. A fork is refused outright: the agent runs the pull request's code (scanners, and
tests when enabled), which must not happen with the base repository's credentials. The organization
comes from the App installation; a comment from an unknown installation never creates one (a
`pull_request` event still does, as in ADR-0017).

**A pull request run needs no approval and writes nothing to the repository.** The workflow's
pull request mode skips the approval wait and the "open a pull request" step, and posts the verified
patch -- or why there is none -- as a comment. People apply it. The run has no Issue (a pull request
scan mints none), so `verified_fix_runs.issue_id` becomes optional and a run names its request and
finding instead; a CHECK keeps one of the two set, and the guest policy reaches such a run through its
request.

**Every model token is budgeted.** Found while building this: the fix agent counted its tokens but
never charged them to the organization's monthly budget. Each attempt now checks the budget first
and charges what it spent, and the run stops at its cap, checked before each model call (the last
call can pass the cap by its own size, never more). The worker's activities now act for the run's
organization; under forced RLS they could not see their own run before, so on Postgres every write
was silently dropped.

## Consequences

- An agent sees exactly what its person sees, and gets labelled text it can choose to treat as data.
- `/fix` costs a person two comments and gives them the price before any spend.
- New schema (migration 0050): `users.github_login`, `scans.github_head_sha`, `pr_fix_requests`
  (forced RLS, guest project policy), and the `verified_fix_runs` changes above.
- The GitHub App also subscribes to the "Issue comment" event; its existing pull requests (read and
  write) permission covers reading the pull request and commenting -- docs/fix-on-pull-requests.md.
- Not proven: a real GitHub App delivering a comment, and a real model (none is configured here). The
  live check used the real worker, Temporal, Postgres and Bandit, with the model scripted and
  GitHub's API recorded (docs/v2-week76-verification.md).
