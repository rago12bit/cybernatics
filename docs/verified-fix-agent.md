# Verified-fix agent

Proposes a patch for one Issue, verifies it against the real thing (reruns the rule that flagged it,
reruns every scanner on the changed file, optionally runs the project's own tests), and only then
asks a human to approve or reject opening a pull request. **Never auto-merged.** Design reasoning in
[ADR-0027](adr/0027-verified-fix-agent.md); the honest verification record (what was, and wasn't,
validated live) is in [v2-week42-verification.md](v2-week42-verification.md).

## The loop

```
select an Issue
    │
    ▼
gather context: taint path, enclosing function, callers (fresh per attempt)
    │
    ▼
propose a patch — an LLM with allowlisted tools: read_file, search_code, get_call_path
    │                                                        ◄── feedback on what failed
    ▼                                                             │
apply the patch to a real checkout                                │
    │                                                             │
    ▼                                                             │
rerun the originating rule ──── still flagged? ──── yes ──────────┤
    │ no                                                          │
    ▼                                                             │
rerun every scanner on the changed file ──── new issues? ── yes ──┤
    │ no                                                          │
    ▼                                                             │
run the project's own tests (opt-in) ──── failures? ──── yes ─────┘
    │ pass                                    (at most 3 attempts, each with its own timeout)
    ▼
a human reviews the patch and the verification record
    │
    ├── Reject ──────────────────────────────────► done, no pull request
    └── Open pull request ──► a real PR, via the GitHub App
```

Implemented as a Temporal workflow (`core/fixagent/workflow.py`) — the first one in this codebase;
everything else uses Celery. It survives a worker restart (validated live: killed the worker
mid-run, a fresh worker resumed it correctly) and waits for the human decision as a signal, with no
timeout counted against it while it waits (see [Limits](#limits)).

## Turning it on

Hosted-only (tool-calling needs a provider's native tool-use protocol; only Anthropic is wired up —
see ADR-0027):

```bash
pip install 'bulwark-scan[fixagent]'         # temporalio + anthropic
export BULWARK_LLM_ENABLED=1
export BULWARK_LLM_API_KEY=...
export BULWARK_GITHUB_APP_ID=...             # to open real pull requests
export BULWARK_GITHUB_APP_PRIVATE_KEY=...
docker compose --profile fixagent up -d      # temporal, temporal-ui (localhost:8081), fixagent-worker
```

## API

| Endpoint | What it does |
|---|---|
| `POST /assets/{asset_id}/issues/{issue_id}/verified-fix` | Start a run. `{"run_tests": bool, "test_image": str, "test_command": str}`. `409` with no completed scan, `429` over the per-org concurrency cap, `503` if Temporal is unreachable. |
| `GET /assets/{asset_id}/issues/{issue_id}/verified-fix` | The latest run's status, patch, and full verification record. `404` if none has started. |
| `POST .../verified-fix/approve` | A human approving the proposed patch. Opens the pull request. `409` unless a run is `awaiting_approval`. |
| `POST .../verified-fix/reject` | A human rejecting it. No pull request is opened. |

All four need `fixes:read` (the `GET`) or `fixes:write` (the rest) on a scoped token, or the legacy
shared token.

## Running the project's own tests (opt-in, verified-owner only)

`run_tests: true` only takes effect when the asset was scanned via an installed GitHub App
(`Scan.github_installation_id` is set) — GitHub's own proof that the installer administers that
repository. Asked for on any other asset, it is silently ignored, not rejected: the rest of
verified-fix still runs, just without a test-execution step. This runs in a **more permissive**
sandbox than every scanner (`core/fixagent/sandbox.py`): network enabled (to install dependencies),
a writable checkout, default Docker capabilities rather than the scanner sandbox's
`--cap-drop=ALL`/read-only/no-network. This is the plan's own "hardened Docker runner, for now" —
ADR-0015 already named Firecracker (Phase 11, not yet built) as the properly-isolated version of
this.

## Limits (ADR-0015)

| Limit | Value | Env var |
|---|---|---|
| Per attempt | 10 minutes | `BULWARK_FIXAGENT_PER_ATTEMPT_TIMEOUT_S` |
| Overall (verification phase only — excludes the human-approval wait) | 30 minutes | `BULWARK_FIXAGENT_OVERALL_TIMEOUT_S` |
| Attempts | 3 | `BULWARK_FIXAGENT_MAX_ATTEMPTS` |
| Concurrent runs per organization | 3 | `BULWARK_FIXAGENT_MAX_CONCURRENT_PER_ORG` |

A run stopped by a timeout resolves to `inconclusive`, never `failed` — a timeout is evidence
verification didn't finish in time, not evidence the patch was wrong (ADR-0015). `ended_reason` on
the run's own record says which limit ended it: `overall_timeout`, `per_attempt_timeout`,
`max_attempts_exhausted`, or `approval_timeout` (a run nobody reviewed within 7 days — a hygiene
limit, not one of ADR-0015's three).

## What leaves your machine

The same things Week 41's remediation feature already sends (title, description, CWE/OWASP ids,
file path, the code snippet — secret-scrubbed and PII-redacted first), plus: whatever the model asks
`read_file`/`search_code` for during its tool-calling turn (also scrubbed and redacted before being
sent back to it), and, once a human approves, the patched file's full content to GitHub via the
Contents API.

## What this does NOT prove (read before relying on it)

- **No live GitHub App run.** `create_pull_request` is unit-tested against a fake transport, built
  from GitHub's documented API contract — not run against a real installation in this environment.
- **No live run against a real hosted model.** The tool-calling loop is unit-tested against a fake
  Anthropic-shaped client covering the real control-flow paths — not run against the real API here.
- **No MLX/local tool-calling.** Privacy mode (Week 41) does not cover verified-fix.
- **No "Edit" action** on a pending patch — the plan's own mockup shows `[Reject] [Edit] [Open pull
  request]`; this ships the first and third.
- **No precise sandbox capability set** for test execution — see [above](#running-the-projects-own-tests-opt-in-verified-owner-only).

Full account in [ADR-0027](adr/0027-verified-fix-agent.md) and
[v2-week42-verification.md](v2-week42-verification.md).
