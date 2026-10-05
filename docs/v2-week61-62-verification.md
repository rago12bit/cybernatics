# Weeks 61-62 verification -- SLA engine and risk acceptance (plan Phase 15, §44.1-§44.2, §55.3)

Honest record of what was built, run and measured, done as two commits. Decision:
[ADR-0046](adr/0046-sla-and-risk-acceptance.md) (deadlines are computed, never stored; accepting a
risk takes a second person). Neither week ends a milestone: M14 and `v2.3.0` come after Week 64.

## What was built

| # | Commit | Result |
|---|---|---|
| 61 | SLA engine | Versioned SLA policies per project by severity (migration 0033, RLS); the clock from first detection, `sla_started_at` for restarts; on track / due soon / breached, met / missed, paused; `issue.sla` on every issue response and `?sla=` on the issues table; a five-minute sweep announcing each crossing once (outbox event + Slack, Discord, webhook); the **SLA** page, an SLA column and filter, the deadline on the issue page |
| 62 | Risk acceptance | `risk_acceptances` and their Issues (migration 0034, RLS); request, four-eyes approve and reject, withdraw, expire now, reinstate, extend, lapse; an expiry job that reopens Issues and can restart their SLA; proof links and encrypted proof files; triage can no longer accept alone; legacy acceptances migrated; the request form (§55.3), the **Approvals** queue and a page per acceptance |

## Bugs found and fixed along the way

1. **CORS refused every PUT, PATCH and DELETE** -- found saving the SLA policy in a browser.
   Preflight allowed only GET and POST since the first CORS commit, so from the web app on its own
   origin (the default: web and API on different ports) these had never worked: threat model,
   retention, plugin allowlist and integration settings saves, and turning off or deleting a
   connector (Week 60). It now allows every method a route uses; a test enumerates them.
2. **A one-person bypass**: triage's "accepted" action would have let anyone skip approval. It now
   answers 409 and points at the request; the old test that accepted through triage was rewritten.
3. The issue page crashed on a non-list response for its acceptances (a real API error could do the
   same); guarded, as Week 59's manual-finding panel was.
4. Found in the browser: people showed as token prefixes ("token:bulwark_083076"); responses now
   carry token names. The issue page showed two banners for one acceptance; now one. The request
   form's SLA checkbox sat above its text and the file picker had a redundant label; fixed.

## Validated against real things -- not mocks

- **Real Postgres under forced Row-Level Security**, as the worker role, migrated to 0034 (and down
  to 0032 and back up): 52 integration tests pass, two new. Another org sees no policy, no
  acceptance, and its sweep and expiry job touch nothing of the first org's; the issues-table SLA
  filter does its deadline arithmetic in Postgres and agrees with the rules.
- **The legacy migration on real Postgres under forced RLS** (the migration sets each org's scope
  itself): two Issues accepted by one person with one reason and expiry became one approved legacy
  acceptance covering both; one past its date became an expired one; an untouched Issue was left
  alone; no Issue's triage or expiry changed.
- **A real browser against the real API** (the end-to-end server, SQLite, Next dev server):
  - SLA: the starter policy saved as version 1; a Critical first seen 10 days ago showed "Breached ·
    3 days overdue", a High at 25 days "Due soon · 4 days left"; the Breached filter showed only the
    first; the issue page read "SLA: Breached · 3 days overdue (due 02/10/2026)".
  - Risk acceptance, with two personal tokens (Alice, Bob): Alice requested from the issues table
    (the approver list offered only Bob; "56 days · Policy maximum: 90 days"); the Issue stayed
    open. Alice's own approve call got 403 ("you requested this; someone else has to approve or
    reject it") and her page offered only Withdraw. Bob approved; the Issue became accepted until
    30/11/2026 and its history read "Risk acceptance requested", "Risk acceptance approved". A second
    request with a link and a PNG proof file was approved by Bob and expired now: the Issue reopened,
    Reinstate was offered, and the trail read requested, proof added, approved, expired -- by name.
- **Mutation checks.** Removing the "not the requester" rule fails three tests; removing the
  "not the shared token" rule fails two.
- Backend: `ruff`, `black`, `mypy` (280 files) clean; 2,489 unit tests pass (4 skipped), coverage
  92%. Web: 288 tests, `tsc` clean.

## What this does NOT prove (read before relying on it)

- **"Someone else" is another API token, not another person.** One person with two tokens can
  approve their own request. Real identities arrive with SSO and SCIM (Week 75).
- **Notifications were not delivered to a real Slack or Discord.** Message text and routing are
  tested with the senders replaced; the senders themselves are the ones scan notifications use.
- **The sweep and the expiry job were run by tests and by hand, not by a running Celery beat**; they
  are scheduled the same way as the connectors job (Week 60).
- **Priority bands** (§44.1's alternative SLA basis) are not built; they need the priority engine
  (Week 63).
- **Scale.** The sweep and expiry job read every open Issue of every org every five minutes; nothing
  here measured that on a large dataset.
- **Proof files without OpenBao are stored unencrypted**, as manual-finding evidence is; the
  encrypted path is the same code, tested with a fake OpenBao in Week 59.
- CI results for these commits have not been observed (nothing pushed).
