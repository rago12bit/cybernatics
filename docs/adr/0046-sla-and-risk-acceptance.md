# ADR-0046: SLA deadlines are computed, never stored; accepting a risk takes a second person

Status: Accepted (2026-10-05), Weeks 61-62 (plan §44.1, §44.2, §55.3; the plan calls this ADR-019).
Builds on [ADR-0019](0019-tamper-evident-audit-log.md) (the hash-chained audit log) and
[ADR-0018](0018-scoped-api-tokens.md) (scoped API tokens).

## Context

Governance starts here. A project needs remediation deadlines per severity, starting at first
detection and not restartable by re-uploading a report, with "due soon" and "breached" announced.
And a risk may be lived with for a while -- but only with a justification, compensating controls,
proof, an expiry capped by policy, and an approver who is *not* the requester, enforced on the
server, with every step evidence an auditor can verify.

Until now one person could mark an Issue "accepted" through triage, alone.

## Decision

**SLA.** A policy per project, versioned by insertion like dedup settings (migration 0033): per
severity band, days to fix and a "due soon" window. Off until someone saves one; the starter values
(7/30/90/180 days, Info none) are offered, not imposed. The deadline is *computed* from the policy,
the Issue's severity and its clock -- `first_seen_at`, which reimport never resets, or
`sla_started_at` once a risk acceptance restarted it -- and never stored, so a policy or severity
change moves every deadline at once. The issues table filters by SLA state in SQL that a test
checks against the rules at every band boundary. A sweep every five minutes announces each crossing
into due soon or breached once (`issues.sla_notified`): an outbox event for the rules engine
(Week 65) and one message per project to Slack, Discord and the outbound webhook. Priority bands,
the plan's alternative basis, wait for the priority engine (Week 63).

**Risk acceptance.** A `risk_acceptances` row covers one or more Issues of one project (migration
0034): decision (accept, mitigate, transfer, avoid), justification and controls (required), proof
(links, and files stored like manual-finding evidence: sniffed, encrypted, downloaded by signed
link), an expiry no later than the policy maximum (90 days, `BULWARK_RISK_ACCEPTANCE_MAX_DAYS`, the
same as the policy gate's rule), and whether the SLA restarts on expiry. `core.acceptance.service`
enforces, whatever a screen does:

- The Issues stay open until approved. The approver's actor differs from the requester's, and is a
  personal API token -- the shared deployment token is anyone, so it approves nothing. A named
  approver is the only one who can decide.
- An Issue is under at most one live (requested or approved) acceptance.
- Approval writes the existing triage fields (`accepted` until the expiry), so the active queue, the
  SLA pause and the policy gate read it unchanged. Expiry -- the job, or "expire now" -- reopens
  them, and restarts their SLA clock if asked.
- "Reinstate" undoes "expire now" only within the approved dates; anything later is an extension,
  which is a new request needing its own approval. A request whose date passes unapproved lapses.
- Every change is a hash-chained audit entry and an outbox event, and appears in each Issue's
  history.

Triage can no longer accept a risk (HTTP 409, pointing at the request); it still marks "not a
risk" and reopens. Issues accepted alone before this become *legacy* acceptances, grouped by
project, person, expiry and reason, approved if still in date and expired otherwise -- no expiry
date lost, and marked as never approved by a second person.

## Consequences

- **"Someone else" is a different API token, not a different human.** Bulwark has no user accounts
  yet; one person holding two tokens can approve their own request. The screens say so, and SSO and
  SCIM (Week 75) are what close it. The approver list is the org's live personal tokens that can
  write, other than the asker's.
- The SLA sweep and the expiry job each read every open Issue of every organization every five
  minutes. That is fine at today's scale; a large deployment would want the due-time index the
  computed deadline avoids storing.
- Without OpenBao, proof files are stored unencrypted, as manual-finding evidence is (the API says
  which).
- Found on the way: CORS allowed only GET and POST, so every PUT, PATCH and DELETE from the web app
  on another origin was refused (settings, threat model, connectors). It now allows every method a
  route uses.
