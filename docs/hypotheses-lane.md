# Hypotheses lane

A separate, off-by-default tab for flaws pattern-based scanning can't express. v1 detects one type:
**a route with no recognized authorization check, in a file where a sibling route has one.** IDOR and
mass assignment are named in the plan but not implemented yet -- a disclosed scope decision, not an
oversight. Design reasoning in [ADR-0028](adr/0028-triage-assistant-and-hypotheses-lane.md); the
honest verification record is in [v2-week43-verification.md](v2-week43-verification.md).

## The loop

```
re-check out the asset's latest scan's source
    │
    ▼
find every route with no auth-looking decorator/middleware, in a file where a sibling route
has one -- entirely deterministic, no model involved (core.hypotheses.facts)
    │
    ▼
for each candidate: show the model the structured facts + that route's own code
    │
    ▼
model decides: worth a person's time? ── no ── nothing stored
    │ yes
    ▼
stored as an open hypothesis, with evidence and a suggested manual check
    │
    ├── Dismiss ─────────────────────────► done, never appears as an Issue
    └── Confirm ──► a real Issue, source="llm-confirmed", never automatic
```

Never counted in the risk score or a policy gate, and never shown in the main issue list, unless and
until a person confirms it.

## Turning it on

Hosted-only, and needs a git-sourced asset (it re-clones over HTTPS to run code intelligence fresh):

```bash
export BULWARK_LLM_ENABLED=1
export BULWARK_LLM_API_KEY=...
export BULWARK_LLM_ROUTE_HYPOTHESES=hosted   # optional: this task's own route
```

## API

| Endpoint | What it does |
|---|---|
| `POST /assets/{asset_id}/hypotheses/generate` | Re-checks out the latest scan's source and asks the model about every candidate found. `409` if the lane isn't enabled, there's no completed scan, or the asset isn't git-sourced. |
| `GET /assets/{asset_id}/hypotheses` | List them, optionally filtered by `?status=open\|promoted\|dismissed`. |
| `POST .../hypotheses/{id}/promote` | A human confirming one. Creates a real Issue. |
| `POST .../hypotheses/{id}/dismiss` | A human declining one. No Issue is created. |

All four need `scans:read` (the `GET`) or `scans:write` (the rest).

## What leaves your machine

Per candidate: the route's method/path, the names of its own and its siblings' auth-looking
markers, and the route's own code (secret-scrubbed and PII-redacted first) -- never the whole
repository, and never another route's code beyond its path and marker names.

## What this does NOT prove

No live run against a real hosted model. No measurement against OWASP Juice Shop's documented
access-control challenges or seeded authorization flaws (the plan's own stated evaluation) -- both
need a live model this environment doesn't have. `auth_markers` extraction covers Python and
Express/JS only; Go and Django routes never produce a candidate yet. Full account in
[v2-week43-verification.md](v2-week43-verification.md).
