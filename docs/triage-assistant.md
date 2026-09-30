# Triage assistant

For one Issue, a model reads its taint path and surrounding code and returns an advisory verdict:
`likely_real`, `likely_false_positive`, or `unsure`, with a rationale and the specific lines it
based that on. **It never changes the issue's status, severity, or visibility.** Design reasoning in
[ADR-0028](adr/0028-triage-assistant-and-hypotheses-lane.md); the honest verification record is in
[v2-week43-verification.md](v2-week43-verification.md).

## What it does, and doesn't, affect

The verdict is stored on the Issue and shown in the issue detail screen immediately. It also feeds
`core.risk.score` as one ranking input -- a bounded nudge (never suppressing the finding, never
overriding a CISA KEV floor) -- but only starting with the asset's **next** scan, not retroactively.
It is a separate signal from the human `triage_status` (not-a-risk/accepted/reopen): nothing here can
ever set that; only a person can, through the existing triage action.

## Turning it on

Hosted-only, same posture as remediation and the verified-fix agent:

```bash
export BULWARK_LLM_ENABLED=1
export BULWARK_LLM_API_KEY=...
# optional: route this task to a different backend/model than the default
export BULWARK_LLM_ROUTE_TRIAGE=hosted
```

## API

| Endpoint | What it does |
|---|---|
| `POST /assets/{asset_id}/issues/{issue_id}/triage-assistant` | Generate a fresh verdict. Sends the finding's taint path and code to the model provider. `409` if the assistant isn't enabled, or if the asset has no completed scan or the issue has no occurrence in it. |
| `GET /assets/{asset_id}/issues/{issue_id}/triage-assistant` | The stored verdict. `404` if none has been generated yet. |

Both need `scans:read` (the `GET`) or `scans:write` (the `POST`) -- the same scopes the issue list
and human triage endpoints already use; no dedicated scope was carved out for a feature this closely
related to them.

## What leaves your machine

The same category of data Week 41/42's LLM features already send: the finding's title, description,
CWE id, file path, its taint path, and the surrounding code -- secret-scrubbed and PII-redacted
first, exactly like remediation's own prompt.

## What this does NOT prove

No live run against a real hosted model, and no measurement against the OWASP Benchmark's
ground-truth labels (the plan's own stated evaluation) -- both need a live model this environment
doesn't have. Full account in [v2-week43-verification.md](v2-week43-verification.md).
