# Security copilot

Tool-grounded chat about one project: issues, code, routes, and scan history. Every answer cites
real issue IDs or file:line -- checked against what actually exists before you ever see it. Design
reasoning in [ADR-0029](adr/0029-security-copilot.md); the honest verification record is in
[v2-week44-verification.md](v2-week44-verification.md).

## What it can answer

The model calls tools that read real, already-scanned data:

| Tool | What it reads |
|---|---|
| `query_issues` | The project's currently-open issues, filterable by severity/category/CWE/path. |
| `fetch_code_range` | A range of lines from a file, with line numbers. |
| `get_call_path` | The known callers of the function enclosing a given file:line. |
| `list_routes` | Every HTTP route code intelligence found, optionally filtered by method. |
| `compare_scans` | New/fixed/reintroduced/unchanged issues between two scans of this project. |

Before the model does anything else, the most relevant already-indexed code (function-level chunks,
Week 44 task 1) is found by similarity search and handed to it as extra context -- not a tool it
calls itself, just grounding for the question you actually asked.

## Citations

Every answer names which issues or file:line it's based on. A citation is checked against real
data (a real issue id for this project, a real file this checkout actually contains) before the
answer is shown; if a citation doesn't check out, the model is told which one and asked to try
again. An answer with nothing to cite (the tools genuinely found nothing relevant) still gets shown
-- it just says so, instead of citing something invented to look complete.

## Turning it on

Hosted-only, same posture as the triage assistant and Hypotheses lane:

```bash
export BULWARK_LLM_ENABLED=1
export BULWARK_LLM_API_KEY=...
export BULWARK_LLM_ROUTE_COPILOT=hosted   # optional: this task's own route
```

A local/Ollama backend routed to this task is rejected with a clear `409`, not a crash: tool-calling
needs the provider's native tool-use protocol, which only the hosted backend implements (ADR-0027).

## API

| Endpoint | What it does |
|---|---|
| `POST /assets/{asset_id}/copilot/conversations` | Start a conversation. Optional `context_kind`/`context_id` ("issue"/<id> or "scan"/<id>) records which page it was opened from. `409` if the copilot isn't enabled, there's no completed scan, or the asset isn't git-sourced. |
| `POST .../conversations/{id}/messages` | Ask one question. Clones the project's latest scan's source on the conversation's first message, reuses that checkout for later messages in the same conversation. |
| `GET .../conversations/{id}/messages` | The conversation's history so far. |

All three need `scans:read` (the `GET`) or `scans:write` (the rest) -- the same scopes every other
LLM feature in this codebase already uses.

## What leaves your machine

Per question: the question itself, the top few similarity-matched code chunks, and whatever a tool
call reads (an issue's title/severity/path, a range of code, a route list) -- secret-scrubbed and
PII-redacted first, the same as every other model call this codebase makes. Never the whole
repository at once.

## What this does NOT prove

No live run against a real hosted model in this environment (no API key here) -- the tool-calling
loop is unit-tested against a fake client covering the real control-flow paths, the same disclosed
gap Weeks 41-43 already carry for their own LLM call sites. No measurement against the plan's own
100-question reference set (needs a live model). The panel's code citations render as plain text,
not a link: this frontend has no view that jumps to an arbitrary file:line yet. The panel isn't
wired into the scan-comparison page's "this scan" context yet. Full account in
[v2-week44-verification.md](v2-week44-verification.md).
