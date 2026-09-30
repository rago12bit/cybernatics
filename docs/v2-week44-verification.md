# Week 44 verification -- security copilot (plan §21.5)

Honest record of what was built, run, and measured. See `docs/adr/0029-security-copilot.md` for the
design decisions, including why several pieces reuse existing infrastructure (the knowledge base's
hashed embedder, the verified-fix agent's tool-calling loop) rather than building new capability.

## What was built

- `core/embeddings/` (task 1): `chunk.py` (function-level chunking off `core.codeintel`'s real
  parsers, no model involved), `service.py` (the analyze-chunk-embed-persist pass). New
  `code_chunks`/`code_chunk_indexes` tables (migration 0015), RLS via `assets`. The pgvector/JSON
  TypeDecorator was extracted from `core.rag.store` into `core.persistence.vector_type` so the
  knowledge base and the new table share one implementation.
- `core/copilot/` (task 2): `tools.py` (the five read-only tools: `query_issues`,
  `fetch_code_range`, `get_call_path`, `list_routes`, `compare_scans`), `contract.py` (citation
  validation), `service.py` (the tool-calling turn loop, `ask()`). `Task.COPILOT` added to the
  gateway.
- `core/copilot/session.py` (task 3): `CheckoutCache`, clone-once-per-conversation with idle-TTL
  eviction and a per-conversation-id lock. New `copilot_conversations`/`copilot_messages` tables
  (migration 0016), the second with a two-hop RLS policy. Three endpoints: start a conversation,
  post a message, list messages.
- `web/components/CopilotPanel.tsx` + `copilot-panel.css` (task 4): a slide-in panel, mounted in
  `IssueDetail` (issue context) and `ProjectOverview` (no context). Issue citations render as real
  links; code citations render as plain `path:line` text (no jump-to-line view exists in this
  frontend yet).
- `docs/adr/0029-security-copilot.md`, `docs/copilot.md`.

## Validated against real, live things -- not mocks

- **Chunking and retrieval, against a real Postgres with pgvector.** A disposable
  `bulwark/postgres:16-pgvector` container: the full migration chain plus the 0015 downgrade/upgrade
  roundtrip, a real chunk-embed-store-search pass proving correct ranking (a `delete_user` function
  ranks above `get_user` for the query "delete a user from the database," not just "returns
  something"), and cross-org RLS isolation as the non-superuser `bulwark_app` role.
- **The tool-calling loop, against a fake Anthropic-shaped client** covering the real control-flow
  paths: a tool call answered and used, an invalid citation rejected then retried successfully, and
  a model that never calls the terminal tool raising `CopilotGiveUp`. `query_issues` and
  `compare_scans` were tested against real seeded issues/scans through
  `core.persistence.repo.sync_issues_for_scan`, not hand-built fixtures standing in for the real
  data shape.
- **The checkout cache's concurrency guarantee, with a real multi-threaded test.** Five real threads
  racing to be the first message of the same brand-new conversation clone exactly once, proven by
  counting actual clone calls under a lock-widened race window -- not just reasoned about in a
  docstring.
- **Persistence and RLS, against a real Postgres, including the two-hop case.** A second disposable
  container run: the full migration chain plus the 0016 downgrade/upgrade roundtrip, and live
  cross-org isolation for both `copilot_conversations` (one-hop) and `copilot_messages` (two-hop,
  through `copilot_conversations` into `assets`) as the non-superuser `bulwark_app` role -- the
  two-hop policy was checked explicitly rather than assumed to follow from the one-hop case.
- **The API layer, against real persisted rows**, not just mocked responses: starting a
  conversation creates a real `CopilotConversationRow`; posting a message (with `ask()` mocked, its
  own real tests cover the loop itself) persists both the user's question and the assistant's
  answer as real `CopilotMessageRow`s, retrievable via the `GET` endpoint; a model that gives up
  still produces a real, honest stored message rather than a 5xx.
- **The frontend panel, against a real running API**, not mocked HTTP: seeded a real scan (with
  real fake findings, via the e2e server's actual scan-creation path) through `scripts/e2e_server
  .py`, then drove a real browser through opening the panel on both the project overview and issue
  detail pages, confirming each POSTs to the real `/copilot/conversations` endpoint and displays the
  real `409 "the copilot is not enabled on this server"` message when no model is configured --
  the actual API's own text, not a hand-written approximation.

## Verified

- Backend: `test_embeddings_*.py` (chunk/repo/service), `test_copilot_*.py` (tools/contract/service/
  repo/session/api) -- new tests across the four backend tasks, plus the existing suite re-run
  clean (ruff/black/mypy, and the affected areas' own tests) after each task.
- Frontend: `copilot-panel.test.tsx` (6 tests: trigger/open/send/citation-link/code-citation-text/
  close), the full existing suite re-run clean, `tsc --noEmit` clean, a real `next build` production
  build clean, the a11y audit re-run clean with the panel now mounted on two more pages.
- Both migrations' live Postgres/RLS validation, and the checkout-cache concurrency test, all above.

## What this does NOT prove (read before relying on it)

- **No live run against a real hosted model.** `core.copilot.service.ask` is unit-tested against a
  fake Anthropic-shaped client covering the real control-flow paths, not run against the real API
  here -- the same disclosed gap Weeks 41-43 already carry for their own LLM call sites.
- **No promptfoo suite for the copilot's system prompt.** Consistent with, not a new gap relative
  to, `core/fixagent`'s own tool-calling prompt (neither has one -- see ADR-0029 for why a
  schema-conformance suite doesn't fit a multi-turn tool-calling conversation the way it fits the
  single-shot `fix`/`triage`/`hypotheses` prompts).
- **No measurement against the plan's own 100-question reference set** ("valid-citation rate;
  answer correctness") -- that evaluation needs a live model, which this environment does not have.
- **Retrieval quality is bounded by the same lexical-embedding limits ADR-009 already discloses**
  for the knowledge base: a plain-English question sharing no vocabulary with the relevant code will
  miss. Not measured separately for code chunks here.
- **The Hypotheses lane's own "off by default" gateway toggle pattern was followed, but no separate
  audit-log entry type was added for copilot conversations/messages** -- they are ordinary
  RLS-protected rows, not audit-logged events, the same posture triage verdicts already have.
- **`core.copilot.session.CheckoutCache` is process-local.** A multi-worker deployment needs sticky
  routing per conversation, or a shared cache, to get the reuse benefit across every worker. A cache
  miss just re-clones -- correctness is unaffected, only the latency benefit is process-scoped.
- **The scan-comparison page's "this scan" copilot context is not wired up.** The panel supports a
  scan context prop; only that specific page's plumbing (threading the selected scan id out of
  `ScanComparison`'s internal state) was not done this task.
- **Code citations have nowhere to link to.** This frontend has no view that jumps to an arbitrary
  file:line; they render as plain text rather than a link that would go nowhere.
