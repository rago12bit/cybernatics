# ADR-0029: Security copilot -- tool-calling chat grounded in issues, code, and scan history

Status: Implemented (2026-09-30), Week 44 (plan §21.5), building on Week 41's model gateway
(ADR-0026), Week 42's tool-calling agent (ADR-0027), and Week 43's retrieval-adjacent work.

## Context

The plan asks for grounded chat: "Which routes accept file uploads?", "Why is ISS-142 ranked above
ISS-98?", "What changed since last week?" -- answered by calling tools over real data, every answer
citing issue IDs and file:line, citations checked before the answer is shown. Retrieval uses pgvector
embeddings of function-level chunks, always filtered by tenant.

## Decisions

### Retrieval reuses the knowledge base's hashed embedder, not new gateway plumbing (task 1)

`core/embeddings/` chunks a checkout at function granularity off `core.codeintel`'s real parsers
(`CodeGraph.all_symbols`) and embeds with `core.rag.embed.HashingEmbedder` -- the same model-free,
hashed/IDF embedder ADR-009 chose for the remediation knowledge base, not a new neural-embedding
capability on the LLM gateway. Checked first: no `LLMClient` implementation anywhere in this codebase
can embed today: every gateway `Task` (`FIX`/`TRIAGE`/`HYPOTHESES`) assumes chat-completion
(`complete(system, user) -> Completion`). Adding real embedding support would mean a new protocol
method, a new Anthropic embeddings call, and a new Ollama `/api/embeddings` call -- genuine new
surface area for a corpus (source code identifiers, route paths) that ADR-009's own reasoning already
covers: keyword-rich technical text, where lexical retrieval works, at no network/dependency cost.
One `HashingEmbedder` fit per asset (`CodeChunkIndexRow`), not one global fit like the knowledge
base's `KbMeta`, since each asset's code is its own small corpus, never compared against another's.

The `Vector`/`_PgVector` pgvector TypeDecorator moved out of `core.rag.store` into
`core.persistence.vector_type` so the new `code_chunks` table and the existing `kb_chunks` table
share one implementation instead of two copies of the same ~25 lines.

### The tool-calling loop reuses `core.fixagent.agent.propose_patch`'s exact shape (task 2)

`core/copilot/service.ask` is structurally identical to Week 42's `propose_patch`: bounded turns
(`MAX_TURNS`), native tool use via `AnthropicClient.complete_with_tools` (hosted-only, ADR-0027 --
local-model tool-calling was not built then and still isn't), every tool result framed to the model
as untrusted data never instructions, and a terminal tool (`give_answer` here, `propose_patch` there)
as the only way a turn produces a real result. This is the second tool-calling loop in the codebase;
rather than generalize an abstraction from one example, it was copied and adapted, the same
"kept as its own small copy" reasoning `core.hypotheses.service._safe_read` already documents for
smaller cases.

`query_issues` and `compare_scans` are thin wrappers around `core.persistence.repo
.list_asset_issues`/`compare_scans` -- the exact functions the issues table and scan-comparison
screen APIs already call. No new filtering or diffing logic was written for the copilot.

Retrieval is wired in as automatic pre-loop grounding (the top-k similar chunks from task 1's index,
prepended to the first user message, labelled as data), not a sixth callable tool -- matching the
plan's own separate treatment of "the model answers by calling tools" and "retrieval uses pgvector
embeddings" as two distinct mechanisms.

**No promptfoo suite for the copilot's system prompt**, consistent with (not a new gap relative to)
`core/fixagent`: neither tool-calling agent's system prompt has one. A promptfoo suite's
schema-conformance fixtures fit a single-shot "prompt in, JSON out" contract (`core/llm/prompts/fix`,
`/triage`, `/hypotheses`) far better than a multi-turn tool-calling conversation, which has no single
input/output pair to snapshot against fixtures.

### Persistence: two tables, one with a two-hop RLS policy (task 3)

`copilot_conversations` (asset-scoped) and `copilot_messages` (no `asset_id` of its own) follow
migration 0014/0015's RLS-via-`assets` pattern, but `copilot_messages`' policy is a two-hop
`EXISTS` (through `copilot_conversations` into `assets`), since a message's only path to a tenant is
through the conversation it belongs to. Verified live against a disposable Postgres, including
cross-org isolation for both tables as the non-superuser `bulwark_app` role -- the two-hop case was
checked explicitly, not assumed to follow from the one-hop case already proven for `hypotheses`.

### Clone once per conversation, not once per message

`core/copilot/session.CheckoutCache` clones an asset's latest scan's source once when a conversation
starts and reuses it (checkout + `CodeGraph`) for every later message in that same conversation,
process-local with idle-TTL eviction, rather than re-cloning on every turn the way Hypotheses-lane
generation and the triage assistant each do their own one-shot re-clone. A chat panel is interactive;
paying a full clone-and-analyze cost per question would make every follow-up question slow. The
checkout is a snapshot as of the conversation's first message -- a scan finishing mid-conversation
does not change what later messages in that conversation see; a new conversation always sees the
asset's current latest scan.

A per-conversation-id lock prevents the one real race this design introduces: two concurrent
first-messages for the same brand-new conversation must not both clone (the loser's checkout would
never be tracked or cleaned up). Proven with a real multi-threaded test, not just reasoned about.

A local (non-Anthropic) backend routed to `Task.COPILOT` is rejected with a `409` at the point of use
(an `isinstance` check mypy itself surfaced as a real gap when `ask()`'s `AnthropicClient` parameter
was checked against the gateway's general `LLMClient | None` return type) rather than crashing --
tool-calling stays hosted-only, the same constraint `core/fixagent` already lives with.

### The frontend panel's citation limits (task 4)

Issue citations render as real links to the issue detail page. Code citations (`path:line`) render as
plain monospace text, not a link: this frontend has no view that jumps to an arbitrary file:line
today (code is only ever shown inline on pages that already fetched it themselves, e.g.
`IssueDetail`'s taint-path steps) -- a link with nowhere real to go would be worse than no link. The
panel is mounted in `IssueDetail` (issue context) and `ProjectOverview` (no context, general
project chat); the scan-comparison page's own "this scan" context is deferred, since wiring it needs
threading the currently-selected scan id out of `ScanComparison`'s internal state, a change to an
existing component this task didn't make.

## Consequences

- A hosted deployment is unaffected by default: nothing here calls a model unless `Task.COPILOT` is
  explicitly routed to a backend, same as every other Week 41-43 LLM feature.
- Retrieval quality is bounded by the same lexical-embedding limits ADR-009 already discloses for the
  knowledge base (plain-English queries without shared vocabulary with the code miss) -- not measured
  separately here; no evaluation run against the plan's own 100-question set in this environment
  (needs a live model).
- `core.copilot.session.CheckoutCache` is process-local: a multi-worker deployment needs sticky
  routing per conversation, or a shared cache, to get the reuse benefit across every worker. A cache
  miss just re-clones -- correctness is unaffected, only the latency benefit is process-scoped.
- The scan-comparison page's copilot context wiring, and code-citation navigation (no jump-to-line
  view exists yet), are both disclosed gaps, not silent omissions.
- No live hosted-model run for the copilot in this environment (no API key here); the tool-calling
  loop is unit-tested against a fake Anthropic-shaped client covering the real control-flow paths
  (a tool call, a rejected citation retried, a give-up), the same posture Weeks 41-43 already
  document for their own LLM call sites.
