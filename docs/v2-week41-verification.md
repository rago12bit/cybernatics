# Week 41 verification — model gateway and LLMOps (plan §21.1)

Honest record of what was built, run, and measured — for Week 41: a local backend, per-task
routing, privacy mode, token budgets, PII redaction, a path denylist, one schema-repair attempt, and
a versioned prompt with a real evaluation suite. See `docs/adr/0026-model-gateway.md` for the design
decisions, including what was deliberately deferred. This closes part of PHASE 10 (M9 is Weeks
41-45; this is Week 41 only).

## What was built

- `core/llm/ollama_client.py`: `OllamaClient`/`OllamaConfig`, a plain-HTTP local backend against
  Ollama's `/api/chat` -- no new SDK dependency.
- `core/llm/gateway.py`: `Task`/`Backend` enums, `GatewayConfig`, `make_gateway_client()` -- the
  single choke point for hosted-vs-local backend selection, per task, with privacy-mode enforcement.
- `core/llm/client.py`: `LLMClient.complete` now returns `Completion(text, tokens)` instead of a
  bare string, so real provider-reported token usage flows through to budgets. `AnthropicClient`
  populates it from the SDK's own `usage.input_tokens`/`output_tokens`.
- `core/llm/budget.py` + migration `0011`: `Scan.llm_tokens_used` (a running per-scan counter) and a
  new `llm_usage` table (per-org-per-month, RLS-protected) -- both a hard `429` stop, checked before
  a real call and recorded after it.
- `core/llm/pii.py`: optional Microsoft Presidio redaction (`bulwark-scan[pii]` extra) as a second
  layer after `scrub_secrets`, explicitly pinned to the small `en_core_web_sm` spaCy model.
- `core/llm/pathguard.py`: a path denylist (`.env`, `*.pem`, `id_rsa*`, ...), additive-only via
  `BULWARK_LLM_PATH_DENYLIST`.
- `core/llm/service.py`: one repair attempt on a `ContractError`, with a fixed generic note that
  never echoes the rejected reply.
- `core/llm/prompts/fix/v1.md` + `core/llm/prompt.py::load_prompt`: the system prompt moved from an
  inline string to a versioned, packaged file.
- `core/llm/prompts/fix/promptfooconfig.yaml` + `promptfoo_provider.py` + `promptfoo_assert.py` +
  `scripts/gen-promptfoo-fixtures.py`: a real, runnable promptfoo evaluation suite.
- `api/main.py`/`api/deps.py`: `build_default_app` now wires the gateway instead of the single
  hardcoded client; `POST /scans/{id}/suggestion` enforces the token budget alongside the existing
  call-rate limiter and records real usage after a genuine (non-cached) call.
- `cli/main.py`: `bulwark llm status` reports gateway routing and both backends' status; `bulwark llm
  suggest` gained `--privacy`.

## Validated against real, live things — not mocks

- **A real local Ollama server**: pulled the real `ollama/ollama` Docker image, ran a real
  `qwen2.5:0.5b` model, and called `OllamaClient.complete()` against it directly -- got a real reply
  and a real token count (31) back before writing any test around it.
- **The full privacy-mode path, end to end**: with a real (valid-shaped) hosted API key configured
  AND `BULWARK_LLM_PRIVACY_MODE=1` AND a real local Ollama server ready, `suggest()` was run through
  `make_gateway_client` for real -- it routed to the local model, made two real HTTP calls (the
  original attempt plus one repair attempt, both logged), got back a real (small-model-quality)
  reply that correctly failed the real contract validator on both attempts, and degraded to static
  text with an honest `degraded_reason` -- the entire pipeline exercised for real, not stubbed at any
  layer.
- **The migration**: `0011` was run up and down against a real `bulwark/postgres:16-pgvector`
  container (the same one Week 40 used), including confirming the RLS policy actually isolates one
  org's `llm_usage` row from another's (`SET ROLE bulwark_app; SET app.current_org = ...`) before and
  after a downgrade/upgrade cycle.
- **The promptfoo suite**: actually run (`promptfoo eval`) against the real local Ollama server, not
  just written. This caught two real integration bugs before they could have shipped silently
  broken:
  1. promptfoo's Python provider is a persistent worker process; an env var exported in the
     invoking shell after that worker starts does not reliably reach it. Fixed by driving the
     provider entirely from its own YAML `config:` block instead of ambient `BULWARK_LLM_*` env vars.
  2. promptfoo itself reserves the provider config key `timeout` (milliseconds, its own per-call
     cap); a first draft reused that name for Ollama's own request timeout (seconds), which silently
     fed a seconds-based number in as a millisecond cap and timed out every call after 90ms. Renamed
     to `request_timeout_s`.
  Once fixed, the suite correctly exercised the real model and correctly *failed* two of its three
  fixtures against the tiny local model's genuinely malformed (fenced-JSON) output -- proof the
  deterministic assertion (the real `parse_response`) actually rejects bad real output, not just a
  suite that trivially always passes.

## A real design trade-off made and documented, not silently dropped

The plan's own wording for schema validation is "validated with Pydantic: one repair attempt, then
fall back to static text." The existing hand-rolled `core/llm/contract.py` validator (568 lines of
tests, including a 20-payload hostile-input battery: bidi-override rejection, dismissal-language
filtering, unified-diff structural checks) already does everything a generic Pydantic model would
plus protections a plain schema wouldn't express. Rewriting it to Pydantic purely to match the
plan's wording would have risked regressing exactly those protections for no behavioral gain --
deliberately not done. The repair attempt (the actually new, valuable half of that plan line) was
built. Full reasoning in ADR-0026.

## Verified

- 1151 backend tests passing (up from 1117: 34 new, across `test_llm.py`, `test_llm_cache.py`, a new
  `test_llm_gateway.py`, and `test_api_suggestions.py`), 2 skipped (unrelated), 94.3% coverage;
  ruff/black/mypy all clean (`mypy core api`).
- The migration's up/down/up cycle and RLS isolation check, above, against a real Postgres container.
- The promptfoo suite's own real run against a real local model, above.
- `bulwark llm status`, `bulwark llm suggest`, and `bulwark llm suggest --privacy` were all run for
  real against this session's real local Ollama server and a real (deliberately invalid, to prove
  the refusal) hosted-key-plus-privacy-mode combination.

## What this does NOT prove (read before relying on it)

- **No MLX backend was built.** The plan names "Ollama or MLX"; only Ollama was built. See
  ADR-0026's "Decisions" section for why, and what would need to change to add MLX later.
- **No new frontend screen.** The plan lists no UI screen for Week 41 (unlike Week 39's policy
  editor or Week 40's Dependencies screen); the existing "Generate AI suggestion" button already
  surfaces whatever message a `429` carries, but it is not itself budget-aware (no usage meter, no
  "X of Y tokens used this month" display). That would be new frontend work, not done here.
- **Token budgets were validated by unit test and by reading the migration's live RLS behavior, not
  by running a real, sustained multi-scan load against a live API + Postgres + real model calls
  concurrently.** The check-before/record-after race window is reasoned about and documented, not
  measured under real concurrent load.
- **Fix quality against a real model is still formally unmeasured** (Week 14's blinded evaluation).
  The promptfoo run above is a schema-conformance smoke test that happened to also surface a real
  small model's real shortcomings -- informative, but not that measurement. See
  `docs/llm-remediation.md`'s own "What this does NOT prove" section, updated this week.
- **PII redaction's actual recall/precision on real code was not measured.** Presidio was run once,
  live, against a synthetic sentence with a name/email/phone/IP/credit-card, and correctly redacted
  all of them (confirmed manually) -- this proves the wiring works, not that it reliably catches PII
  in real, messy source code and comments.
