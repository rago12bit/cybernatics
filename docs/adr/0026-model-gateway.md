# ADR-0026: Model gateway and LLMOps

Status: Implemented (2026-09-30), Week 41 (plan §21.1), building on Week 12/13's LLM remediation
feature (ADR-0010) rather than replacing it.

## Context

Week 12/13 built one hardcoded provider (`core.llm.client.AnthropicClient`) behind an `LLMClient`
Protocol the rest of the code already depended on only through that interface (ADR-0010 §3 stated
provider-agnosticism as an intent, without a second provider to prove it). Nothing routed by task,
nothing tracked spend in tokens (only call *counts*, process-local), nothing removed personal data
before sending text off the machine, and there was no way to guarantee "this specific call never
leaves my machine" beyond simply not setting an API key. Week 41 closes those gaps: a real second
backend, per-task routing, token budgets, PII redaction, a path denylist, one schema-repair attempt,
and a versioned prompt with an evaluation suite gating changes to it.

## Decisions

### A gateway layer on top of `client.py`, not a rewrite of it

`core/llm/gateway.py` is the new single choke point for "which backend does this task use," sitting
above the existing `make_client()` (hosted) and the new `make_ollama_client()` (local,
`core/llm/ollama_client.py`) rather than merging them into one class. `client.py`'s existing
`AnthropicClient`/`LLMConfig` are untouched apart from the `Completion` return type below — every
existing call site that only ever used one hardcoded provider still works exactly as before if it
calls `make_client()` directly; only the two production call sites (the API's `build_default_app`,
the CLI's `llm suggest`) were moved onto the gateway.

`Task` is a real enum keyed by name (`Task.FIX`, the only member), not a hardcoded string, so Week
43's triage assistant and Week 44's copilot register their own routes later without changing this
module. The plan names "explanations" and "triage" as candidate per-task routes; neither has a
model-calling consumer yet, so no route was fabricated for either — inventing configuration for a
task nothing calls would be dead weight, not a real per-task routing story.

### Local backend: Ollama, not MLX

The plan says "Ollama or MLX." Ollama exposes a plain JSON HTTP API (`/api/chat`), needs no new
dependency (`core/llm/ollama_client.py` reuses the same `urllib.request` approach
`core.risk.feeds.http_get` already uses elsewhere in this codebase), and runs identically on any
platform with Docker. MLX is an Apple-Silicon-only in-process Python inference library with no
network surface at all — supporting it would mean a second, structurally different client
implementation (loading model weights in-process, not calling a server) for a platform-specific
gain the plan's own goal ("a local model, so the code never leaves the machine") doesn't need MLX
specifically to achieve. Validated against a real, live `ollama/ollama` container during
development (a real `qwen2.5:0.5b` pull, real HTTP calls, real token counts back) — this is real
prior art for a second backend if MLX is wanted later, not a stub.

### Privacy mode forces local and refuses, never silently falls back to hosted

`BULWARK_LLM_PRIVACY_MODE=1` (or `bulwark llm suggest --privacy`) overrides every task's route to
`Backend.LOCAL`, and `make_gateway_client` raises `PrivacyModeViolation` — loudly, at the call site,
never returning a hosted client instead — when no local backend is ready. A silent fallback would
quietly defeat the one guarantee privacy mode exists to make. Validated live: with a real (working)
hosted API key configured AND privacy mode on, the gateway still refuses rather than using the key.

### Token budgets: two tables, not one, because they have different lifetimes

`Scan.llm_tokens_used` (migration `0011`, a plain integer column, same "counter on the row it
describes" shape as `sbom_summary` in migration `0010`) tracks one scan's own spend. A new
`LlmUsage` table, keyed by `(org_id, period)`, tracks an organization's spend across every scan in a
calendar month — there is no single `Scan` row a month-spanning total could live on. `llm_usage`
gets `org_id` and Postgres RLS exactly like `assets`/`scans` (migration 0005), unlike `api_tokens`
(migration 0007), which deliberately has none: org context here is already known (a scan's own
`org_id`) before any read or write happens, unlike a token lookup, which is what *resolves* org
context in the first place.

Enforcement is check-before / record-after: `core.llm.budget.check()` refuses before a call if
either cap is already at or past its limit; `record()` adds the *real* token cost (from the
provider's own usage field, now on `LLMClient.complete`'s `Completion` return type) after a genuine,
non-cached call. This can overshoot by at most one call's worth of tokens under concurrent requests
— the same class of imprecision `UsageLimiter` (call-rate limiting, ADR-0010) and
`RemediationCache.hits`'s own non-atomic increment already accept elsewhere in this codebase. A
cache hit is free: `core.llm.cache._store` strips `tokens_used` from what gets cached, so replaying
a cached answer never re-reports (or re-charges) a token cost it didn't actually incur this time.

### Redaction: Presidio as a second, best-effort layer after `scrub_secrets`, path denylist as a third

`core/llm/pii.py` wraps Microsoft Presidio (`pip install 'bulwark-scan[pii]'`, plus a separate
`python -m spacy download en_core_web_sm` no pip extra can express) to catch free-text personal
data — names, emails, phone numbers — that `scrub_secrets`'s pattern-based scrubbing was never meant
to catch. It runs strictly after `scrub_secrets`, never before, so Presidio's NER models never see
raw key material. It is optional and lazy exactly like `AnthropicClient`: absent, or its language
model not downloaded, or any internal failure, all degrade to a no-op rather than blocking a
suggestion or crashing `suggest()` — confirmed by explicitly wiring `en_core_web_sm` rather than
trusting Presidio's own default, which downloads `en_core_web_lg` (~400MB) the first time it runs
with no config at all; that surprise was caught by actually running `AnalyzerEngine()` during this
feature's own development, not assumed.

`core/llm/pathguard.py` adds a third, independent layer: a small denylist (`.env`, `*.pem`,
`id_rsa*`, ...) checked against a finding's path before any code from it is even considered for
scrubbing or redaction — the same "withhold entirely" treatment `secrets`-category findings already
get, extended to any file whose *path* alone is reason enough, regardless of what a scanner's
category happened to label it.

### Structured-output validation: keep the hand-rolled contract, add the repair attempt

The plan says "Structured outputs validated with Pydantic: one repair attempt, then fall back to
static text." `core/llm/contract.py`'s existing hand-rolled validator already does everything a
generic Pydantic model would (required keys, types, lengths) *plus* hostile-input protections a
plain schema wouldn't express on its own (bidi-override rejection, control-character rejection, a
dismissal-language filter, unified-diff structural validation) — all covered by 568 lines of
existing tests, including a 20-payload hostile-input battery. Rewriting a security-hardened,
thoroughly tested validator to Pydantic purely to match the plan's wording would risk regressing
exactly the protections that matter here, for no behavioral gain. The genuinely new, valuable half
of that plan line — "one repair attempt" — is what got built: `core.llm.service.suggest` now makes
one additional call with a **fixed, generic** repair note
(`"Reply again with exactly the single JSON object..."`) on a `ContractError`, before falling back
to static text.

The repair note never echoes the rejected reply or the rejection reason back into the next prompt.
Both could carry model- or attacker-influenced text — the reply already failed validation, which is
exactly the trust boundary `prompt.py`'s nonce-fencing exists to police — so feeding either back in
would open a second-order injection channel the rest of this feature was built to avoid. Cost:
tokens from a failed contract check now count twice (original + repair) toward budgets, which
`core.llm.budget` accounts for by summing every real call's usage, not just the last one.

### Prompt registry: a real versioned file, moved under `core/llm/`, not repo-root `prompts/`

The plan's own example path is `prompts/fix/v3.md` (repo root). `pyproject.toml` only packages
`core*`/`cli*`/`api*` (`[tool.setuptools.packages.find]`) for a real `pip install` — a repo-root
`prompts/` directory would silently not exist outside a git checkout. `core/llm/prompts/fix/v1.md`
instead, declared in `[tool.setuptools.package-data]` exactly like `core.rag`'s own bundled corpus
(`core/rag/corpus/*.jsonl`), for the identical reason. `core/llm/prompt.py` now loads `SYSTEM` from
that file (`core.llm.prompt.load_prompt`) instead of an inline string constant; `PROMPT_VERSION`
still hashes the *loaded content*, not the "v1" label, so a cache-busting version change never
depends on someone remembering to bump a filename.

### Evaluation: promptfoo, driven through the real gateway, gated by the real contract validator

`core/llm/prompts/fix/promptfooconfig.yaml` is a real, runnable `promptfoo eval` suite — validated
during development against a live local Ollama container, not just written and assumed to work; two
real bugs were caught doing that (below). Its custom Python provider
(`promptfoo_provider.py`) calls `core.llm.gateway.make_gateway_client` directly, so an eval run
exercises the exact backend-selection code production uses. Its assertion
(`promptfoo_assert.py`) calls the real `core.llm.contract.parse_response` — the same validator
`suggest()` uses — rather than a second, divergence-prone reimplementation of the same rules, matching
the plan's own framing: "correctness is always decided by deterministic checks," not an LLM judge.
Fixtures (`fixtures/*.txt`) are pre-rendered *real* `build_prompt()` output
(`scripts/gen-promptfoo-fixtures.py` regenerates them), not hand-written approximations that could
drift from the real prompt format.

Two real integration bugs surfaced only by actually running this against a live model, not by
inspection:
- promptfoo's Python provider runs as a **persistent worker process**; an env var exported in the
  invoking shell *after* that worker starts does not reliably reach it. The provider's backend
  choice is therefore driven entirely by its own YAML `config:` block, not ambient `BULWARK_LLM_*`
  env vars, so an eval run is reproducible regardless of that.
- promptfoo itself reserves the provider config key `timeout` (milliseconds, its own per-call
  worker timeout) — a first draft that also used `timeout` for Ollama's own request timeout (seconds)
  silently fed a seconds-based number in as a millisecond cap, timing out every call after 90ms. The
  Ollama-side setting is `request_timeout_s` instead, with a comment at the collision site.

Running the suite against a real (small, local) model during development produced two real
contract-validator failures — the model wrapped its JSON in a fenced block in a shape the validator
correctly rejected — which is itself the intended outcome: the suite is a real gate that can fail a
real model's real output, not a suite that always trivially passes. Per `docs/llm-remediation.md`,
fix quality against a real model remains formally unmeasured (Week 14's evaluation pipeline,
unchanged by this ADR); this suite is a schema-conformance gate for prompt *changes*, not that
measurement.

## Consequences

- A hosted deployment is unaffected by default: `GatewayConfig.default_backend` is `hosted`, so
  behavior is identical to before this week unless an operator opts into local routing or privacy
  mode.
- Token budgets are best-effort, not byte-exact, under concurrency — documented, not hidden, and the
  same tolerance this codebase already accepted for call-count limiting.
- Presidio is optional; a deployment that never installs `bulwark-scan[pii]` (or never runs `python
  -m spacy download en_core_web_sm`) gets exactly Week 12's original secret-only scrubbing, silently
  — this is by design (best-effort, not a hard requirement to send text) but worth knowing before
  assuming PII redaction is active.
- MLX support, if ever wanted, has no code to build on here beyond the `Backend` enum itself — it
  would be a structurally different, in-process client, not an extension of `OllamaClient`.
- The Dependencies-screen-style "full hosted integration" question doesn't apply the same way here:
  this ships as backend/CLI plumbing only. No new frontend screen was built this week — the plan
  lists no screen deliverable for Week 41 (unlike, e.g., Week 39's policy editor or Week 40's
  Dependencies screen) — the existing "Generate AI suggestion" UI already surfaces whatever error
  message a 429 (rate or budget) carries; it isn't budget-aware beyond that.
