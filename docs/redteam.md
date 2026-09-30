# Red-team suite

Plan §21.9. Tests whether this project's own LLM-consuming features (`core.llm` fix suggestions,
`core.triage_assistant`, `core.hypotheses`, `core.copilot`) hold up against adversarial content
planted in scanned code, and whether their output contracts reject a malformed or manipulative
model reply. Lives at `tests/redteam/`, discovered automatically by the existing `test` CI job
(`pyproject.toml`'s `testpaths = ["tests"]` already covers it) -- it runs on every push and pull
request, not only nightly.

## The corpus

`tests/fixtures/injection_payloads.json`: 20 named payloads (prompt-injection variants, format
breakers, path-traversal bait, a fake credential, resource-exhaustion strings) curated in an earlier
week but never wired into a test suite until this one.

## What's tested, against real code (not mocks of it)

- **`test_contract_hardening.py`** -- every one of the 20 payloads, fed as a raw model reply
  directly to every contract that parses raw text (`core.llm.contract.parse_response`,
  `core.triage_assistant.contract.parse_response`, `core.attackpath.contract.validate_narrative`):
  none of them are valid replies under any schema, so all 60 combinations must be rejected.
- **`test_patch_confined_to_finding_file.py`** -- schema-*valid* replies (so the broad net above
  isn't doing the work for the wrong reason) that try, one adversarial detail at a time: redirecting
  a suggested patch outside the finding's file (absolute path, `..` traversal, a different real
  file), and arguing in otherwise-valid prose that the finding isn't real, or smuggling an extra
  `"severity"` field. Maps to the plan's "writes outside the patch" and "downgrades severity."
- **`test_severity_immutable_under_injection.py`** -- a worst-case *fully compliant* fake model that
  reads a suppression-style payload planted in scanned code and returns a legitimate
  `"likely_false_positive"` verdict (which `core.triage_assistant` is allowed to say -- that's the
  feature's purpose). Confirms the real `Finding` object's severity, taxonomy and triage state are
  byte-identical before and after, regardless of what the model said.
- **`test_copilot_tool_scope_and_unknown_tools.py`** -- an injected instruction naming a tool
  outside the copilot's five real schemas comes back as an ordinary error string, never executes or
  crashes; and `query_issues` never sees another asset's data even when the model's own tool-call
  arguments try to redirect it, because asset/org scope comes only from `CopilotContext` (fixed at
  conversation start), never from anything the model supplies. Maps to "calls disallowed tools" and
  "reaches another tenant's data."
- **`test_secrets_never_forwarded.py`** -- a real-looking AWS key planted in a finding's own title
  (not just its code). **This test caught a real bug**: `core/llm/prompt.py` and
  `core/triage_assistant/prompt.py` scrubbed secrets from the `code` block but never from
  `finding.title`/`.description`, so a secret-shaped string sitting in the title text would have
  reached the model untouched. Fixed in the same change that added this test (both files now scrub
  title/description the same way code already was) -- kept here as a permanent regression test, not
  removed once green.

## Disclosed gap: no live-model probing

The plan also calls for `garak` and a tracked attack success rate. Both assume a real model call:
garak's probes are meant to test whether the *model itself* resists persuasion, which a deterministic
test cannot measure, and "success rate" only means something for a run that can fail differently each
time. Wiring this up needs a real `ANTHROPIC_API_KEY` in CI, ongoing spend for every scheduled run,
and a decision about probe count/budget -- deliberately deferred rather than faked with a
hardcoded number. If it's picked up later, garak needs a custom generator plugin routing its
probes through `core.llm.client.AnthropicClient`, gated on the secret being present (skipped
otherwise, the same pattern this project already uses for every other optional live-model feature).

One related scenario this suite does *not* claim to structurally prevent: a fully-compliant model
choosing to recite its own system prompt back in free-text output (a `rationale`/`explanation`
field has no filter against echoing prompt text). The mitigating factor is that none of this
project's system prompts contain secrets or credentials -- only instructions -- so the impact of a
leak is low, not that leaking is architecturally blocked. That is a live-model behavioral question,
not one a contract validator can answer.
