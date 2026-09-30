# ADR-0030: Attack paths, threat model draft, and the LLM red-team suite

Status: Implemented (2026-09-30), Week 45 (plan §21.6/§21.7/§21.9), building on Week 44's copilot
(ADR-0029) and the code intelligence/taint infrastructure from Weeks 20-21 rather than inventing new
scanning or analysis passes.

## Context

Week 45 is three plan sections bundled into one week: §21.6 (a ranked attack-path graph chaining an
asset's own open issues into a narrative from entry point to impact), §21.7 (a deterministic
Mermaid data-flow diagram plus a STRIDE table, a starting point for a person's own threat-modeling
review, not an assessment), and §21.9 (a red-team suite proving the LLM-consuming features hold up
against adversarial content). All three deliberately reuse existing infrastructure rather than
building new detection: `core.codeintel`'s entrypoints and call graph, `core.taint.catalog`'s sink
patterns, and an adversarial payload corpus that had been sitting unused since an earlier week.

## Decisions

### The attack-path graph has exactly one verified rule and two disclosed heuristics

`ssrf_reachable_from_entrypoint` (`core/attackpath/rules.py`) is the one rule that is fully real: it
walks `CodeGraph.callers_of` backward from an SSRF finding's location to prove a public route can
reach it, then connects to a synthetic "cloud metadata service" node representing a well-documented
technique (SSRF against 169.254.169.254), not something any scanner reports directly.
`secret_grants_resource` and `ci_secret_workflow` are explicitly labelled heuristics in their own
docstrings: neither Checkov nor gitleaks output in this codebase records which specific credential
grants access to which specific resource, so "a cloud-flavored secret and an IAC issue both exist in
this asset" is the only real signal available, not a proven causal grant. Mixing verified and
heuristic rules under one `AttackPath.rank_score` was deliberately not smoothed over: `likelihood`
is `HIGH` only for the verified rule, `MEDIUM` for the heuristics, so the ranking itself discloses
the difference rather than presenting three rules as equally certain.

### One AttackPath per rule match; no multi-hop combination yet

A single rule application (e.g. entrypoint → SSRF issue → metadata service) becomes one `AttackPath`.
Combining two separately-matched rules into one longer chain (an SSRF path continuing on into a
secret-grants-resource path, say) is a real generalization this week does not attempt — a disclosed
scope boundary in `core/attackpath/service.py`'s own docstring, not an oversight.

### Narrative generation never gates the graph on a model being configured

Unlike the copilot (409 when no model is routed for its task), `GET /assets/{id}/attack-paths` and
`GET /assets/{id}/threat-model` both return their real, computed structure regardless of whether
`Task.ATTACK_PATH` has a client. The graph, the ranking, and the diagram are useful and correct on
their own; the model-written narrative is strictly additive. `core/attackpath/contract.py` enforces
this at the content level too: a narrative must mention every node's label it was given (plan §21.6:
"the graph is the source of truth; the narrative only describes it"), checked by string containment,
not by re-deriving the graph from the prose.

### The threat model draft makes no model call at all

`core/threatmodel/generate.py` is pure, deterministic computation: entrypoints become DFD processes,
a `sql_injection`-category sink (per `core.taint.catalog`) reachable from a route implies a Database
node, a `command_injection`-category sink implies an OS-process node — the exact same sink patterns
the taint engine already uses for vulnerability detection, reused for a different question (which
external systems exist) rather than reimplemented. The STRIDE table is a fixed set of starter
questions per element kind, not a model's per-project judgment, matching the plan's explicit framing
as "a starting point for a person, not an assessment." One current row per asset (`asset_id` is the
primary key), editable, with an explicit `/regenerate` that discards edits rather than a background
job silently overwriting them — verified live against a real disposable Postgres container that
org-a and org-b are isolated on `threat_models` via `bulwark_app` (not a superuser).

### The red-team suite is deterministic-only; garak is deferred, not faked

Wiring up `garak` (or any live-model probing) needs a real API key, real spend on every scheduled
run, and produces a result that can differ between runs — none of which a hardcoded "attack success
rate" would honestly represent. `tests/redteam/` instead runs the 20-payload adversarial corpus
(`tests/fixtures/injection_payloads.json`, curated in an earlier week, never wired into a test until
now) against the real fix/triage/copilot pipelines with worst-case *compliant* fake models, proving
the architectural guarantees hold even when a model is fully fooled. This caught a real bug during
development: `core/llm/prompt.py` and `core/triage_assistant/prompt.py` scrubbed secrets from a
finding's `code` block but never from its `title`/`description`, fixed in the same change. No new CI
job was needed — `pyproject.toml`'s `testpaths` already picks up the new directory, so the suite runs
on every push and pull request now, exceeding the plan's "nightly."
