# Attack paths

A ranked chain from an entry point through this project's own open issues to real impact, computed
from the current scan -- never a hypothetical scenario. Design reasoning in
[ADR-0030](adr/0030-attack-paths-threat-model-and-red-team.md); the honest verification record is in
[v2-week45-verification.md](v2-week45-verification.md).

## How a path is built

`core/attackpath/rules.py` has three deterministic chaining rules, each versioned by its own
`rule_id` so a path's provenance is always traceable:

| Rule | Verified or heuristic | What it connects |
|---|---|---|
| `ssrf-metadata-v1` | Verified -- walks the real call graph | An SSRF issue reachable from a public route -> the cloud metadata service |
| `secret-grants-resource-v1` | Heuristic -- co-location only | A cloud-flavored secret + an IAC issue in the same asset |
| `ci-secret-workflow-v1` | Heuristic -- path-based proxy | A secret + an IAC issue under `.github/workflows/` |

The heuristic rules are disclosed as such in their own docstrings: neither Checkov nor gitleaks
output in this codebase records which specific credential grants access to which specific resource,
so co-location is the only real signal available. `likelihood` reflects this -- `high` only for the
call-graph-verified rule, `medium` for the heuristics -- rather than presenting all three as equally
certain.

## Ranking and the cheapest link

Paths are ranked by `likelihood x impact` (impact from the highest severity issue in the chain).
`cheapest_link` names the one node whose remediation would disconnect the chain -- no fix-effort
estimate exists in this codebase, so it's a disclosed, deterministic proxy: a SECRET node (rotating
a credential is a cheap, always-correct first move) is preferred over an ordinary ISSUE node.

## The narrative

A model-written description of the path, generated per path, never gating the endpoint: the graph
itself is always real and returned even with no model configured. The narrative's own contract
(`core/attackpath/contract.py`) requires it to mention every node's label it was given -- "the graph
is the source of truth; the narrative only describes it" -- rejected and retried once otherwise.

## Turning the narrative on

```bash
export BULWARK_LLM_ENABLED=1
export BULWARK_LLM_API_KEY=...
export BULWARK_LLM_ROUTE_ATTACK_PATH=hosted   # optional: this task's own route
```

Without it, `GET /assets/{id}/attack-paths` still returns every path with `narrative: null`.
