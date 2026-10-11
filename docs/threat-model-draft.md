# Threat model draft

A Mermaid data-flow diagram plus a STRIDE table, generated from code intelligence already computed
for this project -- explicitly a starting point for a person's own review, never an assessment.
Design reasoning in [ADR-0030](adr/0030-attack-paths-threat-model-and-red-team.md); the honest
verification record is in [v2-week45-verification.md](v2-week45-verification.md).

Not to be confused with [docs/THREAT-MODEL.md](../THREAT-MODEL.md), Bulwark's own security threat
model for itself as a tool running untrusted code -- a naming coincidence, unrelated infrastructure.

## How it's built -- no model call

`core/threatmodel/generate.py` makes no LLM call at all. Every `core.codeintel` entrypoint becomes a
diagram process; a `sql_injection`-category sink (`core.taint.catalog`, the same patterns the taint
engine already uses for vulnerability detection) reachable from that route via the real call graph
implies a Database node, and a `command_injection`-category sink implies an OS-process node. The
STRIDE table is a fixed set of starter questions per element kind (spoofing/tampering/repudiation/
information-disclosure/denial-of-service/elevation-of-privilege where each applies), not a model's
per-project judgment.

## Editable, and never silently overwritten

`GET /assets/{id}/threat-model` auto-generates a draft on first access (free, deterministic, so
there's no cost gate to ask for first) and persists it. A person can edit the Mermaid source or the
STRIDE table directly (`PUT`); their edit stays current until an explicit `POST .../regenerate`,
which discards it and rebuilds from the latest scan. `source` (`"generated"` | `"edited"`) and
`version` (a plain incrementing counter, not full history) tell a client which state it's looking at.

The web app draws the diagram in its own frame (`web/app/diagram-frame`): Mermaid's SVG needs inline
styles, which the app's Content-Security-Policy forbids, and without them the diagram rendered as black
boxes with invisible arrows. See T9 in [THREAT-MODEL.md](THREAT-MODEL.md).

One current row per asset, RLS via `assets` -- verified live against a real disposable Postgres
container that org-a and org-b are isolated on `threat_models`, connected as `bulwark_app` (not a
superuser), the same standard held for every other RLS table in this project.
