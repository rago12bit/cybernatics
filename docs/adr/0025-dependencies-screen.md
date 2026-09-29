# ADR-0025: Dependencies screen — hosted SBOM/supply-chain integration

Status: Implemented (2026-09-30), a follow-up to ADR-0024's supply-chain risk mechanism, which
explicitly deferred this: "The data it would render is real and already tested... this is a
rendering problem, not a data problem." This closes that gap end to end: pipeline, persistence,
API, and a real frontend screen.

## Context

ADR-0024 built the supply-chain risk *mechanism* (SBOM parsing, typosquat detection, Scorecard
enrichment, the dependency graph) as pure library code, reachable only via CLI commands. Nothing
persisted it, no API served it, and no page rendered it — `core/sbom/enrich.py`'s own docstring said
so outright: "the hosted pipeline does not yet run Syft as part of a scan." This closes that gap: an
organization opts a hosted scan into `syft`, and the result shows up as its own screen alongside
Issues/Compare, the same way every other piece of scan data already does.

## Decision

### One toggle for the whole feature area, reusing the existing per-scan tool mechanism

There is no feature-flag mechanism anywhere in this schema (`Asset`/`Scan` carry no settings
columns) — the existing, consistent way every other optional tool (grype, checkov, gosec, dockle)
opts in is `Scan.tools`. `core/sbom/syft.py::SyftAdapter` is now registered in `core/scan.py`'s
`ADAPTERS` under `"syft"`, selectable exactly like any other tool from the API (`ScanRequest.tools`)
or the web UI's own scan-creation form. Opting "syft" in gets the SBOM artifact *and* typosquat
detection *and* Scorecard enrichment as one bundle (`core/pipeline.py::_process_sbom`) — not three
separate flags, matching how the plan frames "supply-chain risk" as one feature, not three.

`SyftAdapter` needed one override: the base `ToolAdapter.applies_to` default
(`ctx.languages & spec.languages`) is always false for it, since Syft catalogs manifests/lockfiles,
not source files in `core.adapters`'s "language" sense — without the override, opting "syft" in
would have silently run it on nothing, on every repo.

### The raw SBOM reuses the existing artifact mechanism; the summary is one JSON column, not a table

Two different things needed persisting, so they got two different treatments, matching what each
one actually needs:

- **The raw CycloneDX document**: Syft runs through the exact same per-tool loop as every other
  scanner in `core/pipeline.py::_run_scan_job` (a `ToolOutcome` with `raw` bytes), so it already gets
  a `ToolRun` row and an `ObjectStore` artifact (`_store_raw`) for free — zero new schema.
- **The queryable summary** (every package's identity/license/relation/graph edges, Scorecard
  results): a new nullable `Scan.sbom_summary: JsonType` column (migration `0010`), not a normalized
  table. This matches `FindingRow.data`/`RemediationCache.payload`'s own "keep the full document,
  index only what needs server-side filtering" pattern — nothing about the Dependencies screen needs
  SQL-level pagination or filtering; it renders one scan's whole SBOM summary at once, the same way
  `ProjectOverview` renders several pre-assembled pieces in one response. A typical SBOM is hundreds,
  not hundreds of thousands, of packages.
- **Typosquat findings**: `find_typosquats()` already returns ordinary `Finding`s (`Category.SCA`,
  `evidence.reported_by = ["bulwark-typosquat"]`), so they are folded into the same
  `correlate`/`finalize`/`repo.add_findings` pipeline as every other tool's — they get fingerprints,
  Issue tracking, and show up in the existing Issues table with no new code there at all. No parallel
  table for these either.

### Best-effort at every layer, matching the tools loop's own "a dying tool is data" principle

`core/pipeline.py::_process_sbom` catches `SbomError` (a corrupt or malformed Syft document) and a
Scorecard/deps.dev failure separately, logging and degrading (`sbom_summary = None`, or an empty
Scorecard map) rather than failing the whole scan — the same discipline the per-tool loop already
applies to a scanner that crashes. `repo.set_sbom_summary` treats `None` as "leave the column
unset," never a fabricated empty summary.

### The API endpoint mirrors `/assets/{id}/issues` exactly: empty, not 404

`GET /assets/{asset_id}/dependencies` (`api/schemas.py::DependenciesView`) follows the identical
shape `/assets/{id}/issues` already established: look up the asset's latest scan, and if there is
none (or it never populated `sbom_summary`), return an empty view rather than a 404 — a project that
simply hasn't opted into `syft` yet is a normal, expected state, not an error.

### The frontend needed a graph, but not a graph library

No graph/tree-visualization library exists anywhere in this codebase (confirmed: no d3, react-flow,
dagre, cytoscape). Adding one for a single screen was a bigger commitment than the actual need:
`Sbom.graph` is a small tree/DAG (roots → direct → transitive), and "which path pulls in this
package" only needs a shortest-path walk, not force-directed layout. `web/components/
DependenciesView.tsx` implements `pathTo()` client-side — the same BFS `core.supplychain.
dependency_view.path_to` runs server-side — over the graph edges the one API response already
carries (`DependencyPackage.depends_on`), rendered as an expandable per-row detail (path breadcrumb,
direct children, Scorecard checks) rather than a drawn graph. This is a deliberately smaller
commitment than a full graph-drawing library for what plan §20.5 actually asks for.

The page reuses every existing frontend convention rather than introducing new ones: the same
`TokenGate`/`AppShell`/thin-server-component-plus-client-component shape every other project page
uses, the same plain-`fetch`-in-`useEffect` data pattern (`lib/api.ts::getDependencies`), and adds
itself to `ProjectOverview`'s existing crumbline the same way "compare scans" was added — no new nav
component invented for one more link.

## Consequences

- Supply-chain risk is now a real, persisted, navigable feature for hosted scans, not only a CLI
  workflow — an organization ticks one box on a new scan and the Dependencies screen has real data.
- The SBOM/Scorecard/typosquat mechanism itself is unchanged from ADR-0024; this is entirely
  plumbing (pipeline → persistence → API → frontend) on top of it.
- The next real gap, if this feature area grows further, is a drawn dependency graph (not just the
  expandable-row path view) — deliberately not built here, the same "defer the fancier UI, ship the
  real mechanism" shape ADR-0023's policy editor and this ADR's own predecessor both used.
