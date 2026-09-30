"""Deterministic chaining rules connecting attack-path graph nodes (plan §21.6). Each rule is
versioned in its own rule_id (e.g. "ssrf-metadata-v1") so a path's provenance is always traceable
to one auditable rule, never an opaque model judgment.

`ssrf_reachable_from_entrypoint` (rule 1) is fully verified, not a heuristic: it walks
`core.codeintel`'s real call graph. The other two are heuristics over already-persisted data,
disclosed here and in docs/v2-week45-verification.md, not presented as certain:

  - `secret_grants_resource` (rule 2): connects a cloud-flavored secret to an IAC issue in the same
    asset by co-location alone. Neither Checkov nor gitleaks output in this codebase records which
    specific credential grants access to which specific resource (Checkov gives no resource-type
    field, gitleaks redacts the secret value) -- "both exist in this asset" is the only real signal
    available, not a proven grant.
  - `ci_secret_workflow` (rule 3): connects a secret to an IAC issue whose path is under
    `.github/workflows/`. Checkov auto-scans workflow files (no --framework restriction in
    core/adapters/checkov.py) so an IAC issue there is real, but this codebase has no parser for a
    workflow's trigger type -- this is a path-based proxy for a `pull_request_target`-triggered
    workflow, not actual trigger detection.
"""

from __future__ import annotations

from collections import deque

from core.attackpath.model import EdgeKind, NodeKind, PathEdge, PathNode
from core.attackpath.nodes import entrypoint_nodes, issue_node, symbol_at
from core.codeintel.models import CodeGraph
from core.models import Category, Finding

SSRF_CWE = "CWE-918"
_CLOUD_KEYWORDS = ("aws", "amazon", "gcp", "google cloud", "azure", "cloud")


def _cloud_flavored_secret(finding: Finding) -> bool:
    text = " ".join([finding.title, *finding.evidence.rule_ids.get("gitleaks", [])]).lower()
    return any(k in text for k in _CLOUD_KEYWORDS)


def _reachable_ancestors(graph: CodeGraph, start_symbol: str) -> set[str]:
    """Every symbol id that can reach `start_symbol` (including itself), via backward BFS over
    resolved call edges (`CodeGraph.callers_of`) -- plan §20.3's one-hop-at-a-time walk, run outward
    from the sink instead of from an entrypoint."""
    seen = {start_symbol}
    queue = deque([start_symbol])
    while queue:
        sym = queue.popleft()
        for caller in graph.callers_of(sym):
            if caller not in seen:
                seen.add(caller)
                queue.append(caller)
    return seen


def ssrf_reachable_from_entrypoint(
    graph: CodeGraph, issue_id: str, finding: Finding
) -> tuple[list[PathNode], list[PathEdge]]:
    """Rule 1: an SSRF issue reachable from a public route implies the cloud metadata service is
    reachable too -- a well-documented technique (SSRF against 169.254.169.254), not something any
    scanner here reports directly, so that node is synthetic and always the same fixed node."""
    if SSRF_CWE not in finding.taxonomy.cwe:
        return [], []
    symbol = symbol_at(graph, finding.location.path, finding.location.start_line)
    if symbol is None:
        return [], []
    upstream = _reachable_ancestors(graph, symbol)
    reaching = [ep for ep in graph.entrypoints if ep.symbol_id in upstream]
    if not reaching:
        return [], []

    reaching_ids = {f"ep_{ep.symbol_id}" for ep in reaching}
    ep_nodes = [n for n in entrypoint_nodes(graph) if n.id in reaching_ids]
    iss_node = issue_node(issue_id, finding)
    metadata_node = PathNode(
        id="res_cloud_metadata_service",
        kind=NodeKind.CLOUD_RESOURCE,
        label="Cloud metadata service (169.254.169.254)",
        detail=(
            "Synthetic: not reported by any scanner directly -- inferred from SSRF reachability."
        ),
    )
    edges = [
        PathEdge(EdgeKind.REACHABLE_FROM, f"ep_{ep.symbol_id}", iss_node.id, "ssrf-metadata-v1")
        for ep in reaching
    ]
    edges.append(PathEdge(EdgeKind.EXPOSES, iss_node.id, metadata_node.id, "ssrf-metadata-v1"))
    return [*ep_nodes, iss_node, metadata_node], edges


def secret_grants_resource(
    secret_id: str, secret_finding: Finding, resource_id: str, resource_finding: Finding
) -> tuple[list[PathNode], list[PathEdge]]:
    """Rule 2 (heuristic, see module docstring). Excludes `.github/workflows/` paths -- those are
    `ci_secret_workflow`'s (rule 3) more specific match, and without this exclusion the same
    secret+workflow pair would produce two redundant, overlapping paths under different rule ids."""
    if secret_finding.taxonomy.category is not Category.SECRETS:
        return [], []
    if resource_finding.taxonomy.category is not Category.IAC:
        return [], []
    if resource_finding.location.path.startswith(".github/workflows/"):
        return [], []
    if not _cloud_flavored_secret(secret_finding):
        return [], []
    secret_node = issue_node(secret_id, secret_finding)
    resource_node = PathNode(
        id=f"res_{resource_id}",
        kind=NodeKind.CLOUD_RESOURCE,
        label=resource_finding.location.snippet or resource_finding.title,
        issue_id=resource_id,
        detail=resource_finding.location.path,
    )
    edge = PathEdge(
        EdgeKind.GRANTS_ACCESS_TO, secret_node.id, resource_node.id, "secret-grants-resource-v1"
    )
    return [secret_node, resource_node], [edge]


def ci_secret_workflow(
    secret_id: str, secret_finding: Finding, workflow_issue_id: str, workflow_finding: Finding
) -> tuple[list[PathNode], list[PathEdge]]:
    """Rule 3 (heuristic, see module docstring): path-based proxy, not real trigger detection."""
    if secret_finding.taxonomy.category is not Category.SECRETS:
        return [], []
    if workflow_finding.taxonomy.category is not Category.IAC:
        return [], []
    if not workflow_finding.location.path.startswith(".github/workflows/"):
        return [], []
    secret_node = issue_node(secret_id, secret_finding)
    workflow_node = PathNode(
        id=f"res_{workflow_issue_id}",
        kind=NodeKind.CLOUD_RESOURCE,
        label=workflow_finding.location.snippet or workflow_finding.title,
        issue_id=workflow_issue_id,
        detail=workflow_finding.location.path,
    )
    edge = PathEdge(
        EdgeKind.GRANTS_ACCESS_TO, secret_node.id, workflow_node.id, "ci-secret-workflow-v1"
    )
    return [secret_node, workflow_node], [edge]
