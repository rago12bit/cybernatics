"""Orchestrates attack-path graph construction for one asset (plan §21.6): fetches the asset's
open issues (`core.persistence.repo.list_asset_issues`, paginated), builds nodes and edges via
`core.attackpath.rules`, then ranks and picks a cheapest link per path. Takes an already-built
`CodeGraph` rather than cloning/analyzing itself -- the API layer owns wiring a checkout, the same
way `core.copilot.session.CheckoutCache` already does, so this stays pure and unit-testable without
a git checkout.

One AttackPath per rule match: Task 1 does not yet combine two rules' outputs into a single longer
chain (e.g. an SSRF path continuing on into a secret-grants-resource path) -- a disclosed scope
boundary, not an oversight, tracked in docs/v2-week45-verification.md.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from core.attackpath.model import AttackPath, Impact, Likelihood, NodeKind, PathEdge, PathNode
from core.attackpath.rules import (
    ci_secret_workflow,
    secret_grants_resource,
    ssrf_reachable_from_entrypoint,
)
from core.codeintel.models import CodeGraph
from core.models import Category, Finding, Severity, finding_from_dict
from core.persistence import repo

_PAGE_SIZE = 200
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_IMPACT_BY_SEVERITY = {
    Severity.CRITICAL: Impact.CRITICAL,
    Severity.HIGH: Impact.HIGH,
    Severity.MEDIUM: Impact.MEDIUM,
    Severity.LOW: Impact.LOW,
    Severity.INFO: Impact.LOW,
}
_IMPACT_WEIGHT = {Impact.LOW: 1, Impact.MEDIUM: 2, Impact.HIGH: 3, Impact.CRITICAL: 4}
_LIKELIHOOD_WEIGHT = {Likelihood.LOW: 1, Likelihood.MEDIUM: 2, Likelihood.HIGH: 3}


def _all_issue_findings(
    s: Session, asset_id: str, latest_scan_id: str
) -> list[tuple[str, Finding]]:
    """Every open issue's Finding, reconstructed from `FindingRow.data` via `finding_from_dict`
    (`Finding.to_dict`'s inverse) -- the same round-trip `core.persistence.repo` already uses for
    the issue detail screen (`get_issue_finding`), just for every issue instead of one."""
    out: list[tuple[str, Finding]] = []
    offset = 0
    while True:
        page = repo.list_asset_issues(
            s, asset_id, latest_scan_id, sort="path", limit=_PAGE_SIZE, offset=offset
        )
        for d in page.items:
            issue = d.get("issue")
            if not issue or not issue.get("id"):
                continue
            out.append((issue["id"], finding_from_dict(d)))
        if offset + _PAGE_SIZE >= page.total:
            break
        offset += _PAGE_SIZE
    return out


def _impact_for(*findings: Finding) -> Impact:
    best = Severity.INFO
    for f in findings:
        if _SEVERITY_ORDER.index(f.scoring.normalized_severity) > _SEVERITY_ORDER.index(best):
            best = f.scoring.normalized_severity
    return _IMPACT_BY_SEVERITY[best]


def _cheapest_link(nodes: list[PathNode]) -> str:
    """The node whose remediation would disconnect the chain. No fix-effort estimate exists in
    this codebase, so this is a disclosed, deterministic proxy: prefer a SECRET node (rotating a
    credential is a cheap, always-correct first move) over an ordinary ISSUE node, and never a
    synthetic or entrypoint node (nothing to remediate there)."""
    secrets = [n for n in nodes if n.kind is NodeKind.SECRET]
    if secrets:
        return secrets[0].id
    issues = [n for n in nodes if n.kind is NodeKind.ISSUE]
    if issues:
        return issues[0].id
    remediable = [n for n in nodes if n.issue_id is not None]
    return remediable[0].id if remediable else nodes[0].id


def _build_path(
    asset_id: str,
    nodes: list[PathNode],
    edges: list[PathEdge],
    likelihood: Likelihood,
    findings_for_impact: tuple[Finding, ...],
) -> AttackPath:
    node_t, edge_t = tuple(nodes), tuple(edges)
    impact = _impact_for(*findings_for_impact)
    return AttackPath(
        id=AttackPath.compute_id(asset_id, node_t, edge_t),
        asset_id=asset_id,
        nodes=node_t,
        edges=edge_t,
        likelihood=likelihood,
        impact=impact,
        rank_score=float(_LIKELIHOOD_WEIGHT[likelihood] * _IMPACT_WEIGHT[impact]),
        cheapest_link=_cheapest_link(nodes),
    )


def find_attack_paths(
    s: Session, asset_id: str, latest_scan_id: str, graph: CodeGraph
) -> list[AttackPath]:
    """Every attack path this asset's current open issues chain into, ranked highest risk first."""
    issue_findings = _all_issue_findings(s, asset_id, latest_scan_id)
    secrets = [(iid, f) for iid, f in issue_findings if f.taxonomy.category is Category.SECRETS]
    iac = [(iid, f) for iid, f in issue_findings if f.taxonomy.category is Category.IAC]

    paths: list[AttackPath] = []

    for issue_id, finding in issue_findings:
        nodes, edges = ssrf_reachable_from_entrypoint(graph, issue_id, finding)
        if edges:
            paths.append(_build_path(asset_id, nodes, edges, Likelihood.HIGH, (finding,)))

    for secret_id, secret_finding in secrets:
        for resource_id, resource_finding in iac:
            nodes, edges = secret_grants_resource(
                secret_id, secret_finding, resource_id, resource_finding
            )
            if edges:
                impact_findings = (secret_finding, resource_finding)
                paths.append(
                    _build_path(asset_id, nodes, edges, Likelihood.MEDIUM, impact_findings)
                )
            nodes, edges = ci_secret_workflow(
                secret_id, secret_finding, resource_id, resource_finding
            )
            if edges:
                impact_findings = (secret_finding, resource_finding)
                paths.append(
                    _build_path(asset_id, nodes, edges, Likelihood.MEDIUM, impact_findings)
                )

    paths.sort(key=lambda p: p.rank_score, reverse=True)
    return paths
