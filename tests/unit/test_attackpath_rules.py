from __future__ import annotations

from core.attackpath.model import EdgeKind, NodeKind
from core.attackpath.rules import (
    ci_secret_workflow,
    secret_grants_resource,
    ssrf_reachable_from_entrypoint,
)
from core.codeintel.models import CallEdge, CodeGraph, Entrypoint, Symbol
from core.models import Category, Evidence, Finding, Location, Scoring, Taxonomy


def _finding(category: Category, path: str, line: int, *, cwe=(), title="", rule_ids=None) -> Finding:
    return Finding(
        id=f"f-{path}-{line}",
        title=title or path,
        description="",
        location=Location(path, line, line, "snippet"),
        taxonomy=Taxonomy(category, cwe=cwe),
        scoring=Scoring(),
        evidence=Evidence(rule_ids=rule_ids or {}),
    )


def _graph_with_chain() -> CodeGraph:
    # ep1 (entrypoint) -> helper -> sink (SSRF finding lands here)
    ep1 = Symbol("ep1", "app.py", "handler", "app.handler", "function", 1, 5, "python")
    helper = Symbol("helper", "app.py", "helper", "app.helper", "function", 10, 15, "python")
    sink = Symbol("sink", "app.py", "sink", "app.sink", "function", 20, 25, "python")
    edges = [
        CallEdge("ep1", "helper", 3, callee_id="helper"),
        CallEdge("helper", "sink", 12, callee_id="sink"),
    ]
    entrypoints = [Entrypoint(symbol_id="ep1", framework="fastapi", method="GET", path="/preview")]
    return CodeGraph(
        symbols={"ep1": ep1, "helper": helper, "sink": sink},
        edges=edges,
        entrypoints=entrypoints,
        all_symbols=(ep1, helper, sink),
    )


def test_ssrf_reachable_from_entrypoint_connects_when_reachable():
    graph = _graph_with_chain()
    finding = _finding(Category.SAST, "app.py", 22, cwe=("CWE-918",), title="SSRF")
    nodes, edges = ssrf_reachable_from_entrypoint(graph, "iss1", finding)
    assert {n.kind for n in nodes} == {NodeKind.ISSUE, NodeKind.CLOUD_RESOURCE}
    kinds = {e.kind for e in edges}
    assert kinds == {EdgeKind.REACHABLE_FROM, EdgeKind.EXPOSES}
    reach_edges = [e for e in edges if e.kind is EdgeKind.REACHABLE_FROM]
    assert reach_edges[0].source == "ep_ep1"


def test_ssrf_rule_ignores_non_ssrf_cwe():
    graph = _graph_with_chain()
    finding = _finding(Category.SAST, "app.py", 22, cwe=("CWE-89",), title="SQLi")
    nodes, edges = ssrf_reachable_from_entrypoint(graph, "iss1", finding)
    assert nodes == [] and edges == []


def test_ssrf_rule_no_edge_when_unreachable():
    graph = _graph_with_chain()
    # sink' has no callers at all -> not reachable from any entrypoint
    orphan = Symbol("orphan", "other.py", "orphan", "other.orphan", "function", 1, 5, "python")
    graph.symbols["orphan"] = orphan
    graph.all_symbols = (*graph.all_symbols, orphan)
    finding = _finding(Category.SAST, "other.py", 3, cwe=("CWE-918",), title="SSRF")
    nodes, edges = ssrf_reachable_from_entrypoint(graph, "iss1", finding)
    assert nodes == [] and edges == []


def test_secret_grants_resource_connects_cloud_flavored_secret():
    secret = _finding(
        Category.SECRETS, "config.py", 5, title="AWS Access Key ID",
        rule_ids={"gitleaks": ["aws-access-key-id"]},
    )  # fmt: skip
    resource = _finding(Category.IAC, "main.tf", 10, title="Public S3 bucket")
    nodes, edges = secret_grants_resource("sec1", secret, "res1", resource)
    assert len(nodes) == 2 and len(edges) == 1
    assert edges[0].kind is EdgeKind.GRANTS_ACCESS_TO
    assert edges[0].rule_id == "secret-grants-resource-v1"


def test_secret_grants_resource_ignores_non_cloud_secret():
    secret = _finding(
        Category.SECRETS, "config.py", 5, title="Generic API Key",
        rule_ids={"gitleaks": ["generic-api-key"]},
    )  # fmt: skip
    resource = _finding(Category.IAC, "main.tf", 10, title="Public S3 bucket")
    nodes, edges = secret_grants_resource("sec1", secret, "res1", resource)
    assert nodes == [] and edges == []


def test_ci_secret_workflow_connects_under_workflows_path():
    secret = _finding(Category.SECRETS, "config.py", 5, title="GitHub Token")
    workflow = _finding(Category.IAC, ".github/workflows/deploy.yml", 8, title="Insecure trigger")
    nodes, edges = ci_secret_workflow("sec1", secret, "wf1", workflow)
    assert len(nodes) == 2 and len(edges) == 1
    assert edges[0].rule_id == "ci-secret-workflow-v1"


def test_ci_secret_workflow_ignores_non_workflow_path():
    secret = _finding(Category.SECRETS, "config.py", 5, title="GitHub Token")
    resource = _finding(Category.IAC, "terraform/main.tf", 10, title="Some misconfig")
    nodes, edges = ci_secret_workflow("sec1", secret, "res1", resource)
    assert nodes == [] and edges == []
