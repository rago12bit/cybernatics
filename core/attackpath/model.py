"""Attack-path graph data model (Week 45, plan §21.6).

A path is a chain of nodes connected by edges, built entirely from data this project already has:
`IssueRow`s (SAST/SCA/SECRETS/IAC, already persisted per asset) and the `TaintPathStep`s
`core.taint.reachability` already attaches to SAST findings at scan time. No new scanning or IaC
parsing is introduced here -- IAC misconfigurations already arrive as ordinary Checkov-sourced
Issues (`core/adapters/checkov.py`), and this module's job is only to connect existing Issues into
chains, the same way `core.correlation.engine` connects existing Findings into clusters (a
different relation -- "these are the same defect" vs. this module's "this defect leads to that
one" -- but the same "derive structure from what scanners already reported" shape).

Deterministic id: two chaining runs over the same underlying issues must produce the same path id,
so a path can be tracked across scans the way `IssueRow.fingerprint` tracks one issue -- see
`AttackPath.compute_id`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class NodeKind(str, Enum):
    ENTRYPOINT = "entrypoint"  # a route/handler `core.codeintel` found (public network entry)
    ISSUE = "issue"  # a SAST/SCA/IAC IssueRow
    SECRET = "secret"  # a SECRETS-category IssueRow
    CLOUD_RESOURCE = "cloud_resource"  # a resource identifier lifted from an IAC IssueRow


class EdgeKind(str, Enum):
    REACHABLE_FROM = "reachable_from"  # target is reachable from source (e.g. taint source->sink)
    GRANTS_ACCESS_TO = "grants_access_to"  # source's credential/role grants access to target
    EXPOSES = "exposes"  # source's misconfiguration exposes target


class Likelihood(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Impact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class PathNode:
    """One node in an attack path. `issue_id` is set for ISSUE/SECRET/CLOUD_RESOURCE nodes (points
    back at the `IssueRow` it was derived from); ENTRYPOINT nodes have none -- they come from
    `core.codeintel`'s route/handler data, not from an Issue."""

    id: str
    kind: NodeKind
    label: str
    issue_id: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class PathEdge:
    """One edge in an attack path. `rule_id` names the deterministic chaining rule that produced
    it (versioned, e.g. "ssrf-metadata-credential-theft-v1"), so a path's provenance is always
    traceable back to a specific, auditable rule rather than an opaque model judgment."""

    kind: EdgeKind
    source: str  # PathNode.id
    target: str  # PathNode.id
    rule_id: str


@dataclass(frozen=True)
class AttackPath:
    """A ranked chain from an entrypoint to an impact. `cheapest_link` is the id of the single
    node whose remediation would disconnect the chain -- usually the ISSUE node with the lowest
    fix effort, per plan §21.6."""

    id: str
    asset_id: str
    nodes: tuple[PathNode, ...]
    edges: tuple[PathEdge, ...]
    likelihood: Likelihood
    impact: Impact
    rank_score: float
    cheapest_link: str

    @staticmethod
    def compute_id(asset_id: str, nodes: tuple[PathNode, ...], edges: tuple[PathEdge, ...]) -> str:
        node_part = "|".join(n.id for n in nodes)
        edge_part = "|".join(f"{e.source}>{e.kind.value}>{e.target}:{e.rule_id}" for e in edges)
        digest = hashlib.sha256(f"{asset_id}::{node_part}::{edge_part}".encode()).hexdigest()
        return f"ap_{digest[:24]}"
