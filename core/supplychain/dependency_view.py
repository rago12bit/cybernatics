"""Which path in the dependency graph pulls in a package (plan §20.5's "dependency view"), built
entirely from the SBOM's own `dependencies` graph (`core.sbom.syft.Sbom.graph`/`.roots`) -- no new
data collection. "The smallest upgrade that fixes it" is a separate, more fundamental utility
(`core.scoring.versions.smallest_safe_upgrade`) shared with the adapters that already compute a
fixed-version list (osv-scanner, grype); it does not belong here.
"""

from __future__ import annotations

from collections import deque

from core.sbom.syft import Sbom


def path_to(sbom: Sbom, target_purl: str) -> tuple[str, ...] | None:
    """The shortest root-to-target path over the SBOM's own dependency graph, root first. `None`
    when the graph has no route to `target_purl` -- no relationship data for this manifest/ecosystem
    (a bare, unlocked manifest), or the purl is not in this SBOM at all."""
    if target_purl in sbom.roots:
        return (target_purl,)
    visited = set(sbom.roots)
    queue: deque[tuple[str, tuple[str, ...]]] = deque((r, (r,)) for r in sbom.roots)
    while queue:
        node, path = queue.popleft()
        for child in sbom.graph.get(node, ()):
            if child == target_purl:
                return (*path, child)
            if child not in visited:
                visited.add(child)
                queue.append((child, (*path, child)))
    return None


__all__ = ["path_to"]
