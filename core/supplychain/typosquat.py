"""Typosquat detection (plan §20.5): "flag a dependency whose name is within edit distance 2 of a
top package in its ecosystem... 'possible typosquat of requests'." This is a genuinely new
detection -- nothing else in Bulwark looks at a package's *name* on its own -- not an enrichment of
an existing finding, so it produces new `Finding`s directly from an SBOM's packages.

The reference set (`popular_packages.json`) is a small, hand-curated seed of well-known package
names per ecosystem, not a live popularity feed: unlike EPSS/KEV there is no single canonical "top
N packages per ecosystem" API to depend on. This is honestly a starting point -- the same way the
starter policy library's license rule shipped as real, tested code with nothing yet to match
against.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Package,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)
from core.sbom.syft import SbomPackage

POPULAR_PACKAGES_PATH = Path(__file__).parent / "popular_packages.json"


def _load_popular() -> dict[str, frozenset[str]]:
    doc = json.loads(POPULAR_PACKAGES_PATH.read_text())
    return {eco: frozenset(names) for eco, names in doc.items()}


POPULAR_PACKAGES = _load_popular()

_SEVERITY_BY_DISTANCE = {1: Severity.HIGH, 2: Severity.MEDIUM}
_CONFIDENCE_BY_DISTANCE = {1: 0.6, 2: 0.4}


def _edit_distance(a: str, b: str, cutoff: int) -> int:
    """Levenshtein distance, capped at `cutoff`: the caller only distinguishes 1 vs 2 vs "too far",
    so nothing beyond that needs to be exact."""
    if abs(len(a) - len(b)) >= cutoff:
        return cutoff
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return min(prev[-1], cutoff)


def _closest_popular(name: str, popular: frozenset[str]) -> tuple[str, int]:
    best_name, best_distance = "", 3
    for candidate in popular:
        if abs(len(candidate) - len(name)) >= best_distance:
            continue
        d = _edit_distance(name, candidate, best_distance)
        if d < best_distance:
            best_name, best_distance = candidate, d
    return best_name, best_distance


def find_typosquats(packages: tuple[SbomPackage, ...]) -> list[Finding]:
    """One Finding per SBOM package whose name is edit-distance 1 or 2 from a popular package in
    the same ecosystem and is not itself that name (an exact match is legitimate)."""
    out: list[Finding] = []
    for pkg in packages:
        popular = POPULAR_PACKAGES.get(pkg.ecosystem)
        if not popular or pkg.name in popular:
            continue
        best_name, best_distance = _closest_popular(pkg.name, popular)
        if best_distance not in _SEVERITY_BY_DISTANCE:
            continue
        text = f"{pkg.name}@{pkg.version}"
        location_path = pkg.path or f"{pkg.ecosystem}:{pkg.name}"
        out.append(
            Finding(
                id=f"typosquat:{pkg.ecosystem}:{pkg.name}:{pkg.version}",
                title=f"Possible typosquat: '{pkg.name}' is close to popular package '{best_name}'",
                description=(
                    f"'{pkg.name}' is edit-distance {best_distance} from '{best_name}', a popular "
                    f"{pkg.ecosystem} package. This may be an intentional look-alike name meant to "
                    "trick a typo, or a copy-pasted dependency list, into installing the wrong "
                    "package."
                ),
                location=Location(location_path, 1, 1, text, Location.hash_snippet(text)),
                taxonomy=Taxonomy(Category.SCA, aliases=(f"typosquat:{best_name}",)),
                scoring=Scoring(
                    normalized_severity=_SEVERITY_BY_DISTANCE[best_distance],
                    confidence=_CONFIDENCE_BY_DISTANCE[best_distance],
                ),
                evidence=Evidence(reported_by=["bulwark-typosquat"]),
                remediation=Remediation(
                    summary=f"Confirm this is really '{pkg.name}', not a typo of '{best_name}'.",
                    generated_by="static",
                ),
                package=Package(pkg.name, pkg.version, pkg.ecosystem),
            )
        )
    return out


__all__ = ["find_typosquats", "POPULAR_PACKAGES"]
