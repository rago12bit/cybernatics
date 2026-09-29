"""Software bill of materials (CycloneDX 1.6) from Syft, run in the same sandbox as every scanner.

Syft lists what the project contains; it does not judge it. The SBOM is a separate artifact from the findings,
and `bulwark attest` can sign it. It is generated from the sanitized workspace, so installed dependency
directories (node_modules, virtualenvs) are not in it: lockfiles and manifests are.

`summarize()` also reshapes each component into a `SbomPackage` (plan §20.5: license compliance,
typosquat detection, and Scorecard all read package identity, license and purl from here) and
derives direct-versus-transitive dependency sets from CycloneDX's own `dependencies[].dependsOn`
graph -- real only when the lockfile format Syft read already recorded the tree (validated against
a real `bulwark/syft:1.52.0` run over an npm project with a committed `package-lock.json`: Syft
does emit a full `ref -> dependsOn` graph there, keyed by bom-ref, which is a component's `purl`
plus a `?package-id=...` qualifier, not the bare purl -- hence the bom-ref-to-purl translation
below). A manifest with no lockfile has no such tree, so both sets are simply empty for it: absent
graph data, never a fabricated flat "everything is direct."
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.adapters.base import RepoContext, ToolAdapter, ToolSpec
from core.models import Finding, Package
from core.runner import run_tool

SYFT_IMAGE = "bulwark/syft:1.52.0"
SPEC_VERSION = "1.6"
MAX_SBOM_BYTES = 200 * 1024 * 1024


class SbomError(RuntimeError):
    pass


class SyftAdapter(ToolAdapter):
    """Fits the runner's contract; produces a document, not findings."""

    spec = ToolSpec(
        name="syft",
        image=SYFT_IMAGE,
        categories=frozenset({"sbom"}),
        languages=frozenset(),
        timeout_seconds=600,
    )

    def __init__(self, source_name: str = "project") -> None:
        self.source_name = source_name

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "scan", f"dir:{target}",
            "--output", f"cyclonedx-json@{SPEC_VERSION}={output}",
            "--source-name", self.source_name,
            "--quiet",
        ]  # fmt: skip

    def parse(self, raw: bytes) -> list[Finding]:
        return []  # not a findings tool


@dataclass(frozen=True)
class SbomPackage:
    """One CycloneDX component, reshaped for Week 40's own checks: a stable identity
    (name/version/ecosystem, normalized the same way a `Finding.package` already is, so the two
    join onto each other), its purl (what Scorecard/deps.dev lookups key on), its declared license
    ("" when none is declared -- never a fabricated "unknown"), and the manifest/lockfile path Syft
    found it in, when Syft's own location metadata says so (also best-effort; absent for a
    component Syft has no on-disk location for)."""

    name: str
    version: str
    ecosystem: str
    purl: str
    license: str = ""
    path: str = ""


@dataclass(frozen=True)
class Sbom:
    raw: bytes
    components: int
    spec_version: str
    ecosystems: dict[str, int]
    packages: tuple[SbomPackage, ...] = ()
    direct_purls: frozenset[str] = frozenset()
    transitive_purls: frozenset[str] = frozenset()
    graph: dict[str, tuple[str, ...]] = field(
        default_factory=dict
    )  # purl -> the purls it depends on
    roots: frozenset[str] = frozenset()  # purls nothing else in the SBOM depends on


def _license_of(component: dict[str, Any]) -> str:
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("expression"):
            return str(entry["expression"])
        lic = entry.get("license") or {}
        if lic.get("id"):
            return str(lic["id"])
        if lic.get("name"):
            return str(lic["name"])
    return ""


def _location_of(component: dict[str, Any]) -> str:
    for prop in component.get("properties") or []:
        if prop.get("name") == "syft:location:0:path":
            return str(prop.get("value", "")).lstrip("/")
    return ""


def _dependency_graph(
    doc: dict[str, Any], bom_ref_to_purl: dict[str, str]
) -> tuple[frozenset[str], frozenset[str], dict[str, tuple[str, ...]], frozenset[str]]:
    edges: dict[str, list[str]] = {}
    targets: set[str] = set()
    for dep in doc.get("dependencies") or []:
        ref = str(dep.get("ref", ""))
        children = [str(c) for c in dep.get("dependsOn") or []]
        edges[ref] = children
        targets.update(children)
    root_refs = [ref for ref in edges if ref not in targets]
    direct_refs: set[str] = set()
    for root in root_refs:
        direct_refs.update(edges.get(root, []))
    transitive_refs: set[str] = set(direct_refs)
    queue = list(direct_refs)
    while queue:
        ref = queue.pop()
        for child in edges.get(ref, []):
            if child not in transitive_refs:
                transitive_refs.add(child)
                queue.append(child)
    transitive_refs -= direct_refs

    def to_purls(refs: Any) -> frozenset[str]:
        return frozenset(bom_ref_to_purl[r] for r in refs if r in bom_ref_to_purl)

    graph = {
        bom_ref_to_purl[ref]: tuple(to_purls(children))
        for ref, children in edges.items()
        if ref in bom_ref_to_purl
    }
    return to_purls(direct_refs), to_purls(transitive_refs), graph, to_purls(root_refs)


def summarize(raw: bytes) -> Sbom:
    """Validate the essentials of a CycloneDX document and count what is in it."""
    try:
        doc: Any = json.loads(raw)
        if doc["bomFormat"] != "CycloneDX" or not isinstance(doc.get("components", []), list):
            raise ValueError("not a CycloneDX document")
        eco: dict[str, int] = {}
        packages: list[SbomPackage] = []
        bom_ref_to_purl: dict[str, str] = {}
        for c in doc.get("components", []):
            purl = str(c.get("purl", ""))
            if not purl.startswith("pkg:"):
                continue
            kind = purl[4:].split("/", 1)[0]
            eco[kind] = eco.get(kind, 0) + 1
            bom_ref_to_purl[str(c.get("bom-ref", ""))] = purl
            packages.append(
                SbomPackage(
                    name=str(c.get("name", "")),
                    version=str(c.get("version", "")),
                    ecosystem=Package.normalize_ecosystem(kind),
                    purl=purl,
                    license=_license_of(c),
                    path=_location_of(c),
                )
            )
        direct, transitive, graph, roots = _dependency_graph(doc, bom_ref_to_purl)
        return Sbom(
            raw=raw,
            components=len(doc.get("components", [])),
            spec_version=str(doc.get("specVersion", "")),
            ecosystems=eco,
            packages=tuple(packages),
            direct_purls=direct,
            transitive_purls=transitive,
            graph=graph,
            roots=roots,
        )
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise SbomError(f"Syft output is not a valid CycloneDX document: {exc}") from exc


def generate_sbom(target: Path, source_name: str = "project") -> Sbom:
    """Run Syft on `target` (already a sanitized workspace). Raises SbomError with a readable reason."""
    result = run_tool(SyftAdapter(source_name[:200] or "project"), target)
    if result.status != "ok":
        detail = result.stderr.strip().splitlines()[-1:] or [result.status]
        raise SbomError(f"Syft did not produce an SBOM ({result.status}): {detail[0][:300]}")
    if len(result.raw) > MAX_SBOM_BYTES:
        raise SbomError("SBOM is unreasonably large")
    return summarize(result.raw)
