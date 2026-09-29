"""core/sbom/syft.py: parsing a real CycloneDX document into SbomPackages and a direct/transitive
dependency graph (plan §20.5). The fixture below is not invented -- it is `bulwark/syft:1.52.0`'s
own real output (trimmed) from scanning a two-level npm project (`once` depends on `wrappy`),
captured while validating this feature, so the shapes (bom-ref vs purl, `syft:location:0:path`
properties, the `dependencies[].dependsOn` graph) are exactly what Syft actually emits."""

from __future__ import annotations

import json

from core.sbom.syft import Sbom, SbomError, summarize

RAW = json.dumps(
    {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "bom-ref": "pkg:npm/once@1.4.0?package-id=3f85171a571bc28a",
                "type": "library",
                "name": "once",
                "version": "1.4.0",
                "licenses": [{"license": {"id": "ISC"}}],
                "purl": "pkg:npm/once@1.4.0",
                "properties": [{"name": "syft:location:0:path", "value": "/package-lock.json"}],
            },
            {
                "bom-ref": "pkg:npm/syft_test2@1.0.0?package-id=afe29bc1f6cfdb43",
                "type": "library",
                "name": "syft_test2",
                "version": "1.0.0",
                "licenses": [{"license": {"id": "ISC"}}],
                "purl": "pkg:npm/syft_test2@1.0.0",
                "properties": [{"name": "syft:location:0:path", "value": "/package-lock.json"}],
            },
            {
                "bom-ref": "pkg:npm/wrappy@1.0.2?package-id=3d054461229ae629",
                "type": "library",
                "name": "wrappy",
                "version": "1.0.2",
                "purl": "pkg:npm/wrappy@1.0.2",
                "properties": [{"name": "syft:location:0:path", "value": "/package-lock.json"}],
            },
            {
                "bom-ref": "fd71c2238fc07657",  # a plain file component, no purl -- must be ignored
                "type": "file",
                "name": "/src/package-lock.json",
            },
        ],
        "dependencies": [
            {
                "ref": "pkg:npm/once@1.4.0?package-id=3f85171a571bc28a",
                "dependsOn": ["pkg:npm/wrappy@1.0.2?package-id=3d054461229ae629"],
            },
            {
                "ref": "pkg:npm/syft_test2@1.0.0?package-id=afe29bc1f6cfdb43",
                "dependsOn": ["pkg:npm/once@1.4.0?package-id=3f85171a571bc28a"],
            },
        ],
    }
).encode()


def test_summarize_counts_components_and_ecosystems() -> None:
    sbom = summarize(RAW)
    assert sbom.components == 4
    assert sbom.ecosystems == {"npm": 3}  # the plain "file" component has no purl, so is excluded


def test_summarize_builds_sbom_packages_with_license_and_location() -> None:
    sbom = summarize(RAW)
    by_name = {p.name: p for p in sbom.packages}
    assert set(by_name) == {"once", "syft_test2", "wrappy"}
    assert by_name["once"].license == "ISC"
    assert by_name["once"].path == "package-lock.json"  # leading "/" stripped
    assert by_name["wrappy"].license == ""  # no licenses[] at all -- absent, not fabricated
    assert by_name["once"].ecosystem == "npm"


def test_direct_and_transitive_purls_come_from_the_real_dependency_graph() -> None:
    sbom = summarize(RAW)
    assert sbom.direct_purls == {"pkg:npm/once@1.4.0"}  # what the project's own package depends on
    assert sbom.transitive_purls == {"pkg:npm/wrappy@1.0.2"}  # only reachable through "once"
    assert sbom.roots == {"pkg:npm/syft_test2@1.0.0"}


def test_graph_lets_a_caller_walk_from_root_to_any_purl() -> None:
    sbom = summarize(RAW)
    assert sbom.graph["pkg:npm/syft_test2@1.0.0"] == ("pkg:npm/once@1.4.0",)
    assert sbom.graph["pkg:npm/once@1.4.0"] == ("pkg:npm/wrappy@1.0.2",)


def test_a_manifest_with_no_dependency_graph_yields_empty_direct_and_transitive_sets() -> None:
    """A bare, unlocked manifest has no resolved tree for Syft to report -- absent graph data,
    never a fabricated "everything is direct"."""
    raw = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"bom-ref": "pkg:pypi/flask@0.12", "name": "flask", "version": "0.12",
                 "purl": "pkg:pypi/flask@0.12"}
            ],
        }
    ).encode()  # fmt: skip
    sbom = summarize(raw)
    assert sbom.direct_purls == frozenset()
    assert sbom.transitive_purls == frozenset()
    assert sbom.roots == frozenset()


def test_license_expression_form_is_read_too() -> None:
    raw = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "bom-ref": "a",
                    "name": "ahash",
                    "version": "0.8.12",
                    "purl": "pkg:cargo/ahash@0.8.12",
                    "licenses": [{"expression": "MIT OR Apache-2.0"}],
                }
            ],
        }
    ).encode()
    sbom = summarize(raw)
    assert sbom.packages[0].license == "MIT OR Apache-2.0"


def test_not_cyclonedx_raises_sbom_error() -> None:
    for bad in (b"", b"not json", b"{}", b'{"bomFormat": "SPDX"}'):
        try:
            summarize(bad)
            raise AssertionError("expected SbomError")
        except SbomError:
            pass


def test_summarize_returns_an_sbom() -> None:
    assert isinstance(summarize(RAW), Sbom)
