"""core/sbom/enrich.py: joining an SBOM's own package licenses onto findings before policy
evaluation (plan §20.5) -- the piece `core.policy.input.issue_document`'s `license` field was
always waiting for."""

from __future__ import annotations

from core.sbom.enrich import apply_licenses, license_map
from core.sbom.syft import Sbom, SbomPackage


def _sbom(*packages: SbomPackage) -> Sbom:
    return Sbom(
        raw=b"", components=len(packages), spec_version="1.6", ecosystems={}, packages=packages
    )


def _finding(package: dict[str, object] | None) -> dict[str, object]:
    return {"id": "f1", "package": package}


def test_license_map_only_includes_packages_with_a_license() -> None:
    sbom = _sbom(
        SbomPackage("once", "1.4.0", "npm", "pkg:npm/once@1.4.0", license="ISC"),
        SbomPackage("wrappy", "1.0.2", "npm", "pkg:npm/wrappy@1.0.2"),  # no license
    )
    m = license_map(sbom)
    assert m == {("npm", "once", "1.4.0"): "ISC"}


def test_apply_licenses_enriches_a_matching_finding() -> None:
    sbom = _sbom(SbomPackage("once", "1.4.0", "npm", "pkg:npm/once@1.4.0", license="ISC"))
    findings = [_finding({"ecosystem": "npm", "name": "once", "version": "1.4.0"})]
    out = apply_licenses(findings, sbom)
    assert out[0]["package"]["license"] == "ISC"
    assert findings[0]["package"] == {
        "ecosystem": "npm",
        "name": "once",
        "version": "1.4.0",
    }  # not mutated


def test_apply_licenses_normalizes_ecosystem_aliases_before_matching() -> None:
    sbom = _sbom(
        SbomPackage("flask", "0.12", "pypi", "pkg:pypi/flask@0.12", license="BSD-3-Clause")
    )
    findings = [_finding({"ecosystem": "pip", "name": "flask", "version": "0.12"})]
    assert apply_licenses(findings, sbom)[0]["package"]["license"] == "BSD-3-Clause"


def test_apply_licenses_leaves_a_package_the_sbom_has_no_license_for_unchanged() -> None:
    sbom = _sbom(SbomPackage("once", "1.4.0", "npm", "pkg:npm/once@1.4.0", license="ISC"))
    findings = [_finding({"ecosystem": "npm", "name": "unrelated", "version": "9.9.9"})]
    out = apply_licenses(findings, sbom)
    assert "license" not in out[0]["package"]


def test_apply_licenses_leaves_a_finding_with_no_package_unchanged() -> None:
    sbom = _sbom(SbomPackage("once", "1.4.0", "npm", "pkg:npm/once@1.4.0", license="ISC"))
    findings = [_finding(None)]
    assert apply_licenses(findings, sbom) == findings


def test_apply_licenses_never_overwrites_an_existing_license() -> None:
    sbom = _sbom(SbomPackage("once", "1.4.0", "npm", "pkg:npm/once@1.4.0", license="ISC"))
    findings = [
        _finding({"ecosystem": "npm", "name": "once", "version": "1.4.0", "license": "MIT"})
    ]
    assert apply_licenses(findings, sbom)[0]["package"]["license"] == "MIT"


def test_apply_licenses_is_a_no_op_when_the_sbom_has_no_licenses_at_all() -> None:
    sbom = _sbom(SbomPackage("once", "1.4.0", "npm", "pkg:npm/once@1.4.0"))
    findings = [_finding({"ecosystem": "npm", "name": "once", "version": "1.4.0"})]
    assert apply_licenses(findings, sbom) is findings  # short-circuit, not just equal
