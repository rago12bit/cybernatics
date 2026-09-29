"""core/supplychain/typosquat.py (plan §20.5): "flag a dependency whose name is within edit
distance 2 of a top package in its ecosystem... 'possible typosquat of requests'."."""

from __future__ import annotations

from core.models import Category, Severity
from core.sbom.syft import SbomPackage
from core.supplychain.typosquat import POPULAR_PACKAGES, find_typosquats


def test_popular_packages_seed_loaded_for_every_documented_ecosystem() -> None:
    for eco in ("pypi", "npm", "go", "cargo", "rubygems", "maven", "packagist", "nuget"):
        assert POPULAR_PACKAGES[eco], eco


def test_an_exact_popular_name_is_not_flagged() -> None:
    pkg = SbomPackage("requests", "2.31.0", "pypi", "pkg:pypi/requests@2.31.0")
    assert find_typosquats((pkg,)) == []


def test_an_unrelated_name_is_not_flagged() -> None:
    pkg = SbomPackage("totally-unrelated-package-name", "1.0.0", "pypi", "pkg:pypi/x@1.0.0")
    assert find_typosquats((pkg,)) == []


def test_a_transposition_of_a_popular_name_is_flagged() -> None:
    pkg = SbomPackage("reqeusts", "1.0.0", "pypi", "pkg:pypi/reqeusts@1.0.0")
    findings = find_typosquats((pkg,))
    assert len(findings) == 1
    f = findings[0]
    assert "requests" in f.title
    assert f.taxonomy.category is Category.SCA
    assert f.scoring.normalized_severity in (Severity.HIGH, Severity.MEDIUM)
    assert f.package is not None and f.package.name == "reqeusts"


def test_an_unrecognized_ecosystem_is_never_flagged() -> None:
    pkg = SbomPackage("anything", "1.0.0", "not-a-real-ecosystem", "pkg:x/anything@1.0.0")
    assert find_typosquats((pkg,)) == []


def test_a_single_character_typo_is_scored_higher_than_a_two_character_one() -> None:
    close = find_typosquats((SbomPackage("reqests", "1.0.0", "pypi", "pkg:pypi/reqests@1.0.0"),))
    far = find_typosquats((SbomPackage("reqeusts", "1.0.0", "pypi", "pkg:pypi/reqeusts@1.0.0"),))
    assert close and far
    assert close[0].scoring.confidence >= far[0].scoring.confidence


def test_ids_are_unique_and_stable() -> None:
    pkg = SbomPackage("reqeusts", "1.0.0", "pypi", "pkg:pypi/reqeusts@1.0.0")
    a = find_typosquats((pkg,))[0]
    b = find_typosquats((pkg,))[0]
    assert a.id == b.id
