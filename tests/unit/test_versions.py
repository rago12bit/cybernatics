"""Version order per ecosystem (core/versions.py), checked against each ecosystem's own
implementation: the fixtures are pairs compared by Maven 3.9.16's `ComparableVersion` and by npm's
`semver` 7.8.5, and PyPI goes through `packaging`, which is PEP 440's reference implementation."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.versions import VersionError, compare, key, parse_constraint

FIXTURES = Path(__file__).parent.parent / "fixtures" / "versions"


def _pairs(name: str) -> list[tuple[str, str, int]]:
    out = []
    for line in (FIXTURES / name).read_text().splitlines():
        if line.startswith("#"):
            continue
        a, b, sign = line.split("\t")
        out.append((a, b, int(sign)))
    return out


@pytest.mark.parametrize(
    ("fixture", "ecosystem"), [("maven-3.9.16.tsv", "maven"), ("semver-7.8.5.tsv", "npm")]
)
def test_order_agrees_with_the_ecosystems_own_implementation(fixture: str, ecosystem: str) -> None:
    pairs = _pairs(fixture)
    assert len(pairs) > 2000
    wrong = [(a, b, s) for a, b, s in pairs if compare(ecosystem, a, b) != s]
    assert wrong == []


def test_the_cases_that_differ_between_ecosystems() -> None:
    # Maven: 1 == 1.0 == 1-ga; alpha < release < sp; unknown qualifiers after sp
    assert compare("maven", "1", "1.0.0") == 0 and compare("maven", "1-ga", "1") == 0
    assert compare("maven", "2.17.0", "2.17.1") < 0 and compare("maven", "2.0-beta9", "2.0") < 0
    assert compare("maven", "1-sp", "1") > 0 and compare("maven", "1-foo", "1-sp") > 0
    assert compare("maven", "5.3.18.RELEASE", "5.3.18") == 0
    # PEP 440
    assert compare("pypi", "1.0rc1", "1.0") < 0 and compare("pypi", "1.0.post1", "1.0") > 0
    assert compare("pypi", "1.0", "1.0.0") == 0 and compare("pypi", "2!0.1", "99") > 0
    # Not PEP 440: setuptools' legacy order, before every PEP 440 version (as osv-scanner does)
    assert compare("pypi", "0.8.3ubuntu7.5", "0.0.1") < 0
    assert compare("pypi", "0.8.3ubuntu7.5", "0.9.3.5ubuntu3") < 0
    assert compare("pypi", "1.6.0-NA", "1.5.1") < 0 and compare("pypi", "latest", "0") < 0
    # semver: build metadata never orders; Go's v and +incompatible
    assert compare("npm", "1.0.0+a", "1.0.0+b") == 0
    assert compare("go", "v1.2.3", "1.2.3") == 0
    assert compare("go", "v2.0.0+incompatible", "v1.9.9") > 0
    assert compare("go", "v0.0.0-20210101000000-abcdef123456", "v0.0.1") < 0


def test_semver_is_read_as_leniently_as_osv_scanner_reads_it() -> None:
    """OSV's npm and Go data hold versions that are not strict semver; osv-scanner orders them
    (osv-scalibr's parser) and so does Bulwark, or the two would disagree on real advisories."""
    assert compare("npm", "4.17", "4.17.0") == 0 and compare("npm", "4.17", "4.17.21") < 0
    assert compare("go", "19.03.0", "19.3.0") == 0  # docker/cli's own tags
    assert compare("go", "2.62", "2.62.0") == 0 and compare("go", "2.62", "2.61.9") > 0
    assert compare("go", "9.6.0b1", "9.6.0") < 0  # a prerelease, missing its hyphen
    assert compare("npm", "1.0.0-rc.1+build", "1.0.0-rc.1") == 0


@pytest.mark.parametrize(
    ("ecosystem", "version"),
    [("cargo", "1.0.0"), ("nuget", "1.0.0"), ("pypi", ""), ("maven", ""), ("npm", ""),
     ("go", "x" * 300)],
)  # fmt: skip
def test_what_cannot_be_compared_says_so(ecosystem: str, version: str) -> None:
    with pytest.raises(VersionError):
        key(ecosystem, version)


def test_constraints() -> None:
    c = parse_constraint(">=2.0, <2.17.1")
    assert str(c) == ">=2.0,<2.17.1"
    assert c.check("maven", "2.14.1") and not c.check("maven", "2.17.1")
    assert not c.check("maven", "1.2")
    assert parse_constraint("2.17.0").check("maven", "2.17.0.0")
    assert parse_constraint("==1.0").terms == (("=", "1.0"),)
    assert parse_constraint("!=1.0").check("pypi", "1.1")
    for bad in ("", " , ", "<", "<1 2", "<1<2", ">1,>2,>3,>4,>5"):
        with pytest.raises(VersionError):
            parse_constraint(bad)
    with pytest.raises(VersionError):
        parse_constraint("<2").check("cargo", "1.0.0")  # not an ecosystem compared: no guess
