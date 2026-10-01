import json
from pathlib import Path

import pytest

from core.adapters import ToolAdapter
from core.adapters.bandit import BanditAdapter
from core.adapters.checkov import CheckovAdapter
from core.adapters.dockle import DockleAdapter
from core.adapters.gitleaks import GitleaksAdapter
from core.adapters.gosec import GosecAdapter
from core.adapters.grype import GrypeAdapter
from core.adapters.osv_scanner import OsvScannerAdapter
from core.adapters.semgrep import SemgrepAdapter
from core.adapters.trivy import TrivyAdapter
from core.models import Category, Finding, Package, Severity
from core.plugins.conformance import (
    assert_findings_survive_json_roundtrip,
    assert_matches_golden,
    assert_never_raises_on_garbage,
    assert_paths_relative_to_target,
)

GOLDEN = Path(__file__).parent.parent / "golden"
ADAPTERS: list[ToolAdapter] = [
    BanditAdapter(),
    SemgrepAdapter(),
    GitleaksAdapter(),
    TrivyAdapter(),
    OsvScannerAdapter(),
    GrypeAdapter(),
    CheckovAdapter(),
    GosecAdapter(),
    DockleAdapter(),
]


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.name)
def test_parse_matches_golden(adapter: ToolAdapter) -> None:
    """core.plugins.conformance.assert_matches_golden -- the same function a third-party plugin's
    own conformance test calls (Week 51 task 1, plan §23): built-in adapters run through literally
    the same check, not a parallel hand-copy of it."""
    assert_matches_golden(adapter, GOLDEN / adapter.spec.name)


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.name)
@pytest.mark.parametrize(
    "garbage", [b"", b"not json", b"{}", b"[]", b'{"results": [{"bogus": 1}]}', b'[{"x": 1}]']
)
def test_parse_never_raises_on_garbage(adapter: ToolAdapter, garbage: bytes) -> None:
    assert_never_raises_on_garbage(adapter, [garbage])


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.name)
def test_paths_are_relative_to_target(adapter: ToolAdapter) -> None:
    assert_paths_relative_to_target(adapter, GOLDEN / adapter.spec.name)


def test_gitleaks_output_never_contains_the_secret() -> None:
    raw = (GOLDEN / "gitleaks" / "raw.json").read_bytes()
    findings = GitleaksAdapter().parse(raw)
    blob = json.dumps([f.to_dict() for f in findings])
    assert "8f3b9c1d" not in blob and "8f3b9c1d" not in raw.decode()


def test_semgrep_maps_cwe_and_owasp() -> None:
    raw = (GOLDEN / "semgrep" / "raw.json").read_bytes()
    sqli = next(
        f
        for f in SemgrepAdapter().parse(raw)
        if "sqlalchemy" in f.title.lower() or "CWE-89" in f.taxonomy.cwe
    )
    assert sqli.taxonomy.cwe == ("CWE-89",)
    assert sqli.taxonomy.owasp_top_10_2021 == ("A03:2021",)


def test_bandit_hardcoded_password_value_is_not_carried_into_findings() -> None:
    raw = (GOLDEN / "bandit" / "raw.json").read_bytes()
    assert b"hunter2" in raw  # the fixture really does contain it...
    blob = json.dumps([f.to_dict() for f in BanditAdapter().parse(raw)])
    assert "hunter2" not in blob  # ...but the findings must not


def _parse(name: str, adapter: ToolAdapter) -> list[Finding]:
    return adapter.parse((GOLDEN / name / "raw.json").read_bytes())


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.name)
def test_findings_survive_json_roundtrip(adapter: ToolAdapter) -> None:
    assert_findings_survive_json_roundtrip(adapter, GOLDEN / adapter.spec.name)


def test_ecosystem_normalization_makes_tools_agree() -> None:
    assert Package.normalize_ecosystem("PyPI") == Package.normalize_ecosystem("pip") == "pypi"
    assert Package.normalize_ecosystem("Go") == Package.normalize_ecosystem("gomod") == "go"
    assert Package.normalize_ecosystem("crates.io") == "cargo"
    assert Package.normalize_ecosystem("Weird") == "weird"


def _sca_identities(findings: list[Finding]) -> set[tuple[str, str, str, str]]:
    return {
        (f.package.ecosystem, f.package.name, f.package.version, cve)
        for f in findings
        if f.package
        for cve in f.taxonomy.cve
    }


def test_trivy_and_osv_report_overlapping_sca_findings_under_one_identity() -> None:
    """The precondition for SCA dedup (ADR-004): both tools yield the same (eco,pkg,ver,CVE)."""
    trivy = _sca_identities(_parse("trivy", TrivyAdapter()))
    osv = _sca_identities(_parse("osv-scanner", OsvScannerAdapter()))
    assert trivy & osv, "expected the two SCA tools to agree on at least one vulnerability"
    assert ("npm", "lodash", "4.17.4", "CVE-2018-16487") in trivy & osv


def test_osv_emits_one_finding_per_vulnerability_group() -> None:
    findings = _parse("osv-scanner", OsvScannerAdapter())
    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids))
    assert all(f.taxonomy.category is Category.SCA and f.package for f in findings)
    assert all(f.scoring.cvss_v3_1 is None or 0 <= f.scoring.cvss_v3_1 <= 10 for f in findings)


def test_osv_flags_a_malicious_package_report_as_critical() -> None:
    """A MAL- id (plan §20.5, OSSF's malicious-packages dataset) carries no CVSS score or severity
    label, unlike a graded vulnerability -- without the plan §20.5 fix it would normalize to INFO
    (the *lowest* severity), exactly backwards from what a confirmed malicious package deserves."""
    raw = json.dumps(
        {
            "results": [
                {
                    "source": {"path": "/requirements.txt"},
                    "packages": [
                        {
                            "package": {"name": "reuests", "version": "1.0.0", "ecosystem": "PyPI"},
                            "vulnerabilities": [
                                {
                                    "id": "MAL-2022-7441",
                                    "summary": "Malicious code in reuests (PyPI)",
                                    "details": "Typosquats requests; exfiltrates credentials.",
                                    "database_specific": {},
                                    "affected": [],
                                }
                            ],
                            "groups": [{"ids": ["MAL-2022-7441"], "aliases": ["MAL-2022-7441"]}],
                        }
                    ],
                }
            ]
        }
    ).encode()
    findings = OsvScannerAdapter().parse(raw)
    assert len(findings) == 1
    f = findings[0]
    assert f.scoring.normalized_severity is Severity.CRITICAL
    assert f.scoring.confidence == 1.0
    assert "malicious" in f.title.lower()
    assert "remove" in f.remediation.summary.lower()


def test_trivy_splits_categories_and_maps_severity() -> None:
    findings = _parse("trivy", TrivyAdapter())
    cats = {f.taxonomy.category for f in findings}
    assert cats == {Category.SCA, Category.IAC, Category.CONTAINER}
    docker = [f for f in findings if f.taxonomy.category is Category.CONTAINER]
    assert any("root" in f.title.lower() for f in docker)
    assert all(f.location.start_line >= 1 for f in findings)


def test_sca_tools_only_apply_when_lockfiles_or_iac_exist() -> None:
    from pathlib import Path

    from core.adapters import RepoContext

    bare = RepoContext(Path("."), frozenset({"python"}))
    assert not OsvScannerAdapter().applies_to(bare)
    assert not TrivyAdapter().applies_to(bare)
    assert OsvScannerAdapter().applies_to(RepoContext(Path("."), lockfiles=("go.mod",)))
    assert TrivyAdapter().applies_to(RepoContext(Path("."), has_dockerfile=True))


def test_trivy_collapses_its_own_duplicate_misconfigs() -> None:
    findings = _parse("trivy", TrivyAdapter())
    ids = [f.id for f in findings]
    assert len(ids) == len(set(ids)), "adapter ids must be unique within one run"
    raw = json.loads((GOLDEN / "trivy" / "raw.json").read_bytes())
    raw_misconf = sum(len(r.get("Misconfigurations") or []) for r in raw["Results"])
    kept = sum(f.taxonomy.category is not Category.SCA for f in findings)
    assert (raw_misconf, kept) == (26, 15)  # 11 exact duplicates collapsed, none silently lost
