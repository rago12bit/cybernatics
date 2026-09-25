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
from core.models import Category, Finding, Package, finding_from_dict

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
    d = GOLDEN / adapter.spec.name
    expected = json.loads((d / "expected.json").read_text())
    actual = [f.to_dict() for f in adapter.parse((d / "raw.json").read_bytes())]
    assert actual, "golden fixture must produce findings"
    assert json.loads(json.dumps(actual, sort_keys=True)) == expected


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.name)
@pytest.mark.parametrize(
    "garbage", [b"", b"not json", b"{}", b"[]", b'{"results": [{"bogus": 1}]}', b'[{"x": 1}]']
)
def test_parse_never_raises_on_garbage(adapter: ToolAdapter, garbage: bytes) -> None:
    assert adapter.parse(garbage) == []


@pytest.mark.parametrize("adapter", ADAPTERS, ids=lambda a: a.spec.name)
def test_paths_are_relative_to_target(adapter: ToolAdapter) -> None:
    raw = (GOLDEN / adapter.spec.name / "raw.json").read_bytes()
    assert all(not f.location.path.startswith("/") for f in adapter.parse(raw))


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
    for f in _parse(adapter.spec.name, adapter):
        assert finding_from_dict(json.loads(json.dumps(f.to_dict()))) == f


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
