import json
from pathlib import Path

import pytest

from core.adapters import ToolAdapter
from core.adapters.bandit import BanditAdapter
from core.adapters.gitleaks import GitleaksAdapter
from core.adapters.semgrep import SemgrepAdapter

GOLDEN = Path(__file__).parent.parent / "golden"
ADAPTERS: list[ToolAdapter] = [BanditAdapter(), SemgrepAdapter(), GitleaksAdapter()]


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
