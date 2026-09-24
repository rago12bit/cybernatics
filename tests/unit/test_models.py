import json
from pathlib import Path

from core.adapters import RepoContext, ToolAdapter, ToolSpec
from core.models import Category, Finding, Location, Severity, Taxonomy


def make_finding() -> Finding:
    snippet = 'query = "SELECT * FROM users WHERE id=" + user_id'
    return Finding(
        id="f_01",
        title="SQL query built via string concatenation",
        description="User-controlled input reaches a SQL query.",
        location=Location("src/api/users.py", 42, 44, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(Category.SAST, cwe=("CWE-89",)),
    )


def test_finding_serialises_to_plain_json() -> None:
    d = make_finding().to_dict()
    json.dumps(d)  # must not raise
    assert d["taxonomy"]["category"] == "sast"
    assert d["taxonomy"]["cwe"] == ["CWE-89"]
    assert d["scoring"]["normalized_severity"] == Severity.INFO.value
    assert d["remediation"]["is_suggestion"] is True


class DummyAdapter(ToolAdapter):
    spec = ToolSpec("dummy", "dummy:1", frozenset({"sast"}), frozenset({"python"}))

    def build_command(self, target: Path, output: Path) -> list[str]:
        return ["dummy", str(target), "-o", str(output)]

    def parse(self, raw: bytes) -> list[Finding]:
        return []


def test_applies_to_intersects_languages() -> None:
    a = DummyAdapter()
    assert a.applies_to(RepoContext(Path("."), frozenset({"python", "go"})))
    assert not a.applies_to(RepoContext(Path("."), frozenset({"go"})))
