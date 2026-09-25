from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cli.main import app
from core.ignore import IgnoreRules, apply_ignore
from core.models import Category, Finding, Location, Taxonomy
from core.scan import scan

runner = CliRunner()


def rules(*p: str) -> IgnoreRules:
    return IgnoreRules(p)


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        ("tests/fixtures/", "tests/fixtures/a.py", True),
        ("tests/fixtures/", "tests/fixtures/deep/b.tf", True),
        ("tests/fixtures/", "src/tests/fixtures/a.py", False),  # has a slash: anchored at the root
        (
            "fixtures/",
            "src/tests/fixtures/a.py",
            True,
        ),  # no inner slash: any directory of that name
        ("fixtures/", "fixtures.py", False),
        ("*.lock", "a/b/poetry.lock", True),
        ("*.lock", "a/b/poetry.lockx", False),
        ("docs/*.md", "docs/a.md", True),
        ("docs/*.md", "docs/sub/a.md", False),  # * does not cross /
        ("docs/**/*.md", "docs/sub/deeper/a.md", True),
        ("**/generated", "x/y/generated/z.py", True),
        ("**/generated", "generated/z.py", True),
        ("a?c.py", "abc.py", True),
        ("a?c.py", "a/c.py", False),
        (".env", ".env", True),
        (".env", "src/.env", True),
        ("app.py", "app.py.bak", False),
        ("a.b", "aXb", False),  # a dot is a dot, not a wildcard
    ],
)
def test_patterns(pattern: str, path: str, expected: bool) -> None:
    assert rules(pattern).matches(path) is expected


def test_leading_dot_slash_and_backslashes_are_normalised() -> None:
    assert rules("a/b.py").matches("./a/b.py") and rules("a/b.py").matches("a\\b.py")


def test_parse_skips_comments_and_blank_lines() -> None:
    r = IgnoreRules.parse("# fixtures\n\n  tests/fixtures/  \n#x\n*.min.js\n")
    assert r.patterns == ["tests/fixtures/", "*.min.js"]


def test_load_handles_missing_and_oversized_files(tmp_path: Path) -> None:
    assert IgnoreRules.load(tmp_path / "nope").patterns == []
    big = tmp_path / "big"
    big.write_text("x\n" * 40_000)
    with pytest.raises(ValueError, match="larger than"):
        IgnoreRules.load(big)


def test_pattern_count_is_capped_and_regex_metacharacters_are_literal() -> None:
    assert len(rules(*[f"p{i}" for i in range(2000)]).patterns) == 500
    assert not rules("(a+)+$").matches(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
    )  # no regex injection or backtracking


def f(path: str) -> Finding:
    return Finding(
        id=path,
        title="t",
        description="",
        location=Location(path, 1, 1),
        taxonomy=Taxonomy(Category.SAST),
    )


def test_apply_ignore_counts_what_it_drops() -> None:
    kept, n = apply_ignore([f("a.py"), f("tests/x.py"), f("tests/y.py")], rules("tests/"))
    assert [x.id for x in kept] == ["a.py"] and n == 2
    same, zero = apply_ignore([f("a.py")], IgnoreRules())
    assert len(same) == 1 and zero == 0


def _executor(paths: list[str]):  # type: ignore[no-untyped-def]
    from core.scan import ToolOutcome

    def run(tools: list[str], target: Path):  # type: ignore[no-untyped-def]
        out = []
        for t in tools:
            fs = []
            for p in paths:
                x = f(p)
                x.evidence.reported_by = [t]
                x.evidence.rule_ids = {t: ["r"]}
                fs.append(x)
            out.append(ToolOutcome(t, "ok", findings=fs, raw=b""))
        return out

    return run


def test_scan_reads_the_ignore_file_from_the_target_unless_told_otherwise(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x=1\n")
    (tmp_path / ".bulwarkignore").write_text("tests/\n")
    ex = _executor(["a.py", "tests/t.py"])
    auto = scan(tmp_path, ["bandit"], ex)
    assert [x.location.path for x in auto.findings] == ["a.py"] and auto.ignored == 1
    explicit = scan(
        tmp_path, ["bandit"], ex, IgnoreRules()
    )  # CI: the trusted (here empty) rules win
    assert len(explicit.findings) == 2 and explicit.ignored == 0


def test_cli_ignore_file_option_overrides_the_files_in_the_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import core.scan as cs

    monkeypatch.setattr(cs, "threaded_executor", _executor(["a.py", "tests/t.py"]))
    monkeypatch.setattr(
        "cli.main.scan",
        lambda t, n, *a, **k: cs.scan(t, n, _executor(["a.py", "tests/t.py"]), *a[1:], **k),
    )
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.py").write_text("x=1\n")
    (src / ".bulwarkignore").write_text("a.py\n")  # the change under review tries to hide a.py
    trusted = tmp_path / "trusted-ignore"
    trusted.write_text("tests/\n")
    out = tmp_path / "o.json"
    r = runner.invoke(
        app,
        [
            "scan",
            str(src),
            "--tools",
            "bandit",
            "--ignore-file",
            str(trusted),
            "--output",
            str(out),
        ],
    )
    assert r.exit_code == 0, r.output
    doc = json.loads(out.read_text())
    assert [x["location"]["path"] for x in doc["findings"]] == ["a.py"]
    assert doc["stats"]["ignored_findings"] == 1
