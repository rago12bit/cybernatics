from pathlib import Path

from typer.testing import CliRunner

from cli.main import app
from core.scan import detect_context, scan

runner = CliRunner()


def test_detect_context(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "b.js").write_text("1")
    assert detect_context(tmp_path).languages == frozenset({"python"})


def test_skips_tool_when_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "main.go").write_text("package main\n")
    r = scan(tmp_path, ["bandit"])
    assert r.tool_status["bandit"]["status"] == "skipped"


def test_cli_rejects_unknown_tool(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--tools", "nope"])
    assert result.exit_code != 0
