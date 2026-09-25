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


def test_detect_context_finds_lockfiles_docker_and_iac(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "main.tf").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package-lock.json").write_text("{}")
    ctx = detect_context(tmp_path)
    assert ctx.has_dockerfile and ctx.has_iac
    assert ctx.lockfiles == ("sub/package-lock.json",)


def test_a_maven_project_triggers_the_dependency_scanners(tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project/>")
    assert "pom.xml" in detect_context(tmp_path).lockfiles
