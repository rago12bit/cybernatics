from pathlib import Path

import pytest

from core.adapters.bandit import BanditAdapter
from core.runner import build_docker_argv


def test_sandbox_flags_present() -> None:
    argv = build_docker_argv(BanditAdapter(), Path("."), Path("."), "c1")
    for flag in (
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--user=10001:10001",
        "--security-opt=no-new-privileges",
        "--memory=2g",
        "--cpus=1",
        "--pids-limit=256",
    ):
        assert flag in argv
    assert any(a.endswith(":/target:ro") for a in argv)
    assert "--privileged" not in argv


def test_writable_volume_only_where_a_tool_declares_it() -> None:
    from core.adapters.trivy import TrivyAdapter

    trivy = build_docker_argv(TrivyAdapter(), Path("."), Path("."), "c1")
    assert trivy[trivy.index("/db") - 1] == "-v"
    bandit = build_docker_argv(BanditAdapter(), Path("."), Path("."), "c1")
    assert "/db" not in bandit
    assert "--read-only" in trivy  # rootfs stays read-only even for Trivy


def test_semgrep_loads_only_the_rules_for_languages_present() -> None:
    from core.adapters import RepoContext
    from core.adapters.semgrep import SemgrepAdapter

    def configs(langs: set[str] | None) -> list[str]:
        ctx = RepoContext(Path("."), frozenset(langs)) if langs is not None else None
        argv = SemgrepAdapter().build_command(Path("/target"), Path("/out/r.json"), ctx)
        return [argv[i + 1] for i, a in enumerate(argv) if a == "--config"]

    assert configs({"python"}) == ["/rules/python.yaml"]
    assert configs({"python", "javascript"}) == [
        "/rules/javascript.yaml",
        "/rules/typescript.yaml",
        "/rules/python.yaml",
    ]
    assert configs(set()) == ["/rules"] and configs(None) == ["/rules"]  # unknown -> everything
    assert configs({"ruby"}) == ["/rules"]  # no rules for it -> fall back, never scan nothing


def test_trivy_and_osv_scan_the_same_dependency_scope() -> None:
    """Regression: Trivy skips dev deps by default while OSV includes them, which made ~70% of OSV's
    findings look 'unique' on NodeGoat. Both must cover dev dependencies."""
    from core.adapters.osv_scanner import OsvScannerAdapter
    from core.adapters.trivy import TrivyAdapter

    trivy = TrivyAdapter().build_command(Path("/target"), Path("/out/r.json"))
    assert "--include-dev-deps" in trivy
    osv = OsvScannerAdapter().build_command(Path("/target"), Path("/out/r.json"))
    assert (
        "--no-resolve" in osv and "--offline-vulnerabilities" in osv
    )  # offline, no network resolution


def test_cpu_quota_is_per_tool_and_defaults_to_one() -> None:
    from core.adapters.semgrep import SemgrepAdapter
    from core.adapters.trivy import TrivyAdapter

    for adapter, cpus in ((BanditAdapter(), "1"), (SemgrepAdapter(), "4"), (TrivyAdapter(), "4")):
        argv = build_docker_argv(adapter, Path("."), Path("."), "c1")
        assert f"--cpus={cpus}" in argv


def test_semgrep_jobs_follow_the_cpu_quota() -> None:
    from core.adapters.semgrep import SemgrepAdapter

    argv = SemgrepAdapter().build_command(Path("/target"), Path("/out/r.json"), None)
    assert "--jobs=4" in argv


def test_merge_rules_keeps_rule_ids_semgrep_would_derive_from_paths(tmp_path: Path) -> None:
    import subprocess
    import sys

    pytest.importorskip("ruamel.yaml")
    rule = tmp_path / "src/python/django/security/foo.yaml"
    rule.parent.mkdir(parents=True)
    rule.write_text(
        "rules:\n- id: raw-sql\n  languages: [python]\n  message: m\n  severity: ERROR\n  pattern: f($X)\n"
    )
    (rule.parent / "foo.test.yaml").write_text("rules: []\n")  # test fixtures must not become rules
    script = Path(__file__).parents[2] / "docker/semgrep/merge-rules.py"
    subprocess.run(
        [sys.executable, str(script), str(tmp_path / "src"), str(tmp_path / "out")], check=True
    )
    merged = (tmp_path / "out/python.yaml").read_text()
    assert "id: python.django.security.raw-sql" in merged and merged.count("- id:") == 1


def test_semgrep_says_when_timeouts_may_have_hidden_findings() -> None:
    import json

    from core.adapters.semgrep import SemgrepAdapter

    def sarif(*ids: str) -> bytes:
        notes = [
            {"descriptor": {"id": i}, "level": "warning", "message": {"text": "x"}} for i in ids
        ]
        return json.dumps(
            {"runs": [{"results": [], "invocations": [{"toolExecutionNotifications": notes}]}]}
        ).encode()

    a = SemgrepAdapter()
    assert a.warnings(sarif()) == []
    assert a.warnings(sarif("Other")) == []
    assert "2 rule/file pairs timed out" in a.warnings(sarif("Timeout", "Timeout", "Other"))[0]
    assert a.warnings(b"not json") == []


def test_warnings_survive_the_outcome_round_trip() -> None:
    from core.scan import ToolOutcome

    o = ToolOutcome("semgrep", "ok", warnings=["w"])
    assert o.status_block()["warnings"] == ["w"]
    assert ToolOutcome.from_dict(o.to_dict()).warnings == ["w"]
    assert "warnings" not in ToolOutcome("bandit", "ok").status_block()
