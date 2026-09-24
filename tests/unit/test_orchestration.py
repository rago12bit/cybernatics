from pathlib import Path

import pytest

from core import scan as scan_mod
from core.models import Category, Finding, Location, Taxonomy
from core.scan import ToolOutcome, scan, threaded_executor


def fake_finding(tool: str) -> Finding:
    return Finding(
        id=f"{tool}:1",
        title="t",
        description="d",
        location=Location("a.py", 1, 1),
        taxonomy=Taxonomy(Category.SAST),
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text("x = 1\n")
    return tmp_path


def test_one_tool_crashing_does_not_fail_the_scan(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_execute(name: str, target: Path) -> ToolOutcome:
        if name == "semgrep":
            raise RuntimeError("parser exploded")
        if name == "bandit":
            return ToolOutcome("bandit", "timeout", error="wall-clock timeout")
        return ToolOutcome("gitleaks", "ok", [fake_finding("gitleaks")], 1, 0.5)

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    r = scan(repo, ["bandit", "semgrep", "gitleaks"])
    assert r.tool_status["gitleaks"]["status"] == "ok" and len(r.findings) == 1
    assert r.tool_status["bandit"]["status"] == "timeout"
    assert r.tool_status["semgrep"]["status"] == "error"
    assert "parser exploded" in r.tool_status["semgrep"]["error"]


def test_inapplicable_tools_are_skipped_not_run(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[str] = []

    def fake_execute(name: str, target: Path) -> ToolOutcome:
        called.append(name)
        return ToolOutcome(name, "ok")

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    r = scan(repo, ["bandit", "osv-scanner", "trivy"])  # no lockfiles/Dockerfile/IaC
    assert called == ["bandit"]
    assert r.tool_status["osv-scanner"]["status"] == "skipped"
    assert r.tool_status["trivy"]["status"] == "skipped"


def test_tools_run_concurrently(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import threading
    import time

    barrier = threading.Barrier(3, timeout=5)  # only passes if all 3 run at the same time

    def fake_execute(name: str, target: Path) -> ToolOutcome:
        barrier.wait()
        time.sleep(0.01)
        return ToolOutcome(name, "ok")

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    out = threaded_executor(["bandit", "semgrep", "gitleaks"], tmp_path)
    assert [o.status for o in out] == ["ok", "ok", "ok"]


def test_outcome_roundtrip_preserves_findings() -> None:
    o = ToolOutcome("bandit", "ok", [fake_finding("bandit")], 1, 1.234, None)
    back = ToolOutcome.from_dict(o.to_dict())
    assert back.findings == o.findings and back.status == "ok" and back.exit_code == 1


def test_executor_that_drops_a_tool_is_reported(repo: Path) -> None:
    r = scan(repo, ["bandit"], lambda tools, target: [])
    assert r.tool_status["bandit"]["status"] == "error"


def test_execute_tool_reports_runner_error_and_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from core.runner import RunnerError, RunResult

    monkeypatch.setattr(
        scan_mod, "run_tool", lambda a, t, c=None: (_ for _ in ()).throw(RunnerError("no docker"))
    )
    assert scan_mod.execute_tool("bandit", tmp_path).status == "error"
    monkeypatch.setattr(
        scan_mod,
        "run_tool",
        lambda a, t, c=None: RunResult("bandit", "timeout", None, b"", "wall-clock"),
    )
    o = scan_mod.execute_tool("bandit", tmp_path)
    assert o.status == "timeout" and o.findings == [] and o.error


def test_celery_fanout_with_in_memory_broker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Real Celery worker + real task dispatch/serialization, with an in-memory broker."""
    from celery.contrib.testing.worker import start_worker

    from core import tasks

    def fake_execute(name: str, target: Path) -> ToolOutcome:
        if name == "semgrep":
            return ToolOutcome("semgrep", "timeout", error="wall-clock timeout")
        return ToolOutcome(name, "ok", [fake_finding(name)], 0, 0.1)

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    tasks.celery_app.conf.update(broker_url="memory://", result_backend="cache+memory://")
    with start_worker(tasks.celery_app, perform_ping_check=False, pool="solo", loglevel="ERROR"):
        outcomes = tasks.celery_executor(["bandit", "semgrep", "gitleaks"], tmp_path)
    by = {o.tool: o for o in outcomes}
    assert by["bandit"].status == "ok" and by["bandit"].findings[0].id == "bandit:1"
    assert by["semgrep"].status == "timeout"
    assert by["gitleaks"].status == "ok"
