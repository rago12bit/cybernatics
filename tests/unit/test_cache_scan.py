"""core/scan.py's cache-aware execution path (plan §20.1): scan()/cached_outcomes wired to a
ResultCache, verified without Docker by monkeypatching execute_tool the same way
tests/unit/test_orchestration.py does for the uncached path."""

from __future__ import annotations

from pathlib import Path

import pytest

from core import scan as scan_mod
from core.cache import ResultCache
from core.models import Category, Finding, Location, Taxonomy
from core.scan import ToolOutcome, cached_outcomes, scan


def fake_finding(tool: str, path: str) -> Finding:
    return Finding(
        id=f"{tool}:{path}",
        title="t",
        description="d",
        location=Location(path, 1, 1),
        taxonomy=Taxonomy(Category.SAST),
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "b.py").write_text("y = 2\n")
    return tmp_path


def test_file_local_tool_is_not_rerun_when_every_file_is_cached(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[Path] = []

    def fake_execute(name: str, target: Path, ctx: object = None) -> ToolOutcome:
        calls.append(target)
        return ToolOutcome(name, "ok", [fake_finding(name, "a.py"), fake_finding(name, "b.py")])

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    cache = ResultCache(tmp_path / "cache")
    r1 = scan(repo, ["bandit"], cache=cache)
    assert len(calls) == 1  # cold cache: one real run over both files
    assert {f.location.path for f in r1.findings} == {"a.py", "b.py"}

    calls.clear()
    r2 = scan(repo, ["bandit"], cache=cache)
    assert calls == []  # every file was a hit: no sandboxed run at all
    assert {f.location.path for f in r2.findings} == {"a.py", "b.py"}


def test_file_local_tool_only_rescans_the_changed_file(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_execute(name: str, target: Path, ctx: object = None) -> ToolOutcome:
        seen = sorted(p.name for p in target.rglob("*") if p.is_file())
        return ToolOutcome(name, "ok", [fake_finding(name, p) for p in seen])

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    cache = ResultCache(tmp_path / "cache")
    scan(repo, ["bandit"], cache=cache)

    (repo / "b.py").write_text("y = 999\n")  # only b.py's content changes
    seen_subsets: list[list[str]] = []

    def spying_execute(name: str, target: Path, ctx: object = None) -> ToolOutcome:
        # Inspected here, not after scan() returns: the subset dir is a `with`-scoped
        # tempfile.TemporaryDirectory, already deleted by the time scan() gives back control.
        seen_subsets.append(sorted(p.name for p in target.rglob("*") if p.is_file()))
        return fake_execute(name, target, ctx)

    monkeypatch.setattr(scan_mod, "execute_tool", spying_execute)
    r = scan(repo, ["bandit"], cache=cache)
    assert seen_subsets == [["b.py"]]  # a.py's cached result was reused, not rescanned
    assert {f.location.path for f in r.findings} == {"a.py", "b.py"}


def test_cached_outcomes_status_is_ok_with_zero_findings_on_a_full_hit(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_mod, "execute_tool", lambda n, t, c=None: ToolOutcome(n, "ok", []))
    cache = ResultCache(tmp_path / "cache")
    scan(repo, ["bandit"], cache=cache)
    monkeypatch.setattr(
        scan_mod,
        "execute_tool",
        lambda n, t, c=None: (_ for _ in ()).throw(AssertionError("rerun")),
    )
    r = scan(repo, ["bandit"], cache=cache)
    assert r.tool_status["bandit"]["status"] == "ok"
    assert r.findings == []


def test_a_failed_run_is_not_papered_over_by_the_cache(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        scan_mod, "execute_tool", lambda n, t, c=None: ToolOutcome(n, "error", error="boom")
    )
    cache = ResultCache(tmp_path / "cache")
    r = scan(repo, ["bandit"], cache=cache)
    assert r.tool_status["bandit"]["status"] == "error"
    # Nothing was cached from a failed run -- a later, successful scan is not stuck replaying it.
    monkeypatch.setattr(
        scan_mod,
        "execute_tool",
        lambda n, t, c=None: ToolOutcome(n, "ok", [fake_finding(n, "a.py")]),
    )
    r2 = scan(repo, ["bandit"], cache=cache)
    assert r2.tool_status["bandit"]["status"] == "ok"


def test_repo_wide_tool_is_keyed_on_its_lockfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "requirements.txt").write_text("flask==1.0\n")
    calls: list[Path] = []

    def fake_execute(name: str, target: Path, ctx: object = None) -> ToolOutcome:
        calls.append(target)
        return ToolOutcome(name, "ok", [fake_finding(name, "requirements.txt")])

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    cache = ResultCache(tmp_path / "cache")
    scan(tmp_path, ["osv-scanner"], cache=cache)
    assert len(calls) == 1

    scan(tmp_path, ["osv-scanner"], cache=cache)  # unchanged lockfile: full cache hit
    assert len(calls) == 1

    (tmp_path / "requirements.txt").write_text("flask==2.0\n")
    scan(tmp_path, ["osv-scanner"], cache=cache)  # lockfile changed: rerun
    assert len(calls) == 2


def test_tier2_tools_are_not_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "main.go").write_text("package main\n")
    calls: list[Path] = []

    def fake_execute(name: str, target: Path, ctx: object = None) -> ToolOutcome:
        calls.append(target)
        return ToolOutcome(name, "ok", [])

    monkeypatch.setattr(scan_mod, "execute_tool", fake_execute)
    cache = ResultCache(tmp_path / "cache")
    scan(tmp_path, ["gosec"], cache=cache)
    scan(tmp_path, ["gosec"], cache=cache)
    assert len(calls) == 2  # tier-2 tools run fresh every time, cache or not


def test_cached_outcomes_covers_every_requested_tool(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from core.scan import detect_context

    monkeypatch.setattr(scan_mod, "execute_tool", lambda n, t, c=None: ToolOutcome(n, "ok", []))
    cache = ResultCache(tmp_path / "cache")
    out = cached_outcomes(["bandit"], repo, detect_context(repo), cache)
    assert set(out) == {"bandit"} and out["bandit"].status == "ok"


def test_a_cache_miss_subset_is_readable_by_the_scanners_own_user(repo: Path) -> None:
    """The sandbox runs scanners as uid 10001, not this user. The subset used to be a bare
    TemporaryDirectory (0700): on Linux semgrep reported "/target is not readable" and gitleaks
    found no config, on every cache-miss run in the GitHub Action."""
    (repo / "pkg").mkdir()
    (repo / "pkg" / "c.py").write_text("z = 3\n")
    (repo / "pkg" / "c.py").chmod(0o600)
    with scan_mod._subset_dir(repo, [repo / "a.py", repo / "pkg" / "c.py"]) as subset:
        assert subset.stat().st_mode & 0o777 == 0o755
        assert (subset / "pkg").stat().st_mode & 0o777 == 0o755
        assert (subset / "pkg" / "c.py").stat().st_mode & 0o777 == 0o644
        assert (subset / "a.py").stat().st_mode & 0o777 == 0o644
