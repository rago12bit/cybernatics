from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core.events import MemoryPublisher
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.persistence import repo
from core.persistence.models import FindingRow
from core.persistence.storage import MemoryStore
from core.pipeline import SECRETS_WITHHELD, run_scan_job
from core.scan import ToolOutcome


def finding(
    tool: str,
    cat: Category,
    path: str = "a.py",
    line: int = 1,
    sev: Severity = Severity.HIGH,
    fid: str | None = None,
) -> Finding:
    f = Finding(
        id=fid or f"{tool}:{path}:{line}",
        title=f"{tool} finding",
        description="d",
        location=Location(path, line, line, "code", "h"),
        taxonomy=Taxonomy(cat),
    )
    f.scoring.normalized_severity = sev
    f.evidence.reported_by = [tool]
    return f


def make_scan(s: Session, tools: list[str], ref: str, stype: str = "git") -> str:
    return repo.create_scan(
        s, source_type=stype, source_ref=ref, source_label="lbl", tools=tools
    ).id


def executor_from(table: dict[str, ToolOutcome]):  # type: ignore[no-untyped-def]
    def run(name: str, target: Path) -> ToolOutcome:
        out = table[name]
        if isinstance(out, Exception):
            raise out
        return out

    return run


def test_happy_path_persists_everything_and_publishes_progress(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit", "trivy"], str(sample_repo))
    table = {
        "bandit": ToolOutcome(
            "bandit", "ok", [finding("bandit", Category.SAST)], 1, 2.0, raw=b"RAW"
        ),
    }
    store, bus = MemoryStore(), MemoryPublisher()
    status = run_scan_job(sid, sessions, store, bus, executor_from(table))
    assert status == "completed"  # trivy skipped (no lockfiles), bandit ok
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.status == "completed" and scan.finished_at
        runs = {r.tool: r for r in scan.tool_runs}
        assert runs["trivy"].status == "skipped" and runs["bandit"].findings_count == 1
        assert runs["bandit"].raw_object_key == f"scans/{sid}/raw/bandit.json"
        assert s.query(FindingRow).count() == 1
    assert store.get(f"scans/{sid}/raw/bandit.json") == b"RAW"
    kinds = [e["type"] for _, e in bus.events]
    assert kinds[0] == "scan.started" and kinds[-1] == "scan.finished"
    assert kinds.count("tool.finished") == 2


def test_partial_failure_is_reported_not_fatal(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit", "semgrep", "gitleaks"], str(sample_repo))
    table = {
        "bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST)]),
        "semgrep": ToolOutcome("semgrep", "timeout", error="wall-clock timeout"),
        "gitleaks": RuntimeError("boom"),  # type: ignore[dict-item]
    }
    bus = MemoryPublisher()
    assert run_scan_job(sid, sessions, MemoryStore(), bus, executor_from(table)) == "partial"
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None
        runs = {r.tool: r for r in scan.tool_runs}
        assert runs["semgrep"].status == "timeout" and runs["gitleaks"].status == "error"
        assert "boom" in (runs["gitleaks"].error or "")
        assert s.query(FindingRow).count() == 1  # the healthy tool's findings still landed


def test_all_tools_failing_marks_scan_failed(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(sample_repo))
    table = {"bandit": ToolOutcome("bandit", "error", error="docker down")}
    assert (
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
        == "failed"
    )


def test_raw_output_is_withheld_when_secrets_were_found(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    """Threat T7: Bandit's raw JSON echoes the secret's source line, so it must not be stored."""
    with sessions() as s:
        sid = make_scan(s, ["bandit", "gitleaks"], str(sample_repo))
    table = {
        "bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST, line=20)],
                              raw=b'{"code": "KEY = \\"s3cr3t-value\\""}'),
        "gitleaks": ToolOutcome("gitleaks", "ok", [finding("gitleaks", Category.SECRETS, line=20)],
                                raw=b'[{"Secret": "REDACTED"}]'),
    }  # fmt: skip
    store = MemoryStore()
    run_scan_job(sid, sessions, store, MemoryPublisher(), executor_from(table))
    assert list(store.objects) == [f"scans/{sid}/raw/gitleaks.json"]
    assert all(b"s3cr3t-value" not in v for v in store.objects.values())
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None
        runs = {r.tool: r for r in scan.tool_runs}
        assert runs["bandit"].raw_withheld_reason == SECRETS_WITHHELD
        assert runs["bandit"].raw_object_key is None
        # and the snippet near the secret was redacted in the persisted finding too
        row = s.query(FindingRow).filter_by(finding_id="bandit:a.py:20").one()
        assert "withheld" in row.data["location"]["snippet"]


def test_ingestion_failure_fails_the_scan_with_a_safe_message(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(tmp_path / "does-not-exist"))
    bus = MemoryPublisher()
    assert run_scan_job(sid, sessions, MemoryStore(), bus, executor_from({})) == "failed"
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.status == "failed" and "not found" in (scan.error or "")
    assert bus.events[-1][1]["status"] == "failed"


def test_unexpected_crash_does_not_leak_internals(
    sessions: sessionmaker[Session], sample_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import core.pipeline as pl

    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(sample_repo))
    monkeypatch.setattr(
        pl, "detect_context", lambda ws: (_ for _ in ()).throw(KeyError("/etc/secret"))
    )
    assert (
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from({})) == "failed"
    )
    with sessions() as s:
        scan = repo.get_scan(s, sid)
        assert scan is not None and scan.error == "internal error while running the scan"


def test_rerun_is_idempotent(sessions: sessionmaker[Session], sample_repo: Path) -> None:
    """A redelivered Celery task (acks_late) must not duplicate tool runs or findings."""
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(sample_repo))
    table = {"bandit": ToolOutcome("bandit", "ok", [finding("bandit", Category.SAST)])}
    for _ in range(2):
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    with sessions() as s:
        assert s.query(FindingRow).count() == 1
        scan = repo.get_scan(s, sid)
        assert scan is not None and len(scan.tool_runs) == 1


def test_uploaded_archive_is_deleted_after_the_scan(
    sessions: sessionmaker[Session], tmp_path: Path
) -> None:
    z = tmp_path / "up.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a.py", "x=1")
    with sessions() as s:
        sid = make_scan(s, ["bandit"], str(z), stype="archive")
    table = {"bandit": ToolOutcome("bandit", "ok")}
    run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    assert not z.exists()


def test_unknown_scan_id_raises(sessions: sessionmaker[Session]) -> None:
    with pytest.raises(LookupError):
        run_scan_job("nope", sessions, MemoryStore(), MemoryPublisher())


# ---- repository queries -------------------------------------------------------------------
@pytest.fixture
def populated(sessions: sessionmaker[Session]) -> tuple[sessionmaker[Session], str]:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], "x")
        repo.add_findings(s, sid, [
            finding("bandit", Category.SAST, "src/b.py", 5, Severity.LOW),
            finding("semgrep", Category.SAST, "src/a.py", 9, Severity.CRITICAL),
            finding("trivy", Category.SCA, "package-lock.json", 1, Severity.HIGH),
            finding("trivy", Category.IAC, "main.tf", 3, Severity.HIGH),
            finding("bandit", Category.SAST, "src/b.py", 5, Severity.LOW),  # same id again: kept as bandit:src/b.py:5#2
        ])  # fmt: skip
    return sessions, sid


def test_query_filters_sort_and_paginate(populated: tuple[sessionmaker[Session], str]) -> None:
    sessions, sid = populated
    with sessions() as s:
        page = repo.query_findings(s, sid)
        assert page.total == 5
        assert [i["scoring"]["normalized_severity"] for i in page.items] == [
            "CRITICAL", "HIGH", "HIGH", "LOW", "LOW",
        ]  # fmt: skip
        assert repo.query_findings(s, sid, severities=["high"]).total == 2
        assert repo.query_findings(s, sid, categories=["sca", "iac"]).total == 2
        assert repo.query_findings(s, sid, tool="trivy").total == 2
        assert repo.query_findings(s, sid, tool="nope").total == 0
        by_path = repo.query_findings(s, sid, sort="path")
        assert [i["location"]["path"] for i in by_path.items][0] == "main.tf"
        assert repo.query_findings(s, sid, sort="risk").total == 5
        p2 = repo.query_findings(s, sid, limit=2, offset=2)
        assert p2.total == 5 and len(p2.items) == 2
        assert repo.severity_counts(s, sid) == {"LOW": 2, "CRITICAL": 1, "HIGH": 2}


def test_path_filter_treats_like_wildcards_literally(
    populated: tuple[sessionmaker[Session], str],
) -> None:
    sessions, sid = populated
    with sessions() as s:
        assert repo.query_findings(s, sid, path_contains="src/").total == 3
        assert repo.query_findings(s, sid, path_contains="%").total == 0  # not a wildcard
        assert repo.query_findings(s, sid, path_contains="_").total == 0


def test_colliding_finding_ids_are_disambiguated_not_dropped(
    sessions: sessionmaker[Session],
) -> None:
    with sessions() as s:
        sid = make_scan(s, ["bandit"], "x")
        repo.add_findings(s, sid, [finding("t", Category.SAST, fid="same") for _ in range(3)])
        ids = sorted(r.finding_id for r in s.query(FindingRow).all())
    assert ids == ["same", "same#2", "same#3"]
