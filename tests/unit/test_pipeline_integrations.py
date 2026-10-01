"""core.pipeline._run_scan_job's integrations dispatch wiring (Week 51 task 2, plan §23) -- that
`notify_scan_result` is actually called, with the right arguments, for a real completed scan of an
org's asset, and is NOT called for a PR-preview scan (which must never notify Slack or file an
external ticket for findings that might never merge). The integrations' own behavior is covered by
tests/unit/test_integrations_*.py; this file only checks the wiring at the call site.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core import pipeline
from core.events import MemoryPublisher
from core.models import Category, Finding, Location, Taxonomy
from core.persistence import repo
from core.persistence.storage import MemoryStore
from core.pipeline import run_scan_job
from core.scan import ToolOutcome
from core.tenancy import DEFAULT_ORG_ID


def _finding(fid: str) -> Finding:
    return Finding(
        id=fid, title="t", description="d",
        location=Location("a.py", 1, 1, "code", "h"), taxonomy=Taxonomy(Category.SAST),
    )  # fmt: skip


def executor_from(table: dict[str, ToolOutcome]):  # type: ignore[no-untyped-def]
    def run(name: str, target: Path) -> ToolOutcome:
        return table[name]

    return run


def test_notify_scan_result_is_called_for_a_completed_org_scoped_scan(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sample_repo: Path
) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        pipeline,
        "notify_scan_result",
        lambda s, org_id, label, scan_id, sync, findings_by_id: calls.append(
            {"org_id": org_id, "label": label, "scan_id": scan_id, "sync": sync}
        ),
    )
    table = {"bandit": ToolOutcome("bandit", "ok", [_finding("bandit:a.py:1")])}
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=str(sample_repo), source_label="acme/app",
            tools=["bandit"], org_id="org-a",
        ).id  # fmt: skip
    run_scan_job(
        sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table), org_id="org-a"
    )
    assert len(calls) == 1
    assert calls[0]["org_id"] == "org-a"
    assert calls[0]["label"] == "acme/app"
    assert calls[0]["scan_id"] == sid
    assert calls[0]["sync"].new_count == 1


def test_notify_scan_result_is_not_called_for_a_pr_preview_scan(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sample_repo: Path
) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(pipeline, "notify_scan_result", lambda *a, **kw: calls.append((a, kw)))
    table = {"bandit": ToolOutcome("bandit", "ok", [_finding("bandit:a.py:1")])}
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=str(sample_repo), source_label="acme/app#5",
            tools=["bandit"], org_id="org-a", ref="refs/pull/5/head",
            asset_label=str(sample_repo),
        ).id  # fmt: skip
    status = run_scan_job(
        sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table), org_id="org-a"
    )
    assert status == "completed"  # the scan itself succeeded; notification was still skipped
    assert calls == []


def test_notify_scan_result_is_not_called_without_an_org_id(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sample_repo: Path
) -> None:
    """The trusted-internal/CLI default (org_id=None) has no org to look integration settings up
    for -- notify_scan_result must simply never be reached, not called with a None org."""
    calls: list[Any] = []
    monkeypatch.setattr(pipeline, "notify_scan_result", lambda *a, **kw: calls.append((a, kw)))
    table = {"bandit": ToolOutcome("bandit", "ok", [_finding("bandit:a.py:1")])}
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=str(sample_repo), source_label="acme/app",
            tools=["bandit"], org_id=DEFAULT_ORG_ID,
        ).id  # fmt: skip
    status = run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table))
    assert status == "completed"
    assert calls == []


def test_a_dying_integration_dispatch_does_not_fail_the_scan(
    sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch, sample_repo: Path
) -> None:
    def boom(*a: Any, **kw: Any) -> None:
        raise RuntimeError("Slack is down")

    monkeypatch.setattr(pipeline, "notify_scan_result", boom)
    table = {"bandit": ToolOutcome("bandit", "ok", [_finding("bandit:a.py:1")])}
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=str(sample_repo), source_label="acme/app",
            tools=["bandit"], org_id="org-a",
        ).id  # fmt: skip
    status = run_scan_job(
        sid, sessions, MemoryStore(), MemoryPublisher(), executor_from(table), org_id="org-a"
    )
    assert status == "completed"
