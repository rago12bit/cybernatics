"""The periodic jobs run every organization, whatever one of them does (core.tasks._each_org).

They looped over the organizations with nothing around each one, so the first organization that
raised ended the task: every organization after it was skipped, on that run and every later one."""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy.orm import Session, sessionmaker

from core import tasks
from core.persistence.models import Organization
from core.tenancy import session_org

ORGS = ("org-a", "org-b", "org-c")


@pytest.fixture
def orgs(sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch) -> None:
    with sessions() as s:
        s.add_all([Organization(id=o, name=o) for o in ORGS])
        s.commit()
    monkeypatch.setattr("core.persistence.db.get_session_factory", lambda: sessions)


def test_one_organization_failing_does_not_stop_the_rest(
    orgs: None, caplog: pytest.LogCaptureFixture
) -> None:
    seen: list[tuple[str, str | None]] = []

    def run(s: Session, org_id: str) -> int:
        seen.append((org_id, session_org(s)))  # each in a session scoped to itself
        if org_id == "org-a":
            raise RuntimeError("this organization's data is broken")
        return 2

    with caplog.at_level(logging.ERROR, logger="core.tasks"):
        assert tasks._each_org("the test job", run) == 4
    assert seen == [(o, o) for o in ORGS]
    assert "the test job failed for organization org-a" in caplog.text


@pytest.mark.parametrize(
    ("task", "target", "result"),
    [
        (tasks.sla_sweep_task, "core.sla.service.sweep", SimpleNamespace(announced=1)),
        (tasks.dispatch_outbox_task, "core.dispatch.drain", 1),
        (tasks.tickets_sync_task, "core.tickets.sync.sync_due", 1),
        (tasks.rules_sweep_task, "core.rules.engine.sweep", SimpleNamespace(applied=1, held=0)),
        (tasks.notification_digest_task, "core.notify.service.run_digests",
         SimpleNamespace(emails=1, team_messages=0)),
        (tasks.refresh_metrics_task, "core.metrics.rollup.refresh_dirty", 1),
        (tasks.refresh_metrics_all_task, "core.metrics.rollup.refresh_all", 1),
        (tasks.run_due_reports_task, "core.reports.service.run_due", 1),
    ],
)  # fmt: skip
def test_each_periodic_job_carries_on_past_a_failing_organization(
    orgs: None, monkeypatch: pytest.MonkeyPatch, task: Any, target: str, result: Any
) -> None:
    done: list[str] = []

    def job(_s: Session, org_id: str) -> Any:
        if org_id == "org-a":
            raise RuntimeError("broken")
        done.append(org_id)
        return result

    monkeypatch.setattr(target, job)
    assert task() == 2 and done == ["org-b", "org-c"]
