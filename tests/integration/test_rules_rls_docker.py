"""Week 65 under REAL Row-Level Security (migration 0037): rules and their runs belong to one
organization. A rule fires from the outbox on Postgres -- through the advisory lock that keeps two
dispatchers apart -- and another org's session sees none of its rows, cannot open the rule by id,
and its own dispatcher finds nothing to do. Needs `BULWARK_RLS_TEST_DATABASE_URL` (Postgres at head,
as `bulwark_worker`)."""

from __future__ import annotations

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.dispatch import _lock_key, dispatch, drain
from core.models import Severity
from core.persistence import repo
from core.persistence.models import AutomationRule, IssueRow, OutboxEvent, RuleRun, Tag
from core.rules import service as rules
from core.tenancy import set_session_org
from tests.integration.test_dedup_rls_docker import pytestmark, sessions  # noqa: F401
from tests.integration.test_sla_rls_docker import two_orgs  # noqa: F401
from tests.unit.test_sla import finding


def test_rules_fire_on_postgres_and_stay_in_their_org(
    sessions: sessionmaker[Session], two_orgs: tuple[str, str]  # noqa: F811
) -> None:
    a, b = two_orgs
    with sessions() as s:
        set_session_org(s, a)
        d = rules.validate(s, a, {
            "name": "Critical to P1", "trigger": "issue.created",
            "condition": 'input.issue.severity == "CRITICAL"',
            "actions": [{"type": "set_priority", "band": "P1"}, {"type": "tag", "tags": ["hot"]}],
        })  # fmt: skip
        rule = rules.create(s, a, d, actor="t")
        sc = repo.create_scan(
            s, source_type="git", source_ref="https://example.com/a/b", source_label=f"{a}/web",
            tools=["semgrep"], org_id=a,
        )  # fmt: skip
        found = [finding(1, Severity.CRITICAL), finding(2, Severity.LOW)]
        sync = repo.sync_issues_for_scan(s, sc.id, found)
        repo.add_findings(s, sc.id, found, sync.updates)
        repo.finish_scan(s, sc.id, "completed")
        # Another dispatcher holds this org's lock: this one does nothing and leaves the events.
        with s.get_bind().connect() as other:  # type: ignore[union-attr]
            other.execute(text("SELECT pg_advisory_lock(:k)"), {"k": _lock_key(a)})
            assert dispatch(s, a) == 0
            other.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _lock_key(a)})
        assert drain(s, a) > 0
        by_title = {i.title: i for i in s.scalars(select(IssueRow))}
        assert by_title["Problem 1"].priority_override == "P1"
        assert by_title["Problem 2"].priority_override is None
        [run] = s.scalars(select(RuleRun)).all()
        assert run.status == "applied" and run.subject_ids == [by_title["Problem 1"].id]
        assert s.scalar(select(func.count()).select_from(OutboxEvent).where(
            OutboxEvent.dispatched_at.is_(None))) == 0  # fmt: skip
        rule_id = rule.id
    with sessions() as s:
        set_session_org(s, b)
        for model in (AutomationRule, RuleRun, Tag, IssueRow, OutboxEvent):
            assert s.scalar(select(func.count()).select_from(model)) == 0, model.__tablename__
        assert rules.get(s, b, rule_id) is None
        assert dispatch(s, b) == 0
    with sessions() as s:  # the first org still sees all of it
        set_session_org(s, a)
        assert rules.get(s, a, rule_id) is not None
        assert len(rules.runs(s, a, rule_id=rule_id)) == 1
