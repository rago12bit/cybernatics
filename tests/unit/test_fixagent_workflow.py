"""VerifiedFixWorkflow's own orchestration logic (plan §21.2, ADR-0015's three limits) against a
REAL Temporal engine -- `temporalio.testing.WorkflowEnvironment.start_time_skipping()` starts a real
(if disposable) Temporal test server and fast-forwards its clock past any workflow timer/timeout, so
these tests exercise the actual `VerifiedFixWorkflow.run()` code, not a reimplementation of it, while
the ADR-0015 timeout scenarios still finish in real seconds rather than real minutes.

No `pytest-asyncio` dependency: each scenario is a plain `async def`, run via `asyncio.run()` inside
an ordinary sync test function -- this is the only async-heavy code in the whole project, so adding
a test-runner plugin for one file was not worth it.

Every activity here is a FAKE with the real activity's name (`@activity.defn(name=...)`): this suite
is about the workflow's own control flow (attempt loop, timeouts, the approval signal, never
auto-merging), not about re-proving the individual activities, which have their own direct unit
tests (test_fixagent_verify.py, test_fixagent_github_pr.py, ...).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from core.fixagent.limits import WorkflowLimits
from core.fixagent.workflow import VerifiedFixInput, VerifiedFixWorkflow

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def _input(**overrides: Any) -> VerifiedFixInput:
    base: dict[str, Any] = dict(
        run_db_id="run1", workflow_id="wf-x", org_id="org1", issue_id="issue1", finding={},
        clone_url="https://example.com/x.git", ref=None, originating_tool="bandit",
        baseline_fingerprints=[], repo_full_name="acme/widgets", installation_id="123",
        run_tests=None,
        limits=WorkflowLimits(per_attempt_timeout_s=5, overall_timeout_s=30, max_attempts=3).__dict__,
    )  # fmt: skip
    base.update(overrides)
    return VerifiedFixInput(**base)


@activity.defn(name="set_awaiting_approval_activity")
async def fake_awaiting(run_db_id: str, patch: dict[str, Any]) -> None:
    pass


@activity.defn(name="open_pr_activity")
async def fake_open_pr(inp: VerifiedFixInput, patch: dict[str, Any]) -> str:
    return "https://github.com/acme/widgets/pull/1"


def test_an_approved_patch_opens_a_pr() -> None:
    calls: list[Any] = []
    opened: list[Any] = []

    @activity.defn(name="run_one_attempt_activity")
    async def fake_pass(
        inp: VerifiedFixInput, feedback: str | None, attempt: int
    ) -> dict[str, Any]:
        return {
            "passed": True,
            "patch": {"explanation": "x", "patch": "p", "confidence": "high"},
            "feedback": None,
        }

    @activity.defn(name="open_pr_activity")
    async def tracking_open_pr(inp: VerifiedFixInput, patch: dict[str, Any]) -> str:
        opened.append(patch)
        return "https://github.com/acme/widgets/pull/1"

    async def scenario() -> str:
        env = await WorkflowEnvironment.start_time_skipping()
        async with Worker(
            env.client,
            task_queue="q-approve",
            workflows=[VerifiedFixWorkflow],
            activities=[fake_pass, fake_awaiting, tracking_open_pr, _finish_recorder(calls)],
        ):
            handle = await env.client.start_workflow(
                VerifiedFixWorkflow.run,
                _input(),
                id=f"wf-{uuid.uuid4()}",
                task_queue="q-approve",
            )
            await asyncio.sleep(0.2)
            await handle.signal(VerifiedFixWorkflow.approve)
            return await handle.result()

    result = asyncio.run(scenario())
    assert result == "opened_pr"
    assert opened == [{"explanation": "x", "patch": "p", "confidence": "high"}]
    assert any(
        c == ("finish", "opened_pr", None, "https://github.com/acme/widgets/pull/1") for c in calls
    )


def _finish_recorder(calls: list[Any]) -> Any:
    @activity.defn(name="finish_run_activity")
    async def fake_finish(
        run_db_id: str, status: str, ended_reason: str | None, pr_url: str | None
    ) -> None:
        calls.append(("finish", status, ended_reason, pr_url))

    return fake_finish


def test_a_rejected_patch_never_opens_a_pr() -> None:
    calls: list[Any] = []
    opened: list[Any] = []

    @activity.defn(name="run_one_attempt_activity")
    async def fake_pass(
        inp: VerifiedFixInput, feedback: str | None, attempt: int
    ) -> dict[str, Any]:
        return {
            "passed": True,
            "patch": {"explanation": "x", "patch": "p", "confidence": "high"},
            "feedback": None,
        }

    @activity.defn(name="open_pr_activity")
    async def tracking_open_pr(inp: VerifiedFixInput, patch: dict[str, Any]) -> str:
        opened.append(True)
        return "should-not-be-called"

    async def scenario() -> str:
        env = await WorkflowEnvironment.start_time_skipping()
        async with Worker(
            env.client,
            task_queue="q-reject",
            workflows=[VerifiedFixWorkflow],
            activities=[fake_pass, fake_awaiting, tracking_open_pr, _finish_recorder(calls)],
        ):
            handle = await env.client.start_workflow(
                VerifiedFixWorkflow.run,
                _input(),
                id=f"wf-{uuid.uuid4()}",
                task_queue="q-reject",
            )
            await asyncio.sleep(0.2)
            await handle.signal(VerifiedFixWorkflow.reject, "not good enough")
            return await handle.result()

    result = asyncio.run(scenario())
    assert result == "rejected" and opened == []
    assert any(c[0] == "finish" and c[1] == "rejected" for c in calls)


def test_max_attempts_exhausted_fails_without_ever_asking_for_approval() -> None:
    calls: list[Any] = []
    attempts: list[int] = []
    asked_for_approval: list[Any] = []

    @activity.defn(name="run_one_attempt_activity")
    async def fake_fail(
        inp: VerifiedFixInput, feedback: str | None, attempt: int
    ) -> dict[str, Any]:
        attempts.append(attempt)
        return {"passed": False, "patch": None, "feedback": f"nope {attempt}"}

    @activity.defn(name="set_awaiting_approval_activity")
    async def tracking_awaiting(run_db_id: str, patch: dict[str, Any]) -> None:
        asked_for_approval.append(True)

    async def scenario() -> str:
        env = await WorkflowEnvironment.start_time_skipping()
        async with Worker(
            env.client,
            task_queue="q-maxattempts",
            workflows=[VerifiedFixWorkflow],
            activities=[fake_fail, tracking_awaiting, fake_open_pr, _finish_recorder(calls)],
        ):
            handle = await env.client.start_workflow(
                VerifiedFixWorkflow.run,
                _input(),
                id=f"wf-{uuid.uuid4()}",
                task_queue="q-maxattempts",
            )
            return await handle.result()

    result = asyncio.run(scenario())
    assert result == "failed" and attempts == [1, 2, 3] and asked_for_approval == []
    assert any(c == ("finish", "failed", "max_attempts_exhausted", None) for c in calls)


def test_overall_timeout_stops_starting_new_attempts_and_reports_inconclusive() -> None:
    calls: list[Any] = []
    attempts: list[int] = []

    @activity.defn(name="run_one_attempt_activity")
    async def slow_fail(
        inp: VerifiedFixInput, feedback: str | None, attempt: int
    ) -> dict[str, Any]:
        attempts.append(attempt)
        await asyncio.sleep(20)  # the time-skipping server fast-forwards this
        return {"passed": False, "patch": None, "feedback": "slow"}

    async def scenario() -> str:
        env = await WorkflowEnvironment.start_time_skipping()
        async with Worker(
            env.client,
            task_queue="q-overall-timeout",
            workflows=[VerifiedFixWorkflow],
            activities=[slow_fail, fake_awaiting, fake_open_pr, _finish_recorder(calls)],
        ):
            handle = await env.client.start_workflow(
                VerifiedFixWorkflow.run,
                _input(limits=WorkflowLimits(per_attempt_timeout_s=25, overall_timeout_s=25, max_attempts=3).__dict__),
                id=f"wf-{uuid.uuid4()}", task_queue="q-overall-timeout",
            )  # fmt: skip
            return await handle.result()

    result = asyncio.run(scenario())
    assert result == "inconclusive" and len(attempts) < 3  # stopped early, not all 3 attempts ran
    assert any(c == ("finish", "inconclusive", "overall_timeout", None) for c in calls)
