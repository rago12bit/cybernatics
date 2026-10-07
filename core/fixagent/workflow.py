"""The verified-fix agent as a Temporal workflow (plan §21.2, ADR-0027): the first Temporal workflow
in this codebase (everything else uses Celery for scan fan-out). Durable and resumable by
construction -- Temporal replays the workflow's event history on a worker restart, so `run()` picks
up exactly where it left off, including a pending human-approval signal (validated live during this
feature's own development: started a workflow, killed the worker mid-run, started a brand-new worker
process with no shared memory, and it resumed and completed correctly from Temporal's own history).

Everything the workflow needs from the outside world is one of the `@activity.defn` functions below
-- `VerifiedFixWorkflow.run()` itself does no I/O, per Temporal's own determinism requirement (a
workflow's code is replayed, sometimes on a different worker, so it can only ever depend on inputs it
explicitly asked an activity to fetch). Each activity is a thin, testable wrapper around one
already-built piece: `core.gitfetch`, `core.fixagent.agent`, `core.fixagent.verify`,
`core.fixagent.sandbox`, `core.fixagent.github_pr`, `core.fixagent.store`.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from temporalio import activity, workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError

from core.fixagent.limits import WorkflowLimits

APPROVAL_TIMEOUT_S = 7 * 24 * 3600  # a stale, never-reviewed run is cleaned up, not left forever --
# a pragmatic hygiene limit, distinct from ADR-0015's three (this one covers the human-wait phase
# that ADR-0015 deliberately excludes from the overall verification timeout).


@dataclass
class VerifiedFixInput:
    run_db_id: str
    workflow_id: str
    org_id: str
    issue_id: str  # "" for a pull request run (`/fix`), whose finding has no Issue yet
    finding: dict[str, Any]  # Finding.to_dict()
    clone_url: str
    ref: str | None
    originating_tool: str
    baseline_fingerprints: list[str]
    repo_full_name: str | None  # "owner/repo", when this asset is GitHub-App-linked; else None
    installation_id: str | None
    run_tests: dict[str, Any] | None  # a TestRunSpec's fields, or None if tests are not opted in
    limits: dict[str, Any]  # WorkflowLimits.__dict__, passed explicitly: workflows can't read env
    # Week 76 (`/fix`, plan §50). With defaults, so a workflow started before them still replays.
    token_cap: int | None = None  # the most this run may spend on the model, across attempts
    pr_fix_request_id: str | None = None  # set: a pull request run -- post the result, no approval
    pr_number: int | None = None


@workflow.defn
class VerifiedFixWorkflow:
    def __init__(self) -> None:
        self._decision: str | None = None  # "approve" | "reject", set by a signal

    @workflow.signal
    def approve(self) -> None:
        self._decision = "approve"

    @workflow.signal
    def reject(self, reason: str = "") -> None:
        self._decision = "reject"

    @workflow.query
    def decision(self) -> str | None:
        return self._decision

    @workflow.run
    async def run(self, inp: VerifiedFixInput) -> str:
        limits = WorkflowLimits(**inp.limits)
        per_attempt = timedelta(seconds=limits.per_attempt_timeout_s)
        start = workflow.now()
        feedback: str | None = None
        final_patch: dict[str, Any] | None = None
        spent = 0  # model tokens, across attempts

        for attempt in range(1, limits.max_attempts + 1):
            if (workflow.now() - start).total_seconds() > limits.overall_timeout_s:
                return await self._finish(inp, "inconclusive", "overall_timeout")
            left = None if inp.token_cap is None else inp.token_cap - spent
            if left is not None and left <= 0:
                return await self._finish(inp, "inconclusive", "token_cap")
            try:
                outcome = await workflow.execute_activity(
                    run_one_attempt_activity,
                    args=[inp, feedback, attempt, left],
                    start_to_close_timeout=per_attempt,
                )
            except ActivityError:
                return await self._finish(inp, "inconclusive", "per_attempt_timeout")

            spent += int(outcome.get("tokens") or 0)
            if outcome.get("stop"):  # the organization's monthly budget: another try can't help
                return await self._finish(inp, "failed", str(outcome["stop"]))
            if outcome["passed"]:
                final_patch = outcome["patch"]
                break
            feedback = outcome["feedback"]
        else:
            return await self._finish(inp, "failed", "max_attempts_exhausted")

        assert final_patch is not None
        if inp.pr_fix_request_id is not None:
            # `/fix` (plan §50): a person already confirmed the preview, and the patch is posted
            # for a person to apply -- nothing is written to the repository, so there is nothing
            # here to approve.
            return await self._finish(inp, "verified", None)
        await workflow.execute_activity(
            set_awaiting_approval_activity,
            args=[inp.run_db_id, final_patch, inp.org_id],
            start_to_close_timeout=timedelta(seconds=30),
        )
        await workflow.wait_condition(
            lambda: self._decision is not None, timeout=timedelta(seconds=APPROVAL_TIMEOUT_S)
        )
        if self._decision is None:
            return await self._finish(inp, "inconclusive", "approval_timeout")
        if self._decision == "reject":
            return await self._finish(inp, "rejected", None)

        # Never auto-merge (plan §21.2): a human already approved the patch above; opening the PR
        # is still its own activity, run only now, never speculatively during verification.
        pr_url = await workflow.execute_activity(
            open_pr_activity,
            args=[inp, final_patch],
            start_to_close_timeout=timedelta(seconds=60),
        )
        return await self._finish(inp, "opened_pr", None, pr_url=pr_url)

    async def _finish(
        self,
        inp: VerifiedFixInput,
        status: str,
        ended_reason: str | None,
        *,
        pr_url: str | None = None,
    ) -> str:
        if inp.pr_fix_request_id is not None:
            try:
                await workflow.execute_activity(
                    post_pr_result_activity,
                    args=[inp, status, ended_reason],
                    start_to_close_timeout=timedelta(seconds=60),
                    retry_policy=RetryPolicy(maximum_attempts=5),
                )
            except ActivityError:
                ended_reason = ended_reason or "comment_not_posted"
        await workflow.execute_activity(
            finish_run_activity,
            args=[inp.run_db_id, status, ended_reason, pr_url, inp.org_id],
            start_to_close_timeout=timedelta(seconds=30),
        )
        return status


# ---- activities: all real I/O lives here, never inside VerifiedFixWorkflow.run --------------------


def _sessions(org_id: str | None) -> Any:
    """A session acting for the run's organization: the worker's database role is under forced
    RLS like every service's, so without it a run's own row is invisible and every write a no-op.
    `org_id` None only for a workflow started before Week 76 passed it."""
    from contextlib import contextmanager

    from core.persistence.db import get_session_factory
    from core.tenancy import set_session_org

    @contextmanager
    def scoped() -> Any:
        with get_session_factory()() as s:
            if org_id:
                set_session_org(s, org_id)
            yield s

    return scoped()


@activity.defn
async def run_one_attempt_activity(
    inp: VerifiedFixInput, feedback: str | None, attempt: int, token_budget: int | None = None
) -> dict[str, Any]:
    """One full propose -> apply -> rerun-rule -> rerun-scanners -> (opt-in) run-tests cycle,
    against a fresh checkout. Re-cloning per attempt (rather than reusing one checkout across the
    whole workflow) is deliberately simple: an activity may run on a different worker than the one
    before it, so a checkout living only on one worker's local disk cannot be assumed to survive
    between activities anyway.

    Every model token is charged to the organization's monthly budget (core.llm.budget), and an
    attempt does not start once that is used up. `token_budget` is what this run may still spend
    (`/fix`'s cap); the result's "tokens" is what this attempt spent."""
    from core.fixagent.agent import AgentGiveUp, propose_patch
    from core.fixagent.context import gather_context
    from core.fixagent.sandbox import TestRunSpec
    from core.fixagent.sandbox import run_tests as sandbox_run_tests
    from core.fixagent.verify import PatchApplyError, apply_patch, rerun_rule, rerun_scanners
    from core.gitfetch import clone_repo
    from core.llm.budget import BudgetExceeded, check_org
    from core.llm.client import AnthropicClient, LLMConfig
    from core.models import finding_from_dict

    finding = finding_from_dict(inp.finding)
    checkout = Path(tempfile.mkdtemp(prefix=f"bulwark-fixagent-{attempt}-"))
    steps: list[dict[str, Any]] = []
    try:
        clone_repo(inp.clone_url, checkout, ref=inp.ref)
        cfg = LLMConfig.from_env()
        if not cfg.enabled or not cfg.api_key:
            return _record(
                inp, attempt, steps, False, "no hosted model is configured for the fix agent"
            )
        with _sessions(inp.org_id) as s:
            try:
                check_org(s, inp.org_id)
            except BudgetExceeded as exc:
                out = _record(inp, attempt, steps, False, str(exc))
                return {**out, "stop": "org_budget"}
        client = AnthropicClient(cfg)
        ctx = gather_context(checkout, finding)
        try:
            proposal = propose_patch(
                client, checkout, finding, ctx, feedback=feedback, max_tokens=token_budget
            )
        except AgentGiveUp as exc:
            _charge(inp.org_id, exc.tokens_used)
            return {**_record(inp, attempt, steps, False, str(exc)), "tokens": exc.tokens_used}
        _charge(inp.org_id, proposal.tokens_used)
        spent = proposal.tokens_used

        try:
            apply_patch(checkout, proposal.patch)
        except PatchApplyError as exc:
            return {**_record(inp, attempt, steps, False, str(exc)), "tokens": spent}

        rule_step = rerun_rule(checkout, finding, inp.originating_tool)
        steps.append(rule_step.__dict__)
        if not rule_step.passed:
            return {**_record(inp, attempt, steps, False, rule_step.detail), "tokens": spent}

        scanners_step = rerun_scanners(
            checkout,
            [finding.location.path],
            [inp.originating_tool],
            frozenset(inp.baseline_fingerprints),
        )
        steps.append(scanners_step.__dict__)
        if not scanners_step.passed:
            return {**_record(inp, attempt, steps, False, scanners_step.detail), "tokens": spent}

        if inp.run_tests is not None:
            tests_step = sandbox_run_tests(checkout, TestRunSpec(**inp.run_tests))
            steps.append(tests_step.__dict__)
            if not tests_step.passed:
                return {**_record(inp, attempt, steps, False, tests_step.detail), "tokens": spent}

        patch_record = {
            "explanation": proposal.explanation,
            "patch": proposal.patch,
            "confidence": proposal.confidence,
            "tokens_used": proposal.tokens_used,
        }
        _save_attempt(inp, attempt, steps, feedback=None, patch=patch_record)
        return {"passed": True, "patch": patch_record, "feedback": None, "tokens": spent}
    finally:
        shutil.rmtree(checkout, ignore_errors=True)


def _charge(org_id: str, tokens: int) -> None:
    from core.llm.budget import record_org

    with _sessions(org_id) as s:
        record_org(s, org_id, tokens)


def _record(
    inp: VerifiedFixInput, attempt: int, steps: list[dict[str, Any]], passed: bool, feedback: str
) -> dict[str, Any]:
    _save_attempt(inp, attempt, steps, feedback=feedback, patch=None)
    return {"passed": passed, "patch": None, "feedback": feedback, "tokens": 0}


def _save_attempt(
    inp: VerifiedFixInput,
    attempt: int,
    steps: list[dict[str, Any]],
    *,
    feedback: str | None,
    patch: dict[str, Any] | None,
) -> None:
    from core.fixagent.store import get_run, update_run

    with _sessions(inp.org_id) as s:
        run = get_run(s, inp.run_db_id)
        if run is None:
            return
        entry: dict[str, Any] = {"attempt": attempt, "steps": steps}
        if feedback is not None:
            entry["feedback"] = feedback
        fields: dict[str, Any] = {
            "attempts": attempt,
            "verification_record": [*run.verification_record, entry],
        }
        if patch is not None:
            fields["latest_patch"] = patch
        update_run(s, run, **fields)


@activity.defn
async def set_awaiting_approval_activity(
    run_db_id: str, patch: dict[str, Any], org_id: str | None = None
) -> None:
    from core.fixagent.store import get_run, update_run

    with _sessions(org_id) as s:
        run = get_run(s, run_db_id)
        if run is not None:
            update_run(s, run, status="awaiting_approval", latest_patch=patch)


@activity.defn
async def finish_run_activity(
    run_db_id: str,
    status: str,
    ended_reason: str | None,
    pr_url: str | None,
    org_id: str | None = None,
) -> None:
    from core.fixagent.store import get_run, update_run

    with _sessions(org_id) as s:
        run = get_run(s, run_db_id)
        if run is not None:
            update_run(s, run, status=status, ended_reason=ended_reason, pr_url=pr_url)


#: How the GitHub API is reached; tests replace it (core.ci.github's transport shape).
github_transport: Any = None


@activity.defn
async def post_pr_result_activity(
    inp: VerifiedFixInput, status: str, ended_reason: str | None
) -> None:
    """`/fix`: one comment on the pull request with this finding's outcome -- the verified patch,
    or why there is none. Raises (and Temporal retries) when GitHub cannot be reached."""
    from core.ci.github import http_transport, post_comment
    from core.config import Settings
    from core.fixagent.pr_command import result_body
    from core.fixagent.store import get_run
    from core.github_app import installation_token

    if inp.repo_full_name is None or inp.installation_id is None or inp.pr_number is None:
        raise RuntimeError("a pull request run without its pull request")
    with _sessions(inp.org_id) as s:
        run = get_run(s, inp.run_db_id)
        record = list(run.verification_record) if run is not None else []
        patch = run.latest_patch if run is not None and status == "verified" else None
    body = result_body(inp.finding, patch, record, ended=ended_reason)
    transport = github_transport or http_transport
    settings = Settings.from_env()
    token = installation_token(
        inp.installation_id,
        settings.github_app_id,
        settings.github_app_private_key,
        transport=transport,
    )
    post_comment(inp.repo_full_name, inp.pr_number, body, token, transport=transport)


@activity.defn
async def open_pr_activity(inp: VerifiedFixInput, patch: dict[str, Any]) -> str:
    """Only reachable after a human signals approval (plan §21.2: "never auto-merge"). Re-clones the
    repository fresh rather than reusing any earlier attempt's checkout (already deleted, and
    possibly made on a different worker) to get the file's real pre-patch content, applies the
    already-verified patch to get its new content, then commits that through the Contents API --
    which replaces a whole file, not a diff (`core.fixagent.github_pr`'s own docstring has why)."""
    from core.config import Settings
    from core.fixagent.github_pr import create_pull_request
    from core.fixagent.verify import apply_patch
    from core.gitfetch import clone_repo
    from core.github_app import installation_token
    from core.models import finding_from_dict

    if inp.repo_full_name is None or inp.installation_id is None:
        raise RuntimeError("this issue's asset is not linked to a GitHub App installation")
    finding = finding_from_dict(inp.finding)
    checkout = Path(tempfile.mkdtemp(prefix="bulwark-fixagent-pr-"))
    try:
        clone_repo(inp.clone_url, checkout, ref=inp.ref)
        apply_patch(checkout, patch["patch"])
        new_content = (checkout / finding.location.path).read_text()
    finally:
        shutil.rmtree(checkout, ignore_errors=True)

    settings = Settings.from_env()
    token = installation_token(
        inp.installation_id, settings.github_app_id, settings.github_app_private_key
    )
    branch = f"bulwark/fix-{inp.issue_id[:8]}-{inp.workflow_id[-8:]}"
    result = create_pull_request(
        inp.repo_full_name,
        branch,
        finding.location.path,
        new_content,
        title=f"Bulwark: fix {finding.title}",
        body=(
            f"{patch['explanation']}\n\n_Opened by Bulwark's verified-fix agent after human "
            f"approval. Confidence: {patch['confidence']}._"
        ),
        token=token,
    )
    return result.html_url


_ = workflow, activity  # re-exported for the worker entrypoint (core/fixagent/worker.py)
