"""`/fix` on a pull request, the I/O half (plan §50, Week 76, ADR-0059): read the comment GitHub
sent, check who it is from and what the pull request is, reply with a preview, and -- on a confirm
-- start one verified-fix run per finding. `core.fixagent.pr_command` has the rules themselves.

Called from the GitHub App webhook (`issue_comment`), after its signature check. The organization
comes from the App installation, never from the comment. Everything the comment says is
untrusted: only its first line can be a command, and only the code in `/fix confirm <code>` is
read from it.

Every step is re-checked on confirm -- the person, their role, the pull request still open and
not from a fork, its head still the commit the preview was about, the budget -- because time has
passed and any of it may have changed.
"""

from __future__ import annotations

import logging
import os
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.ci.github import _REPO, Transport, http_transport, post_comment
from core.fixagent import pr_command as cmd
from core.fixagent import store as fixagent_store
from core.fixagent.limits import WorkflowLimits
from core.identity.roles import RANK
from core.identity.users import access_for
from core.llm.budget import BudgetConfig, org_usage
from core.persistence import repo
from core.persistence.models import FindingRow, PrFixRequest, Scan, User
from core.tenancy import set_session_org

log = logging.getLogger(__name__)

EXPIRY = timedelta(hours=24)
DEFAULT_TOKENS_PER_FINDING = 60_000


def tokens_per_finding() -> int:
    return max(
        1_000, int(os.environ.get("BULWARK_FIX_TOKENS_PER_FINDING", DEFAULT_TOKENS_PER_FINDING))
    )


@dataclass(frozen=True)
class CommentEvent:
    installation_id: str
    repo: str
    pr_number: int
    commenter: cmd.Commenter
    command: cmd.Command


def parse_comment_event(payload: dict[str, Any]) -> CommentEvent | None:
    """None for anything that is not a new `/fix` comment by a person on a pull request."""
    if payload.get("action") != "created":
        return None  # an edit could turn an old comment into a command after the fact
    try:
        issue = payload["issue"]
        comment = payload["comment"]
        user = comment["user"]
        if not isinstance(issue.get("pull_request"), dict):
            return None  # a comment on an issue, not a pull request
        login = str(user["login"])
        is_bot = user.get("type") == "Bot" or login.endswith("[bot]")
        event = CommentEvent(
            installation_id=str(payload["installation"]["id"]),
            repo=str(payload["repository"]["full_name"]),
            pr_number=int(issue["number"]),
            commenter=cmd.Commenter(login, str(comment.get("author_association") or ""), is_bot),
            command=cmd.Command("none"),
        )
        command = cmd.parse(str(comment.get("body") or ""))
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    if command is None or event.commenter.is_bot or not _REPO.match(event.repo):
        return None
    return CommentEvent(
        event.installation_id, event.repo, event.pr_number, event.commenter, command
    )


class GitHub:
    """The installation's view of GitHub: read a pull request, post a comment."""

    def __init__(
        self,
        token: Callable[[], str],
        transport: Transport | None = None,
        api_url: str = "https://api.github.com",
    ) -> None:
        self._token, self._api = token, api_url.rstrip("/")
        self._transport = transport or http_transport

    def pull_request(self, repo_name: str, number: int) -> cmd.PullRequest | None:
        try:
            status, data = self._transport(
                "GET",
                f"{self._api}/repos/{repo_name}/pulls/{number}",
                {
                    "Authorization": f"Bearer {self._token()}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "bulwark-github-app",
                },  # fmt: skip
                None,
            )
        except Exception:  # noqa: BLE001 - unreachable GitHub is a refusal, not a crash
            log.exception("/fix: could not read %s#%s", repo_name, number)
            return None
        if status != 200 or not isinstance(data, dict):
            return None
        try:
            head, base = data["head"], data["base"]
            head_repo = (head.get("repo") or {}).get("full_name")
            return cmd.PullRequest(
                number=int(data["number"]),
                state=str(data["state"]),
                head_sha=str(head["sha"]).lower(),
                head_repo=str(head_repo) if head_repo else None,
                base_repo=str(base["repo"]["full_name"]),
            )
        except (KeyError, TypeError, ValueError, AttributeError):
            return None

    def comment(self, repo_name: str, number: int, body: str) -> bool:
        try:
            post_comment(repo_name, number, body, self._token(), self._api, self._transport)
            return True
        except Exception:  # noqa: BLE001 - logged; the request's own state is already saved
            log.exception("/fix: could not comment on %s#%s", repo_name, number)
            return False


#: Starts one run: (session, request, finding document, workflow id, run id) -> None.
Starter = Callable[[Session, PrFixRequest, dict[str, Any], str, str], Awaitable[None]]


async def temporal_starter(
    s: Session, req: PrFixRequest, finding: dict[str, Any], workflow_id: str, run_id: str
) -> None:
    from core.fixagent.client import start_verified_fix

    scan = s.get(Scan, req.scan_id)
    assert scan is not None
    reported = (finding.get("evidence") or {}).get("reported_by") or []
    await start_verified_fix(
        run_id, workflow_id, req.org_id, "", _finding_only(finding), scan.source_ref, scan.ref,
        str(reported[0]) if reported else "",
        fixagent_store.baseline_fingerprints_for(s, scan.id, finding["location"]["path"]),
        req.repo, req.installation_id, None, WorkflowLimits.from_env(),
        token_cap=req.tokens_per_finding, pr_fix_request_id=req.id, pr_number=req.pr_number,
    )  # fmt: skip


def _finding_only(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if k not in ("scan_id", "issue")}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _linked_user(s: Session, org_id: str, login: str) -> User | None:
    return s.scalar(
        select(User).where(
            User.org_id == org_id,
            func.lower(User.github_login) == login.lower(),
            User.active.is_(True),
        )
    )


def _pr_scans(s: Session, org_id: str, repo_name: str, number: int) -> Any:
    return (
        select(Scan)
        .where(Scan.org_id == org_id, Scan.github_repo == repo_name,
               Scan.github_pr_number == number)
        .order_by(Scan.created_at.desc())
    )  # fmt: skip


def new_findings(s: Session, scan_id: str) -> list[dict[str, Any]]:
    """The findings this pull request introduced: a pull request scan never mints Issues, so
    "new" is on the stored finding (repo.classify_findings_for_pr), with no Issue id."""
    rows = s.scalars(
        select(FindingRow).where(FindingRow.scan_id == scan_id, FindingRow.issue_state == "new")
    )
    return [{**r.data, "issue": {"id": None, "state": "new"}} for r in rows]


def budget_left(s: Session, org_id: str) -> int:
    return max(0, BudgetConfig.from_env().per_org_month - org_usage(s, org_id))


def _audit(s: Session, actor: str, action: str, req: PrFixRequest, **payload: Any) -> None:
    repo.append_audit_entry(
        s, actor=actor, action=action, target=f"pr_fix:{req.id}",
        payload={"org_id": req.org_id, "repo": req.repo, "pr_number": req.pr_number,
                 "head_sha": req.head_sha, **payload},
    )  # fmt: skip


async def handle_comment(
    s: Session,
    event: CommentEvent,
    org_id: str,
    gh: GitHub,
    *,
    starter: Starter = temporal_starter,
    usd_per_1k: float | None = None,
    now: datetime | None = None,
) -> str:
    """Answer one `/fix` comment. Returns what happened, for the webhook's reply and the tests:
    refused | ignored | previewed | over_budget | started | cancelled."""
    set_session_org(s, org_id)
    now = now or _now()

    def refuse(reason: str) -> str:
        gh.comment(event.repo, event.pr_number, cmd.refused_body(reason))
        return "refused"

    scan_for_asset = s.scalar(_pr_scans(s, org_id, event.repo, event.pr_number).limit(1))
    if scan_for_asset is None or scan_for_asset.asset_id is None:
        return "ignored"  # Bulwark never scanned this pull request: not ours to answer
    user = _linked_user(s, org_id, event.commenter.login)
    rank = None
    if user is not None:
        rank = RANK[access_for(s, user).role_on(scan_for_asset.asset_id)]
    # The cheap checks first: no GitHub call for someone who may not use /fix anyway.
    pr: cmd.PullRequest | None = None
    reason = cmd.refusal(event.commenter, _placeholder(event), rank)
    if reason is None:
        pr = gh.pull_request(event.repo, event.pr_number)
        reason = cmd.refusal(event.commenter, pr, rank)
    if reason is not None:
        return refuse(reason)
    assert user is not None and pr is not None

    if event.command.action == "preview":
        return _preview(s, event, org_id, gh, user, pr, scan_for_asset.asset_id, usd_per_1k, now)

    req = s.scalar(
        select(PrFixRequest).where(
            PrFixRequest.org_id == org_id, PrFixRequest.code == event.command.code,
            PrFixRequest.repo == event.repo, PrFixRequest.pr_number == event.pr_number,
        )
    )  # fmt: skip
    if req is None or req.status != "previewed":
        return refuse("there is no open /fix preview with that code on this pull request")
    actor = f"user:{user.id}"
    if event.command.action == "cancel":
        req.status, req.decided_at = "cancelled", now
        _audit(s, actor, "pr_fix.cancelled", req)  # commits
        gh.comment(event.repo, event.pr_number, cmd.refused_body("cancelled; nothing was spent"))
        return "cancelled"
    if now > req.expires_at:
        req.status, req.decided_at = "expired", now
        _audit(s, actor, "pr_fix.expired", req)
        return refuse("that preview has expired; comment /fix for a new one")
    if pr.head_sha != req.head_sha:
        req.status, req.decided_at = "cancelled", now
        _audit(s, actor, "pr_fix.stale", req, now_at=pr.head_sha)
        return refuse(
            "the pull request has new commits since the preview, so it is not what was "
            "previewed; comment /fix for a new one"
        )
    left = budget_left(s, org_id)
    if req.token_cap > left:
        return refuse(
            f"this needs up to {req.token_cap:,} tokens and only {left:,} are left this month"
        )
    limits = WorkflowLimits.from_env()
    running = fixagent_store.count_running_for_org(s, org_id)
    if running + len(req.finding_ids) > limits.max_concurrent_per_org:
        return refuse(
            f"the organization already has {running} verified-fix run(s) going (at most "
            f"{limits.max_concurrent_per_org}); try again when they finish"
        )
    return await _start(s, req, gh, user, event.commenter.login, starter, now)


def _placeholder(event: CommentEvent) -> cmd.PullRequest:
    """A stand-in that passes the pull request checks, for checking the person first."""
    return cmd.PullRequest(event.pr_number, "open", "", event.repo, event.repo)


def _preview(
    s: Session, event: CommentEvent, org_id: str, gh: GitHub, user: User, pr: cmd.PullRequest,
    asset_id: str, usd_per_1k: float | None, now: datetime,
) -> str:  # fmt: skip
    scan = s.scalar(
        _pr_scans(s, org_id, event.repo, event.pr_number)
        .where(Scan.github_head_sha == pr.head_sha, Scan.status == "completed")
        .limit(1)
    )
    if scan is None:
        gh.comment(event.repo, event.pr_number, cmd.refused_body(
            "Bulwark has no finished scan of this pull request's latest commit yet; comment /fix "
            "again once its scan comment is up"))  # fmt: skip
        return "refused"
    findings, left_out = cmd.fixable(new_findings(s, scan.id))
    if not findings:
        gh.comment(event.repo, event.pr_number, cmd.refused_body(
            "this pull request introduced no code, secret or configuration findings the agent "
            "can fix"))  # fmt: skip
        return "refused"
    est = cmd.Estimate(len(findings), tokens_per_finding(), usd_per_1k, budget_left(s, org_id))
    # A new preview replaces any earlier one on this pull request: one code is live at a time.
    for old in s.scalars(
        select(PrFixRequest).where(
            PrFixRequest.org_id == org_id, PrFixRequest.repo == event.repo,
            PrFixRequest.pr_number == event.pr_number, PrFixRequest.status == "previewed",
        )
    ):  # fmt: skip
        old.status, old.decided_at = "cancelled", now
    req = PrFixRequest(
        org_id=org_id, asset_id=asset_id, scan_id=scan.id, installation_id=event.installation_id,
        repo=event.repo, pr_number=event.pr_number, head_sha=pr.head_sha, code=cmd.new_code(),
        finding_ids=[str(f["id"]) for f in findings], tokens_per_finding=est.tokens_per_finding,
        token_cap=est.cap, status="refused" if est.over_budget else "previewed",
        requested_by=user.id, requested_login=event.commenter.login[:39], created_at=now,
        expires_at=now + EXPIRY,
    )  # fmt: skip
    s.add(req)
    s.flush()
    _audit(s, f"user:{user.id}", "pr_fix.previewed", req, findings=req.finding_ids,
           token_cap=req.token_cap, over_budget=est.over_budget)  # fmt: skip
    gh.comment(event.repo, event.pr_number, cmd.preview_body(req.code, findings, left_out, est))
    return "over_budget" if est.over_budget else "previewed"


async def _start(
    s: Session, req: PrFixRequest, gh: GitHub, user: User, login: str, starter: Starter,
    now: datetime,
) -> str:  # fmt: skip
    req.status, req.confirmed_by, req.decided_at = "started", user.id, now
    _audit(s, f"user:{user.id}", "pr_fix.started", req, findings=req.finding_ids,
           token_cap=req.token_cap)  # fmt: skip
    rows = {
        r.finding_id: r
        for r in s.scalars(
            select(FindingRow).where(
                FindingRow.scan_id == req.scan_id, FindingRow.finding_id.in_(req.finding_ids)
            )
        )
    }
    started = 0
    for fid in req.finding_ids:
        row = rows.get(fid)
        if row is None:
            continue
        workflow_id = f"fixagent-pr-{req.id[:8]}-{uuid.uuid4().hex[:8]}"
        run = fixagent_store.create_run(
            s, req.org_id, None, workflow_id, pr_fix_request_id=req.id, finding_id=fid[:300]
        )
        try:
            await starter(s, req, row.data, workflow_id, run.id)
            started += 1
        except Exception as exc:  # noqa: BLE001 - Temporal unreachable: say so, spend nothing
            log.exception("/fix: could not start a run for %s", fid)
            fixagent_store.update_run(s, run, status="failed", ended_reason="not_started")
            if started == 0:
                gh.comment(req.repo, req.pr_number, cmd.refused_body(
                    f"the verified-fix agent could not be started ({type(exc).__name__}); nothing "
                    "was spent"))  # fmt: skip
                return "refused"
    est = cmd.Estimate(started, req.tokens_per_finding, None, None)
    gh.comment(req.repo, req.pr_number, cmd.started_body(started, est, login))
    return "started"
