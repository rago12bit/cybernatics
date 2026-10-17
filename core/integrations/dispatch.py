"""Orchestrates every configured integration for one completed scan (Week 51 task 2, plan §23).

Called inline from `core.pipeline._run_scan_job`, the same place `_post_pr_comment` already posts to
GitHub -- not a separate Celery task: every outbound call this codebase already makes (EPSS/KEV
feeds, Scorecard enrichment, the PR comment itself) happens inline in the worker, best-effort, never
failing the scan over a side feature's own network hiccup. This function follows that same
established convention rather than introducing new async plumbing.

Each integration is wrapped in its own try/except: a broken Jira token must not stop the Slack
notification from going out, and neither should stop the scan from being recorded as complete.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from core.integrations import discord, github_issues, jira, slack
from core.integrations.github_issues import GithubIssueError
from core.integrations.jira import JiraError
from core.integrations.ssrf import validate_webhook_url
from core.integrations.webhooks import deliver_signed
from core.issues import SyncResult
from core.models import Finding
from core.netsafety import Resolver, default_resolver
from core.notify import team
from core.persistence import repo
from core.persistence.models import IntegrationSettingsRow

log = logging.getLogger(__name__)
# Swapped by tests for a fixed resolver, as in core.tickets.sync.
RESOLVER: Resolver = default_resolver


def notify_scan_result(
    s: Session,
    org_id: str,
    asset_label: str,
    scan_id: str,
    sync: SyncResult,
    findings_by_id: dict[str, Finding],
) -> None:
    settings = repo.get_integration_settings(s, org_id)
    if settings is None:
        return
    counts = dict(
        new_count=sync.new_count, reintroduced_count=sync.reintroduced_count,
        fixed_count=sync.fixed_count,
    )  # fmt: skip

    # Week 66: the team chooses instant, the daily digest, or nothing for scan summaries; the
    # ticket sync below runs either way.
    text = slack.scan_summary_payload(asset_label=asset_label, scan_id=scan_id, **counts)["text"]
    now = team.gate(s, org_id, "scan", text)
    if now:
        team.send_teams(s, org_id, text.replace("*", ""))

    if now and settings.slack_webhook_url:
        try:
            slack.send(settings.slack_webhook_url, slack.scan_summary_payload(
                asset_label=asset_label, scan_id=scan_id, **counts
            ))  # fmt: skip
        except Exception:  # noqa: BLE001 - a dying notification must not fail the scan
            log.warning("slack notification failed for scan %s", scan_id, exc_info=True)

    if now and settings.discord_webhook_url:
        try:
            discord.send(settings.discord_webhook_url, discord.scan_summary_payload(
                asset_label=asset_label, scan_id=scan_id, **counts
            ))  # fmt: skip
        except Exception:  # noqa: BLE001
            log.warning("discord notification failed for scan %s", scan_id, exc_info=True)

    if now and settings.outbound_webhook_url and settings.outbound_webhook_secret:
        try:
            deliver_signed(
                settings.outbound_webhook_url,
                {"type": "scan.finished", "scan_id": scan_id, "asset": asset_label, **counts},
                settings.outbound_webhook_secret,
            )
        except Exception:  # noqa: BLE001
            log.warning("outbound webhook failed for scan %s", scan_id, exc_info=True)

    # Week 66: a project with its own ticket settings is synced by `core.tickets`, not filed
    # issue by issue here.
    scan_row = repo.get_scan(s, scan_id)
    if scan_row is not None and scan_row.asset_id is not None:
        from core.tickets.config import get as ticket_config

        if ticket_config(s, scan_row.asset_id) is not None:
            return

    if settings.github_token and settings.github_issues_repo:
        try:
            _sync_github(s, org_id, settings, sync, findings_by_id)
        except Exception:  # noqa: BLE001
            log.warning("GitHub issue sync failed for scan %s", scan_id, exc_info=True)

    if (
        settings.jira_base_url
        and settings.jira_email
        and settings.jira_api_token
        and settings.jira_project_key
    ):
        try:
            _sync_jira(s, org_id, settings, sync, findings_by_id, scan_id)
        except Exception:  # noqa: BLE001
            log.warning("Jira ticket sync failed for scan %s", scan_id, exc_info=True)


def _finding_title(findings_by_id: dict[str, Finding], finding_id: str) -> tuple[str, str]:
    f = findings_by_id.get(finding_id)
    if f is None:
        return "Bulwark finding", ""
    return f.title, f"{f.location.path}:{f.location.start_line}\n\n{f.description}"


def _sync_github(
    s: Session,
    org_id: str,
    settings: IntegrationSettingsRow,
    sync: SyncResult,
    findings_by_id: dict[str, Finding],
) -> None:
    token, target_repo = settings.github_token, settings.github_issues_repo
    assert token and target_repo  # narrowed by the caller's own guard
    for update in sync.updates:
        if not update.is_new_issue or update.issue_id is None:
            continue
        if repo.get_external_link(s, update.issue_id, "github") is not None:
            continue  # already filed on a prior scan (shouldn't happen for is_new_issue, but safe)
        title, body = _finding_title(findings_by_id, update.finding_id)
        created = github_issues.create_issue(
            target_repo, f"[Bulwark] {title}", body or title, token, labels=("bulwark", "security")
        )
        repo.create_external_link(
            s, issue_id=update.issue_id, org_id=org_id, provider="github",
            external_id=f"{target_repo}#{created.number}", external_url=created.url,
        )  # fmt: skip
    for issue_id in sync.fixed_issue_ids:
        link = repo.get_external_link(s, issue_id, "github")
        if link is None or link.external_status == "closed":
            continue
        number = int(link.external_id.rsplit("#", 1)[-1])
        try:
            github_issues.set_issue_state(target_repo, number, "closed", token)
        except GithubIssueError:
            continue  # the ticket may have been deleted/renamed on GitHub's side; not fatal
        repo.set_external_link_status(s, link.id, "closed")


def _sync_jira(
    s: Session,
    org_id: str,
    settings: IntegrationSettingsRow,
    sync: SyncResult,
    findings_by_id: dict[str, Finding],
    scan_id: str,
) -> None:
    base, email, token, project = (
        settings.jira_base_url, settings.jira_email, settings.jira_api_token,
        settings.jira_project_key,
    )  # fmt: skip
    assert base and email and token and project
    # Checked again now, not only when it was saved: the name can point somewhere else since
    # (core.tickets.sync does the same before each use).
    base = validate_webhook_url(base, RESOLVER).url
    for update in sync.updates:
        if not update.is_new_issue or update.issue_id is None:
            continue
        if repo.get_external_link(s, update.issue_id, "jira") is not None:
            continue
        title, body = _finding_title(findings_by_id, update.finding_id)
        created = jira.create_ticket(
            base, email, token, project, f"[Bulwark] {title}", body or title
        )
        repo.create_external_link(
            s, issue_id=update.issue_id, org_id=org_id, provider="jira",
            external_id=created.key, external_url=created.url,
        )  # fmt: skip
    for issue_id in sync.fixed_issue_ids:
        link = repo.get_external_link(s, issue_id, "jira")
        if link is None or link.external_status == "closed":
            continue
        try:
            jira.add_comment(
                base,
                email,
                token,
                link.external_id,
                f"Bulwark no longer detects this issue as of scan {scan_id}.",
            )
        except JiraError:
            continue
        repo.set_external_link_status(s, link.id, "closed")
