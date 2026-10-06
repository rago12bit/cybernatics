"""Ticket sync with Jira and GitHub Issues, both ways (plan §49), with one source of truth per field
(`core.tickets.config`).

**Filing.** An Issue's ticket goes where its project's ticket settings say, with the organization's
stored credentials. An Issue in a group is filed as the group: one ticket, a link row for every
member, and an Issue that joins later is added to it. Filing again updates rather than duplicates.

**Push (platform to ticket).** The summary and Bulwark's own labels (`bulwark`,
`bulwark-severity-<worst>`), written only when they changed (a digest of what was last pushed). When
every Issue on the ticket is fixed, or one comes back: with the ticket owning status, a comment says
so; with the platform owning it, the ticket is closed or reopened (Jira by status category, so no
per-workflow transition ids). Labels someone added by hand are kept.

**Pull (ticket to platform).** The ticket's status and assignee, from a webhook or the poll.
With the ticket owning status, a change maps through the project's status map: "ready for retest"
marks each open Issue ready, as the ticket (`ticket:PAY-12`); nothing ever marks an Issue fixed.
Watchers hear about every status change.

Every call to Jira passes the SSRF guard first: its address is an operator setting, and the poll
calls it on a schedule. GitHub is always api.github.com.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from core.ci.github import Transport, http_transport
from core.integrations import github_issues, jira
from core.integrations.ssrf import validate_webhook_url
from core.netsafety import Resolver, default_resolver
from core.persistence import repo
from core.persistence.models import (
    ExternalIssueLinkRow,
    IntegrationSettingsRow,
    IssueGroup,
    IssueRow,
    TicketConfig,
)
from core.sla.policy import OPEN_STATES
from core.tickets import config as ticket_config

log = logging.getLogger(__name__)

# Swapped by tests for recorded responses and a fixed resolver.
TRANSPORT: Transport = http_transport
RESOLVER: Resolver = default_resolver
STALE_AFTER = timedelta(minutes=10)
POLL_LIMIT = 200
RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


class TicketError(ValueError):
    field = "ticket"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Remote:
    status: str
    closed: bool
    category: str | None
    assignee: str | None


class Provider:
    """One project's ticket target, with the organization's credentials."""

    def __init__(self, cfg: TicketConfig, settings: IntegrationSettingsRow) -> None:
        self.cfg, self.kind = cfg, cfg.provider
        if self.kind == "jira":
            if not (settings.jira_base_url and settings.jira_email and settings.jira_api_token):
                raise TicketError("Jira's address, email and API token are not set.")
            self.base = validate_webhook_url(settings.jira_base_url, RESOLVER).url
            self.email, self.token = settings.jira_email, settings.jira_api_token
        else:
            if not settings.github_token:
                raise TicketError("No GitHub token is set.")
            self.token = settings.github_token

    def _number(self, external_id: str) -> int:
        return int(external_id.rsplit("#", 1)[1])

    def create(self, summary: str, description: str, labels: list[str]) -> tuple[str, str]:
        if self.kind == "jira":
            t = jira.create_ticket(
                self.base,
                self.email,
                self.token,
                self.cfg.target,
                summary,
                description,
                issue_type=self.cfg.issue_type or "Bug",
                labels=labels,
                transport=TRANSPORT,
            )
            return t.key, t.url
        gh = github_issues.create_issue(
            self.cfg.target,
            summary,
            description,
            self.token,
            labels=tuple(labels),
            transport=TRANSPORT,
        )
        return f"{self.cfg.target}#{gh.number}", gh.url

    def read(self, external_id: str) -> Remote:
        if self.kind == "jira":
            j = jira.get_ticket(self.base, self.email, self.token, external_id, transport=TRANSPORT)
            return Remote(j.status, j.category == "done", j.category, j.assignee)
        repo_name = external_id.rsplit("#", 1)[0]
        g = github_issues.get_issue(
            repo_name, self._number(external_id), self.token, transport=TRANSPORT
        )
        return Remote(g.status, g.state == "closed", None, g.assignee)

    def update(self, external_id: str, summary: str, labels: list[str]) -> None:
        if self.kind == "jira":
            stale = [f"bulwark-severity-{s.lower()}" for s in RANK]
            jira.update_ticket(
                self.base,
                self.email,
                self.token,
                external_id,
                summary=summary,
                add_labels=labels,
                remove_labels=[x for x in stale if x not in labels],
                transport=TRANSPORT,
            )
            return
        repo_name, number = external_id.rsplit("#", 1)[0], self._number(external_id)
        current = github_issues.get_issue(repo_name, number, self.token, transport=TRANSPORT)
        keep = [x for x in current.labels if not x.startswith("bulwark")]
        github_issues.update_issue(
            repo_name, number, self.token, title=summary, labels=keep + labels, transport=TRANSPORT
        )

    def comment(self, external_id: str, text: str) -> None:
        if self.kind == "jira":
            jira.add_comment(
                self.base, self.email, self.token, external_id, text, transport=TRANSPORT
            )
        else:
            github_issues.add_comment(
                external_id.rsplit("#", 1)[0],
                self._number(external_id),
                text,
                self.token,
                transport=TRANSPORT,
            )

    def set_closed(self, external_id: str, closed: bool) -> bool:
        if self.kind == "jira":
            return jira.transition_to(
                self.base,
                self.email,
                self.token,
                external_id,
                "done" if closed else "new",
                transport=TRANSPORT,
            )
        github_issues.set_issue_state(
            external_id.rsplit("#", 1)[0],
            self._number(external_id),
            "closed" if closed else "open",
            self.token,
            transport=TRANSPORT,
        )
        return True


def _provider(s: Session, org_id: str, cfg: TicketConfig) -> Provider:
    settings = repo.get_integration_settings(s, org_id)
    if settings is None:
        raise TicketError("No ticketing credentials are set (Settings, integrations).")
    return Provider(cfg, settings)


# --- what Bulwark says on the ticket --------------------------------------------------------------


def _members(s: Session, issue: IssueRow) -> tuple[IssueGroup | None, list[IssueRow]]:
    if issue.group_id:
        group = s.get(IssueGroup, issue.group_id)
        rows = list(
            s.scalars(
                select(IssueRow)
                .where(IssueRow.group_id == issue.group_id)
                .order_by(IssueRow.first_seen_at)
            )
        )
        return group, rows
    return None, [issue]


def fields_for(group: IssueGroup | None, members: Sequence[IssueRow]) -> tuple[str, list[str]]:
    open_ = [m for m in members if m.state in OPEN_STATES] or list(members)
    worst = max((m.severity.upper() for m in open_), key=lambda x: RANK.get(x, -1), default="INFO")
    if group is not None:
        n = len(members)
        summary = f"[Bulwark] {group.name} ({n} issue{'s' if n != 1 else ''})"
    else:
        summary = f"[Bulwark] {members[0].title}"
    return summary[:255], ["bulwark", f"bulwark-severity-{worst.lower()}"]


def description_for(group: IssueGroup | None, members: Sequence[IssueRow]) -> str:
    base = os.environ.get("BULWARK_PUBLIC_URL", "").rstrip("/")
    lines = [
        f"Filed by Bulwark for {'the group ' + group.name if group else 'this issue'}."
        " Bulwark owns the summary and its bulwark-* labels; the status is yours.",
        "",
    ]
    for m in members:
        where = f" -- {base}/app/projects/{m.asset_id}/issues/{m.id}" if base else ""
        lines.append(f"- {m.severity.upper()} {m.title} ({m.path}){where}")
    return "\n".join(lines)


def _digest(summary: str, labels: list[str], members: Sequence[IssueRow]) -> str:
    h = hashlib.sha256("\x1f".join([summary, *sorted(labels)]).encode()).hexdigest()[:56]
    fixed = all(m.state not in OPEN_STATES for m in members)
    return f"{h}:{'F' if fixed else 'O'}"


# --- links ----------------------------------------------------------------------------------------


def links_for_ticket(
    s: Session, org_id: str, provider: str, external_id: str
) -> list[ExternalIssueLinkRow]:  # noqa: E501
    return list(
        s.scalars(
            select(ExternalIssueLinkRow).where(
                ExternalIssueLinkRow.org_id == org_id,
                ExternalIssueLinkRow.provider == provider,
                ExternalIssueLinkRow.external_id == external_id,
            )
        )
    )


def link_for_issue(s: Session, issue_id: str) -> ExternalIssueLinkRow | None:
    return s.scalars(
        select(ExternalIssueLinkRow)
        .where(ExternalIssueLinkRow.issue_id == issue_id)
        .order_by(ExternalIssueLinkRow.created_at.desc())
        .limit(1)
    ).first()


def _ticket_issues(s: Session, links: Sequence[ExternalIssueLinkRow]) -> list[IssueRow]:
    ids = [ln.issue_id for ln in links]
    return list(s.scalars(select(IssueRow).where(IssueRow.id.in_(ids)))) if ids else []


# --- filing ---------------------------------------------------------------------------------------


def file(s: Session, org_id: str, issue: IssueRow, *, actor: str) -> list[ExternalIssueLinkRow]:
    """File the Issue's ticket (its group's, if it is in one), or bring the existing one up to
    date. Commits."""
    cfg = ticket_config.get(s, issue.asset_id)
    if cfg is None or not cfg.enabled:
        raise TicketError("This project has no ticket settings yet.")
    group, members = _members(s, issue)
    existing = None
    if group is not None:
        existing = s.scalars(
            select(ExternalIssueLinkRow)
            .where(
                ExternalIssueLinkRow.group_id == group.id,
                ExternalIssueLinkRow.provider == cfg.provider,
            )
            .limit(1)
        ).first()
    if existing is None:
        existing = s.scalars(
            select(ExternalIssueLinkRow).where(
                ExternalIssueLinkRow.issue_id == issue.id,
                ExternalIssueLinkRow.provider == cfg.provider,
            )
        ).first()
    provider = _provider(s, org_id, cfg)
    if existing is None:
        summary, labels = fields_for(group, members)
        external_id, url = provider.create(summary, description_for(group, members), labels)
    else:
        external_id, url = existing.external_id, existing.external_url
    already = {
        ln.issue_id
        for ln in s.scalars(
            select(ExternalIssueLinkRow).where(
                ExternalIssueLinkRow.issue_id.in_([m.id for m in members]),
                ExternalIssueLinkRow.provider == cfg.provider,
            )
        )
    }
    added = []
    for m in members:
        if m.id in already:
            continue  # it already has a ticket of its own with this provider
        s.add(
            ExternalIssueLinkRow(
                issue_id=m.id,
                org_id=org_id,
                provider=cfg.provider,
                external_id=external_id,
                external_url=url,
                group_id=group.id if group else None,
            )
        )
        added.append(m)
    s.flush()
    for m in added:
        repo.append_audit_entry(  # commits
            s,
            actor=actor,
            action="issue.ticket.filed",
            target=m.id,
            payload={
                "asset_id": m.asset_id,
                "ticket": external_id,
                "url": url,
                "group_id": group.id if group else None,
            },
        )
    if existing is not None and added:
        provider.comment(
            external_id,
            f"Bulwark added {len(added)} issue"
            f"{'s' if len(added) != 1 else ''} to this ticket: "
            + "; ".join(m.title[:120] for m in added),
        )
    push(s, org_id, cfg.provider, external_id, provider=provider)
    if existing is None:
        # Read the new ticket once, so its status shows at once; a first read never acts.
        try:
            apply_remote(s, org_id, cfg.provider, external_id, provider.read(external_id))
        except Exception:  # noqa: BLE001 - the ticket exists; the poll reads it later
            s.rollback()
            log.warning("could not read %s just after filing it", external_id, exc_info=True)
    s.commit()
    return links_for_ticket(s, org_id, cfg.provider, external_id)


# --- push -----------------------------------------------------------------------------------------


def push(
    s: Session,
    org_id: str,
    provider_kind: str,
    external_id: str,
    *,
    provider: Provider | None = None,
) -> bool:
    """Write what Bulwark owns, if it changed. True when it wrote something."""
    links = links_for_ticket(s, org_id, provider_kind, external_id)
    issues = _ticket_issues(s, links)
    if not issues:
        return False
    cfg = ticket_config.get(s, issues[0].asset_id)
    if cfg is None or not cfg.enabled or cfg.provider != provider_kind:
        return False
    provider = provider or _provider(s, org_id, cfg)
    group_id = next((ln.group_id for ln in links if ln.group_id), None)
    group = s.get(IssueGroup, group_id) if group_id else None
    summary, labels = fields_for(group, issues)
    new = _digest(summary, labels, issues)
    old = next((ln.pushed_digest for ln in links if ln.pushed_digest), None)
    if new == old:
        return False
    if old is None or old.split(":")[0] != new.split(":")[0]:
        if old is not None:  # just created: the ticket already says this
            provider.update(external_id, summary, labels)
    if old is not None and old.split(":")[1] != new.split(":")[1]:
        fixed = new.endswith(":F")
        if cfg.status_source == "platform":
            provider.set_closed(external_id, fixed)
        else:
            provider.comment(
                external_id,
                (
                    "Bulwark no longer detects "
                    + ("this issue." if len(issues) == 1 else "any of these issues.")
                    if fixed
                    else "Bulwark detects this again: it is not fixed."
                ),
            )
    for ln in links:
        ln.pushed_digest, ln.updated_at = new, _now()
    s.commit()
    return True


# --- pull -----------------------------------------------------------------------------------------


def apply_remote(
    s: Session, org_id: str, provider_kind: str, external_id: str, remote: Remote
) -> list[str]:
    """Record what the ticket says, and act on a status change. Returns what it did, per Issue."""
    from core.retest.service import RetestError, act

    links = links_for_ticket(s, org_id, provider_kind, external_id)
    if not links:
        return []
    issues = _ticket_issues(s, links)
    cfg = ticket_config.get(s, issues[0].asset_id) if issues else None
    previous = links[0].raw_status
    for ln in links:
        ln.raw_status, ln.external_assignee = remote.status[:100], remote.assignee
        ln.external_status, ln.synced_at = ("closed" if remote.closed else "open"), _now()
    s.commit()
    if previous is None or previous == remote.status or cfg is None:
        return []  # first sight of the ticket, or no change: nothing to act on
    effect = "none"
    if cfg.status_source == "ticket":
        effect = ticket_config.effect_of(cfg, remote.status, remote.category)
    done: list[str] = []
    for issue in issues:
        said = "none"
        if (
            effect == "ready_for_retest"
            and issue.state in OPEN_STATES
            and issue.retest_status != "requested"
        ):
            try:
                act(
                    s,
                    issue,
                    "request",
                    actor=f"ticket:{external_id}",
                    note=f"{external_id} moved to “{remote.status}”.",
                )
                said = "marked ready for retest"
            except RetestError:
                said = "none"
        repo.add_outbox_event(
            s,
            org_id=org_id,
            event_type="issue.ticket_status",
            payload={
                "issue_id": issue.id,
                "asset_id": issue.asset_id,
                "ticket": external_id,
                "status": remote.status,
                "previous": previous,
                "effect": None if said == "none" else f"Bulwark {said}.",
            },
        )
        done.append(said)
    s.commit()
    return done


def pull(s: Session, org_id: str, provider_kind: str, external_id: str) -> list[str]:
    links = links_for_ticket(s, org_id, provider_kind, external_id)
    issues = _ticket_issues(s, links)
    cfg = ticket_config.get(s, issues[0].asset_id) if issues else None
    if cfg is None or not cfg.enabled:
        return []
    remote = _provider(s, org_id, cfg).read(external_id)
    return apply_remote(s, org_id, provider_kind, external_id, remote)


def sync_due(s: Session, org_id: str, *, now: datetime | None = None) -> int:
    """The poll: every linked ticket not synced in the last ten minutes, both ways."""
    now = now or _now()
    rows = s.execute(
        select(ExternalIssueLinkRow.provider, ExternalIssueLinkRow.external_id)
        .join(IssueRow, IssueRow.id == ExternalIssueLinkRow.issue_id)
        .join(TicketConfig, TicketConfig.asset_id == IssueRow.asset_id)
        .where(
            ExternalIssueLinkRow.org_id == org_id,
            TicketConfig.enabled.is_(True),
            TicketConfig.provider == ExternalIssueLinkRow.provider,
            or_(
                ExternalIssueLinkRow.synced_at.is_(None),
                ExternalIssueLinkRow.synced_at < now - STALE_AFTER,
            ),
        )
        .distinct()
        .limit(POLL_LIMIT)
    ).all()
    n = 0
    for kind, external_id in rows:
        try:
            pull(s, org_id, kind, external_id)
            push(s, org_id, kind, external_id)
            n += 1
        except Exception:  # noqa: BLE001 - one ticket failing must not stop the rest
            s.rollback()
            log.warning("ticket sync failed for %s %s", kind, external_id, exc_info=True)
    return n


# --- from events ----------------------------------------------------------------------------------

PUSH_ON = ("issue.closed", "issue.reopened", "issue.retest_passed", "issue.retest_failed")


def on_events(s: Session, org_id: str, events: Sequence[Any]) -> int:
    """The dispatcher's subscriber: an Issue on a ticket was fixed or came back."""
    issue_ids = {e.payload.get("issue_id") for e in events if e.type in PUSH_ON}
    issue_ids.discard(None)
    if not issue_ids:
        return 0
    tickets = set(
        s.execute(
            select(ExternalIssueLinkRow.provider, ExternalIssueLinkRow.external_id).where(
                ExternalIssueLinkRow.org_id == org_id, ExternalIssueLinkRow.issue_id.in_(issue_ids)
            )
        ).all()
    )
    n = 0
    for kind, external_id in tickets:
        try:
            n += int(push(s, org_id, kind, external_id))
        except Exception:  # noqa: BLE001
            s.rollback()
            log.warning("ticket push failed for %s %s", kind, external_id, exc_info=True)
    return n


def view(s: Session, issue: IssueRow) -> dict[str, Any] | None:
    ln = link_for_issue(s, issue.id)
    if ln is None:
        return None
    return {
        "provider": ln.provider,
        "id": ln.external_id,
        "url": ln.external_url,
        "status": ln.raw_status,
        "closed": ln.external_status == "closed",
        "assignee": ln.external_assignee,
        "synced_at": ln.synced_at,
        "group_id": ln.group_id,
    }
