"""Where a project's tickets go, and which side owns each field (plan §49: "for each field, one side
is the source of truth -- status from the ticket, severity from the platform -- instead of
last-writer-wins").

- Severity, title and Bulwark's own labels: always the platform. A sync writes them when they
  change; edits on the ticket to them are overwritten at the next sync.
- Status: the ticket by default. Each of the ticket's statuses maps to what it means here: nothing,
  or "ready for retest" (closing the ticket says "fixed, please verify"; the next scan or a tester
  decides). Bulwark never marks an Issue fixed because a ticket closed. With `status_source`
  "platform", it is the other way round: Bulwark closes the ticket when every Issue on it is fixed
  and reopens it when one comes back, and ignores the ticket's status.
- Assignee: the ticket. Bulwark shows who has the ticket and never writes it.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.persistence import repo
from core.persistence.models import TicketConfig

PROVIDERS = ("jira", "github")
STATUS_SOURCES = ("ticket", "platform")
EFFECTS = ("none", "ready_for_retest")
DEFAULT_MAP = {
    "jira": {"done": "ready_for_retest"},  # by Jira's status category when no name matches
    "github": {"closed": "ready_for_retest", "closed (not planned)": "none"},
}
_JIRA_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,19}$")
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class ConfigError(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def get(s: Session, asset_id: str) -> TicketConfig | None:
    return s.scalars(select(TicketConfig).where(TicketConfig.asset_id == asset_id)).one_or_none()


def effective_map(cfg: TicketConfig) -> dict[str, str]:
    return {
        **DEFAULT_MAP.get(cfg.provider, {}),
        **{k.lower(): v for k, v in cfg.status_map.items()},
    }


def effect_of(cfg: TicketConfig, status: str, category: str | None = None) -> str:
    m = effective_map(cfg)
    found = m.get(status.strip().lower())
    if found is None and category:
        found = m.get(category.lower())
    return found if found in EFFECTS else "none"


def save(
    s: Session, org_id: str, asset_id: str, raw: dict[str, Any], *, actor: str
) -> TicketConfig:
    provider = raw.get("provider")
    if provider not in PROVIDERS:
        raise ConfigError("provider", "Jira or GitHub Issues.")
    target = str(raw.get("target") or "").strip()
    if provider == "jira" and not _JIRA_KEY.match(target):
        raise ConfigError("target", "A Jira project key, like PAY.")
    if provider == "github" and not _REPO.match(target):
        raise ConfigError("target", "owner/repository.")
    source = raw.get("status_source", "ticket")
    if source not in STATUS_SOURCES:
        raise ConfigError("status_source", "ticket or platform.")
    status_map: dict[str, str] = {}
    for name, effect in (raw.get("status_map") or {}).items():
        key = " ".join(str(name).split()).lower()[:100]
        if not key or effect not in EFFECTS:
            raise ConfigError("status_map", f"Each status maps to one of: {', '.join(EFFECTS)}.")
        status_map[key] = effect
    if len(status_map) > 50:
        raise ConfigError("status_map", "At most 50 statuses.")
    issue_type = str(raw.get("issue_type") or "").strip()[:64] or None
    settings = repo.get_integration_settings(s, org_id)
    if provider == "jira" and not (
        settings and settings.jira_base_url and settings.jira_email and settings.jira_api_token
    ):
        raise ConfigError(
            "provider",
            "Jira's address, email and API token are not set yet " "(Settings, integrations).",
        )
    if provider == "github" and not (settings and settings.github_token):
        raise ConfigError("provider", "No GitHub token is set yet (Settings, integrations).")
    row = get(s, asset_id)
    if row is None:
        row = TicketConfig(org_id=org_id, asset_id=asset_id)
        s.add(row)
    row.provider, row.target, row.status_source = provider, target, source
    row.status_map, row.issue_type = status_map, issue_type
    row.enabled = bool(raw.get("enabled", True))
    row.updated_by, row.updated_at = actor, datetime.now(timezone.utc)
    s.flush()
    repo.append_audit_entry(  # commits
        s,
        actor=actor,
        action="tickets.config.changed",
        target=f"asset:{asset_id}",
        payload={
            "org_id": org_id,
            "provider": provider,
            "target": target,
            "status_source": source,
            "status_map": status_map,
            "enabled": row.enabled,
        },
    )
    return row
