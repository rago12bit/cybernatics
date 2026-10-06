"""What Bulwark tells people about, and through which channels (plan §49).

A person's channels are the in-app inbox and email. The team's channels are the organization's
Slack, Discord, Microsoft Teams and outbound webhook. Each kind of event has a mode per channel:
off, instant, or digest (once a day, at the hour the person or team chose, UTC).
"""

from __future__ import annotations

PERSON_KINDS: dict[str, str] = {
    "mention": "Someone mentions you in a note",
    "assigned": "An issue is assigned to you",
    "note": "A new note on an issue you watch",
    "retest": "A retest is requested or decided on an issue you watch",
    "sla": "An SLA is due soon or breached on an issue you own or watch",
    "risk_acceptance": "A risk acceptance waits for you, or yours is decided or expiring",
    "ticket": "A linked ticket changes status on an issue you watch",
    "rules": "A rule names you, or waits for an Admin to confirm",
}
PERSON_CHANNELS: dict[str, tuple[str, ...]] = {
    "in_app": ("off", "instant"),
    "email": ("off", "instant", "digest"),
}
PERSON_DEFAULTS = {"in_app": "instant", "email": "digest"}

TEAM_KINDS: dict[str, str] = {
    "scan": "A scan or import completes",
    "sla": "Issues cross into due soon or breached",
    "risk_acceptance": "A risk acceptance is requested, decided or expires",
    "rules": "A rule's notify action",
}
TEAM_CHANNEL = "team"  # Slack, Discord, Teams and the webhook together
TEAM_MODES = ("off", "instant", "digest")
TEAM_DEFAULT = "instant"  # what every organization had before preferences existed
TEAM_OWNER = "team"
