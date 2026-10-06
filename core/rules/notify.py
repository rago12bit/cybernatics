"""A rule's "notify" action: one message to every channel the organization configured (plan §45).

Issue titles come from scanners reading other people's code, so they are untrusted text:
- Slack: `&`, `<` and `>` are escaped as Slack documents, so a title cannot become `<!channel>`, a
  user mention or a link.
- Discord: `allowed_mentions` is empty, so `@everyone` in a title pings nobody.
- The outbound webhook gets JSON, signed.
One channel failing does not stop the others.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from core.persistence import repo

log = logging.getLogger(__name__)
MAX_TEXT = 1900


def slack_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def send_rule_message(s: Session, org_id: str, text: str) -> list[str]:
    """Returns the channels it went to; raises only if every configured channel failed."""
    from core.integrations import discord, slack
    from core.integrations.webhooks import deliver_signed

    settings = repo.get_integration_settings(s, org_id)
    if settings is None:
        return []
    text = text[:MAX_TEXT]
    sent: list[str] = []
    errors: list[str] = []
    if settings.slack_webhook_url:
        try:
            slack.send(settings.slack_webhook_url, {"text": slack_escape(text)})
            sent.append("Slack")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Slack: {exc}")
    if settings.discord_webhook_url:
        try:
            discord.send(settings.discord_webhook_url,
                         {"content": text, "allowed_mentions": {"parse": []}})  # fmt: skip
            sent.append("Discord")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Discord: {exc}")
    if settings.outbound_webhook_url and settings.outbound_webhook_secret:
        try:
            deliver_signed(settings.outbound_webhook_url, {"type": "rule.notify", "text": text},
                           settings.outbound_webhook_secret)  # fmt: skip
            sent.append("webhook")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"webhook: {exc}")
    if errors and not sent:
        raise RuntimeError("; ".join(errors))
    for e in errors:
        log.warning("rule notification: %s", e)
    return sent
