"""Discord webhook notifications (Week 51 task 2, plan §23). Discord's own webhook format: POST a
JSON body with a top-level `content` field (max 2000 characters) -- same "the URL is the secret, no
further auth" model as Slack's incoming webhooks.
"""

from __future__ import annotations

from typing import Any

from core.ci.github import Transport, http_transport
from core.integrations.webhooks import deliver_plain
from core.netsafety import Resolver, default_resolver

_MAX_CONTENT_LEN = 2000


def scan_summary_payload(
    *, asset_label: str, scan_id: str, new_count: int, reintroduced_count: int, fixed_count: int
) -> dict[str, Any]:
    if new_count == 0 and reintroduced_count == 0 and fixed_count == 0:
        content = f"✅ Bulwark scan of **{asset_label}** found no new issues."
    else:
        parts = []
        if new_count:
            parts.append(f"{new_count} new")
        if reintroduced_count:
            parts.append(f"{reintroduced_count} reintroduced")
        if fixed_count:
            parts.append(f"{fixed_count} fixed")
        content = f"🛡️ Bulwark scan of **{asset_label}**: {', '.join(parts)}. (`{scan_id}`)"
    return {"content": content[:_MAX_CONTENT_LEN]}


def send(
    webhook_url: str,
    payload: dict[str, Any],
    *,
    resolver: Resolver = default_resolver,
    transport: Transport = http_transport,
) -> None:
    deliver_plain(webhook_url, payload, resolver=resolver, transport=transport)
