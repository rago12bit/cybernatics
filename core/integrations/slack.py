"""Slack incoming-webhook notifications (Week 51 task 2, plan §23). Slack's own webhook format:
POST a JSON body with a top-level `text` field to the URL Slack generated when the operator added an
"Incoming Webhook" to their workspace -- no further auth, since the URL itself is the secret.
"""

from __future__ import annotations

from typing import Any

from core.ci.github import Transport, http_transport
from core.integrations.webhooks import deliver_plain
from core.netsafety import Resolver, default_resolver


def scan_summary_payload(
    *, asset_label: str, scan_id: str, new_count: int, reintroduced_count: int, fixed_count: int
) -> dict[str, Any]:
    if new_count == 0 and reintroduced_count == 0 and fixed_count == 0:
        text = f"✅ Bulwark scan of *{asset_label}* found no new issues."
    else:
        parts = []
        if new_count:
            parts.append(f"{new_count} new")
        if reintroduced_count:
            parts.append(f"{reintroduced_count} reintroduced")
        if fixed_count:
            parts.append(f"{fixed_count} fixed")
        text = f"🛡️ Bulwark scan of *{asset_label}*: {', '.join(parts)}. (`{scan_id}`)"
    return {"text": text}


def send(
    webhook_url: str,
    payload: dict[str, Any],
    *,
    resolver: Resolver = default_resolver,
    transport: Transport = http_transport,
) -> None:
    deliver_plain(webhook_url, payload, resolver=resolver, transport=transport)
