"""Microsoft Teams notifications (Week 66, plan §49), through a Teams "Workflows" incoming webhook:
POST an Adaptive Card wrapped in a `message` attachment. (Office 365 connector webhooks, which took
MessageCards, are being retired by Microsoft; Workflows webhooks take this shape.)

The URL is the secret and passes the same SSRF guard as every other webhook. Card text supports a
little Markdown, and issue titles are untrusted, so the characters that make links and emphasis are
escaped before they go in.
"""

from __future__ import annotations

import re
from typing import Any

from core.ci.github import Transport, http_transport
from core.integrations.webhooks import deliver_plain
from core.netsafety import Resolver, default_resolver

_MD = re.compile(r"([\\`*_\[\]()<>#|~])")
MAX_TEXT = 4000


def escape(text: str) -> str:
    return _MD.sub(r"\\\1", text)


def card(text: str, title: str | None = None) -> dict[str, Any]:
    body: list[dict[str, Any]] = []
    if title:
        body.append({"type": "TextBlock", "text": escape(title)[:200], "weight": "Bolder",
                     "size": "Medium", "wrap": True})  # fmt: skip
    body.append({"type": "TextBlock", "text": escape(text)[:MAX_TEXT], "wrap": True})
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": body,
                },
            }
        ],
    }


def send(
    webhook_url: str,
    payload: dict[str, Any],
    *,
    resolver: Resolver = default_resolver,
    transport: Transport = http_transport,
) -> None:
    deliver_plain(webhook_url, payload, resolver=resolver, transport=transport)
