"""Create and update Jira tickets from Bulwark Issues (Week 51 task 2, plan §23).

Authenticates with HTTP Basic Auth using an Atlassian account email + API token -- Jira Cloud's own
documented auth scheme for the REST API, no OAuth app registration required, matching the plain-
credential posture `core.integrations.github_issues` uses for GitHub.

Deliberately does not attempt to drive Jira's workflow-transition API to close/reopen a ticket:
transition ids are per-project-configurable workflow state, with no universal "closed" id this code
could assume -- attempting it would mean either a brittle guess or a second settings field asking
the operator to name their own project's exact transition id for a feature most workflows differ on
anyway. Instead, a status change adds a comment recording what Bulwark observed ("marked fixed by
scan <id>" / "reintroduced"); the operator's own workflow (or a person) still owns the ticket's
actual status. This is a disclosed scope cut, not an oversight -- see this module's own tests and
docs/v2-week51-verification.md.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from core.ci.github import Transport, http_transport


class JiraError(RuntimeError):
    pass


@dataclass(frozen=True)
class CreatedTicket:
    key: str
    url: str


def _headers(email: str, api_token: str) -> dict[str, str]:
    basic = base64.b64encode(f"{email}:{api_token}".encode()).decode()
    return {
        "Authorization": f"Basic {basic}",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "bulwark-integrations",
    }


def create_ticket(
    base_url: str,
    email: str,
    api_token: str,
    project_key: str,
    summary: str,
    description: str,
    *,
    issue_type: str = "Bug",
    transport: Transport = http_transport,
) -> CreatedTicket:
    base = base_url.rstrip("/")
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary[:255],
            "description": {
                "type": "doc", "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": description}]}
                ],
            },  # fmt: skip
            "issuetype": {"name": issue_type},
        }
    }
    status, data = transport(
        "POST", f"{base}/rest/api/3/issue", _headers(email, api_token), json.dumps(payload).encode()
    )  # fmt: skip
    if status not in (200, 201) or not isinstance(data, dict) or "key" not in data:
        raise JiraError(f"could not create a ticket in project {project_key} (HTTP {status})")
    key = str(data["key"])
    return CreatedTicket(key=key, url=f"{base}/browse/{key}")


def add_comment(
    base_url: str,
    email: str,
    api_token: str,
    issue_key: str,
    body: str,
    *,
    transport: Transport = http_transport,
) -> None:
    base = base_url.rstrip("/")
    payload = {
        "body": {
            "type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": body}]}],
        }
    }  # fmt: skip
    status, _ = transport(
        "POST", f"{base}/rest/api/3/issue/{issue_key}/comment", _headers(email, api_token),
        json.dumps(payload).encode(),
    )  # fmt: skip
    if status != 201:
        raise JiraError(f"could not comment on {issue_key} (HTTP {status})")
