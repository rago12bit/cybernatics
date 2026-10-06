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
from typing import Any

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
    labels: list[str] | None = None,
    transport: Transport = http_transport,
) -> CreatedTicket:
    base = base_url.rstrip("/")
    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary[:255],
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": description}]}
                ],
            },
            "issuetype": {"name": issue_type},
        }
    }
    if labels:
        payload["fields"]["labels"] = labels
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


# --- Week 66 (plan §49): two-way sync -------------------------------------------------------------


@dataclass(frozen=True)
class TicketState:
    status: str  # the workflow's own status name, e.g. "In Review"
    category: str  # Jira's fixed statusCategory key: "new" | "indeterminate" | "done"
    assignee: str | None  # display name


def _ok(status: int, expected: tuple[int, ...], what: str) -> None:
    if status not in expected:
        raise JiraError(f"could not {what} (HTTP {status})")


def get_ticket(
    base_url: str, email: str, api_token: str, key: str, *, transport: Transport = http_transport
) -> TicketState:
    base = base_url.rstrip("/")
    status, data = transport(
        "GET", f"{base}/rest/api/3/issue/{key}?fields=status,assignee", _headers(email, api_token),
        None,
    )  # fmt: skip
    _ok(status, (200,), f"read {key}")
    fields = (data or {}).get("fields") or {} if isinstance(data, dict) else {}
    st = fields.get("status") or {}
    assignee = fields.get("assignee") or {}
    return TicketState(
        status=str(st.get("name") or ""),
        category=str((st.get("statusCategory") or {}).get("key") or ""),
        assignee=str(assignee["displayName"]) if assignee.get("displayName") else None,
    )


def update_ticket(
    base_url: str,
    email: str,
    api_token: str,
    key: str,
    *,
    summary: str,
    add_labels: list[str],
    remove_labels: list[str],
    transport: Transport = http_transport,
) -> None:
    """Only the fields Bulwark owns: the summary, and its own labels added or removed one by one
    (Jira's `update` verbs), so labels someone added by hand stay."""
    base = base_url.rstrip("/")
    ops = [{"add": x} for x in add_labels] + [{"remove": x} for x in remove_labels]
    body: dict[str, Any] = {"fields": {"summary": summary[:255]}}
    if ops:
        body["update"] = {"labels": ops}
    status, _ = transport(
        "PUT",
        f"{base}/rest/api/3/issue/{key}",
        _headers(email, api_token),
        json.dumps(body).encode(),
    )
    _ok(status, (200, 204), f"update {key}")


def transition_to(
    base_url: str,
    email: str,
    api_token: str,
    key: str,
    category: str,
    *,
    transport: Transport = http_transport,
) -> bool:
    """Move the ticket to the first available status in `category` ("done" to close, "new" or
    "indeterminate" to reopen). Workflows name their statuses as they like, but every status has
    one of Jira's three categories, so this needs no per-project transition ids. False when the
    workflow offers no such transition from where the ticket is."""
    base = base_url.rstrip("/")
    status, data = transport(
        "GET", f"{base}/rest/api/3/issue/{key}/transitions", _headers(email, api_token), None
    )
    _ok(status, (200,), f"list transitions of {key}")
    wanted = (category,) if category == "done" else ("new", "indeterminate")
    for t in (data or {}).get("transitions", []) if isinstance(data, dict) else []:
        to = t.get("to") or {}
        if (to.get("statusCategory") or {}).get("key") in wanted:
            status, _ = transport(
                "POST", f"{base}/rest/api/3/issue/{key}/transitions", _headers(email, api_token),
                json.dumps({"transition": {"id": str(t.get("id"))}}).encode(),
            )  # fmt: skip
            _ok(status, (204,), f"transition {key}")
            return True
    return False
