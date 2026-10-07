"""Roles and what they allow (Week 75, plan §51: "scoped roles: organization roles gain
per-portfolio and per-project overrides that cascade downward, the way DefectDojo's product
permissions do").

A person has an organization role and, optionally, a higher role on some business units or
projects. The organization role is the floor everywhere; an override raises it on its business
unit's projects or on its project, never lowers it. `none` as the organization role means the
person sees only the projects an override grants -- a contractor on one engagement, say.

    viewer   read: scans, fixes, imports
    member   viewer, and change things: scan, triage, import, fix
    admin    member, and run the organization: rules, people and roles, sign-in settings

A role is turned into the token scopes the API already checks (core.tokens), so every route keeps
its one `require_scope(...)` line; what changes is that, for a person, the scopes depend on which
project the request is about.
"""

from __future__ import annotations

from dataclasses import dataclass, field

ORG_ROLES = ("admin", "member", "viewer", "none")
OVERRIDE_ROLES = ("admin", "member", "viewer")
RANK = {"none": 0, "viewer": 1, "member": 2, "admin": 3}

VIEWER = frozenset({"scans:read", "fixes:read", "ingest:read"})
MEMBER = VIEWER | {"scans:write", "fixes:write", "ingest:write"}
ADMIN = MEMBER | {"rules:write", "org:admin"}
SCOPES = {"none": frozenset(), "viewer": VIEWER, "member": MEMBER, "admin": ADMIN}


def higher(a: str, b: str) -> str:
    return a if RANK[a] >= RANK[b] else b


@dataclass(frozen=True)
class Access:
    """What one person may do, worked out once per request."""

    user_id: str
    role: str
    portfolios: dict[str, str] = field(default_factory=dict)  # portfolio id -> role
    projects: dict[str, str] = field(default_factory=dict)  # project id -> role
    #: Every project in a business unit with an override (filled in by core.identity.users)
    in_portfolios: dict[str, str] = field(default_factory=dict)  # project id -> its unit's role
    #: For a token the person made: what the token itself was given. Never more than the role.
    token_scopes: frozenset[str] | None = None

    def role_on(self, project_id: str | None) -> str:
        """The person's role on one project (None: the organization itself)."""
        role = self.role
        if project_id is not None:
            role = higher(role, self.in_portfolios.get(project_id, "none"))
            role = higher(role, self.projects.get(project_id, "none"))
        return role

    def scopes_on(self, project_id: str | None) -> frozenset[str]:
        scopes = SCOPES[self.role_on(project_id)]
        return scopes & self.token_scopes if self.token_scopes is not None else scopes

    def visible_projects(self) -> frozenset[str] | None:
        """None: every project of the organization. Otherwise exactly the granted ones."""
        if self.role != "none":
            return None
        return frozenset(self.projects) | frozenset(self.in_portfolios)
