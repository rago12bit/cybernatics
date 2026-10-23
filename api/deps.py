"""Dependency wiring. Everything external is injected so tests can substitute fakes."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from fastapi import Depends, HTTPException, Request, WebSocket
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from core.config import Settings
from core.identity import sessions as web_sessions
from core.identity.roles import Access
from core.llm.budget import BudgetConfig
from core.llm.client import LLMClient
from core.llm.limits import UsageLimiter
from core.persistence.db import SessionFactory
from core.tenancy import DEFAULT_ORG_ID, ORG_HEADER, set_session_org

_bearer = HTTPBearer(auto_error=False)


class EventSubscriber(Protocol):
    def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]: ...


@dataclass
class AppState:
    settings: Settings
    sessions: SessionFactory
    enqueue: Callable[[str, str], None]  # (scan_id, org_id) -> dispatches a scan job to the worker
    subscriber: EventSubscriber
    # (scan_id, org_id) -> dispatches a DAST campaign job (Week 49 task 3, plan §22.4). Defaults to
    # a no-op so every existing AppState(...) call built positionally (tests predating this field)
    # keeps working unchanged rather than needing to pass one.
    enqueue_dast_campaign: Callable[[str, str], None] = lambda *_: None
    # (import_id, org_id) -> dispatches an uploaded report to the worker (Week 54 task 7, ADR-0040).
    # A no-op default for the same reason as above: an AppState built without it still works.
    enqueue_import: Callable[[str, str], None] = lambda *_: None
    llm: LLMClient | None = None  # None: AI suggestions are off; guidance is static reference text
    limiter: UsageLimiter = field(default_factory=UsageLimiter)  # caps real model calls (rate)
    llm_budget: BudgetConfig = field(default_factory=BudgetConfig.from_env)  # caps them by tokens
    llm_triage: LLMClient | None = None  # None: the triage assistant is off (plan §21.3)
    llm_hypotheses: LLMClient | None = None  # None: the Hypotheses lane is off (plan §21.4)
    llm_copilot: LLMClient | None = None  # None: the copilot is off (plan §21.5)
    llm_attack_path: LLMClient | None = None  # None: attack-path narratives are off (plan §21.6)
    llm_mapper: LLMClient | None = None  # None: mapping drafts match field names (plan §42.4)
    llm_report: LLMClient | None = None  # None: report summaries are written by people (§48.3)
    # Render a queued report (run_id, org_id) on the worker; None renders it in the request.
    enqueue_report: Callable[[str, str], None] | None = None
    # (connector_id, org_id) -> runs a connector on the worker (Week 60, plan §42.5). None: "Run
    # now" runs it in the request -- tests and worker-less local development.
    enqueue_connector: Callable[[str, str], None] | None = None
    # (priority_policy_id, org_id) -> re-ranks a project's Issues on the worker (Week 63, plan
    # §44.3). None: the API does it after responding, in its own process.
    enqueue_priority: Callable[[str, str], None] | None = None
    # (retest_run_id, org_id) -> runs a targeted retest on the worker (Week 64, plan §43.3). None:
    # the API does it after responding, in its own process.
    enqueue_retest: Callable[[str, str], None] | None = None
    # The HTTP client single sign-on uses to reach identity providers (Week 75); None makes one per
    # call. Tests pass one backed by a fake provider.
    sso_http: Any = None


def state(request: Request) -> AppState:
    st: AppState = request.app.state.bulwark
    return st


#: The most a webhook body may be. GitHub caps its own payloads at 25 MB; Jira's are far smaller.
WEBHOOK_MAX_BYTES = 25 * 1024 * 1024


async def read_capped_body(request: Request, limit: int | None = None) -> bytes:
    """The request body, refused with 413 once it passes `limit`. For the routes anyone can reach
    (webhooks), which read the body before they can check who sent it: uvicorn sets no limit, so
    `await request.body()` would hold whatever an anonymous caller sends."""
    limit = WEBHOOK_MAX_BYTES if limit is None else limit
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, f"request body over {limit} bytes")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > limit:
            raise HTTPException(413, f"request body over {limit} bytes")
    return bytes(body)


def token_ok(supplied: str | None, expected: str) -> bool:
    return bool(supplied) and hmac.compare_digest(supplied.encode(), expected.encode())  # type: ignore[union-attr]


@dataclass(frozen=True)
class AuthContext:
    """What a request authenticated as (Week 29 backfill, ADR-0018).

    `org_id=None, scopes=None` is the legacy single shared `BULWARK_API_TOKEN` -- "the whole
    deployment," matching v1.0/Week 29's original trust model: full access, org selected separately
    by `current_org` (the `X-Bulwark-Org` header, defaulting to the bootstrap org).

    `org_id` set is a real scoped token (`core/tokens.py`): its org is fixed and authoritative, not
    client-suppliable, and `scopes` is the exact, non-empty set of actions it may perform -- this is
    what actually closes the gap ADR-0013 documented as a known limitation ("a caller that knows the
    token can claim any org id")."""

    org_id: str | None
    scopes: frozenset[str] | None
    actor: str  # for audit-log attribution: "user:<id>", "token:<display_prefix>", "shared-token"
    #: Week 75: a signed-in person, or a token a person made. Their role decides their scopes,
    #: project by project (`require_scope`), and which projects they see at all (`db`). `scopes`
    #: is then their organization-level scopes, never None: None means the shared token.
    access: Access | None = None


def _scoped_token_context(st: AppState, raw: str) -> AuthContext | None:
    """A DB lookup that must not be org-scoped (see `core.persistence.repo.get_api_token_by_hash`'s
    docstring) -- this IS how org context gets resolved, so it can't depend on org context already
    existing. Uses a fresh, unscoped session, not `Depends(db)`."""
    from core.tokens import hash_token, verify_checksum

    if not verify_checksum(raw):
        return None
    with st.sessions() as s:
        from core.persistence import repo

        row = repo.get_api_token_by_hash(s, hash_token(raw))
        if row is None or row.revoked_at is not None:
            return None
        # SQLite (tests) hands back a naive datetime even for a `DateTime(timezone=True)` column;
        # every timestamp this codebase writes is UTC (`core.persistence.models._now`), so a naive
        # value is always meant as UTC, never the local zone.
        expires_at = row.expires_at
        if expires_at is not None:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at <= datetime.now(timezone.utc):
                return None
        repo.touch_api_token(s, row.id)
        if row.user_id is not None:
            # A token a person made acts as them, within both its own scopes and their role now.
            return _person_context(s, row.org_id, row.user_id, frozenset(row.scopes))
        return AuthContext(
            org_id=row.org_id, scopes=frozenset(row.scopes), actor=f"token:{row.display_prefix}"
        )


def _person_context(
    s: Session, org_id: str, user_id: str, token_scopes: frozenset[str] | None = None
) -> AuthContext | None:
    """A person's context, or None when they are turned off or gone. Their overrides are read
    under their organization's RLS, with every project visible (the scope comes from this)."""
    from core.identity.users import access_for, actor_of
    from core.persistence.models import User

    set_session_org(s, org_id)
    u = s.get(User, user_id)
    if u is None or u.org_id != org_id or not u.active:
        return None
    access = access_for(s, u, token_scopes)
    return AuthContext(org_id=org_id, scopes=access.scopes_on(None), actor=actor_of(u.id),
                       access=access)  # fmt: skip


_UNSAFE = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _session_context(request: Request, st: AppState) -> AuthContext | None:
    """A browser signed in with a session cookie (core.identity.sessions). A change needs the
    session's CSRF token in a header as well."""
    secret = request.cookies.get(web_sessions.COOKIE)
    if not secret:
        return None
    with st.sessions() as s:
        row = web_sessions.resolve(s, secret)
        if row is None:
            return None
        if request.method in _UNSAFE and not web_sessions.csrf_ok(
            row, request.headers.get(web_sessions.CSRF_HEADER)
        ):
            raise HTTPException(403, "missing or wrong CSRF token; reload the page")
        return _person_context(s, row.org_id, row.user_id)


def require_auth(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    st: AppState = Depends(state),
) -> AuthContext:
    if creds is None:
        signed_in = _session_context(request, st)
        if signed_in is not None:
            return signed_in
        raise HTTPException(401, "invalid or missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})  # fmt: skip
    if token_ok(creds.credentials, st.settings.api_token):
        return AuthContext(org_id=None, scopes=None, actor="shared-token")
    scoped = _scoped_token_context(st, creds.credentials)
    if scoped is not None:
        return scoped
    raise HTTPException(401, "invalid or missing bearer token",
                        headers={"WWW-Authenticate": "Bearer"})  # fmt: skip


#: Path parameters that name a project, or something that belongs to one, and how to find it.
_PROJECT_OF: tuple[tuple[str, str], ...] = (
    ("asset_id", "SELECT id FROM assets WHERE id = :v"),
    ("project_id", "SELECT id FROM assets WHERE id = :v"),
    ("scan_id", "SELECT asset_id FROM scans WHERE id = :v"),
    ("issue_id", "SELECT asset_id FROM issues WHERE id = :v"),
    ("acceptance_id", "SELECT asset_id FROM risk_acceptances WHERE id = :v"),
    ("engagement_id", "SELECT asset_id FROM engagements WHERE id = :v"),
    ("manual_id", "SELECT asset_id FROM manual_findings WHERE id = :v"),
    ("statement_id", "SELECT asset_id FROM vex_statements WHERE id = :v"),
    ("group_id", "SELECT asset_id FROM issue_groups WHERE id = :v"),
    ("note_id", "SELECT i.asset_id FROM issue_notes n JOIN issues i ON i.id = n.issue_id "
                "WHERE n.id = :v"),
    ("test_id", "SELECT e.asset_id FROM engagement_tests t JOIN engagements e "
                "ON e.id = t.engagement_id WHERE t.id = :v"),
    ("import_id", "SELECT e.asset_id FROM import_records r JOIN engagement_tests t "
                  "ON t.id = r.test_id JOIN engagements e ON e.id = t.engagement_id "
                  "WHERE r.id = :v"),
)  # fmt: skip
_MISSING = object()

#: Organization-level routes someone limited to some projects (organization role `none`) may
#: still read: what they return is already limited to their projects (RLS and the app filter), or
#: is their own. Organization-wide pages -- dashboards, reports, rules, evidence -- are not here:
#: they are for people with an organization role.
GUEST_ROUTES = frozenset({
    "/assets", "/v2/issues", "/v2/issues/parse", "/v2/issues/suggest", "/v2/issue-views",
    "/v2/issue-views/{view_id}", "/v2/issue-views/{view_id}/copy", "/v2/issue-views/import",
    "/v2/me", "/v2/me/role", "/v2/me/assigned", "/v2/me/engagements", "/v2/me/tables/{table}",
    "/v2/notifications", "/v2/notifications/read", "/v2/mentions", "/v2/calendar",
})  # fmt: skip


def _project_of(st: AppState, auth: AuthContext, params: dict[str, Any]) -> object:
    """The project a request is about (from its path), None for an organization-level request,
    or _MISSING when the path names something this person cannot see."""
    from sqlalchemy import text

    for name, sql in _PROJECT_OF:
        value = params.get(name)
        if not value:
            continue
        if len(str(value)) > 64:
            return _MISSING
        assert auth.org_id is not None and auth.access is not None
        with st.sessions() as s:
            set_session_org(s, auth.org_id, auth.access.visible_projects())
            found = s.execute(text(sql), {"v": str(value)}).scalar()
            if found is not None and _visible(s, str(found), auth.access):
                return str(found)
        return _MISSING
    return None


def _visible(s: Session, project_id: str, access: Access) -> bool:
    """Postgres's RLS already hid everything else; SQLite (tests) has none, so check here too."""
    from core.persistence.models import Asset

    seen = access.visible_projects()
    a = s.get(Asset, project_id)
    return a is not None and (seen is None or project_id in seen)


def require_scope(scope: str) -> Callable[..., None]:
    """`auth.scopes is None` (the legacy shared token) is treated as "every scope" -- the existing
    self-hosted, single-operator trust model already grants it unrestricted access; scopes only
    narrow what a *real* scoped token (`core/tokens.py`) may do."""

    def _check(
        request: Request, auth: AuthContext = Depends(require_auth), st: AppState = Depends(state)
    ) -> None:
        if auth.access is not None:
            # A person: their role on the project the request is about, else in the organization.
            project = _project_of(st, auth, request.path_params)
            if project is _MISSING:
                raise HTTPException(404, "not found")
            allowed = auth.access.scopes_on(project if isinstance(project, str) else None)
            route = getattr(request.scope.get("route"), "path", "")
            if (project is None and auth.access.role == "none" and route in GUEST_ROUTES
                    and scope.endswith(":read") and auth.access.visible_projects()):  # fmt: skip
                return
            if scope not in allowed:
                where = "this project" if isinstance(project, str) else "this organization"
                raise HTTPException(403, f"your role in {where} does not allow this ('{scope}')")
            return
        if auth.scopes is not None and scope not in auth.scopes:
            raise HTTPException(403, f"this token does not have the '{scope}' scope")

    return _check


def websocket_auth(ws: WebSocket, st: AppState, token: str) -> AuthContext | None:
    """Who a WebSocket connected as, by the same rules as `require_auth`: a token from the first
    message (the shared token or a scoped one), else the browser's session cookie. The cookie only
    counts from an origin the API already trusts (`cors_origins`): a browser sends cookies with any
    page's WebSocket handshake and no CORS check applies to what comes back, so without this another
    site could read a signed-in person's scans (cross-site WebSocket hijacking)."""
    if token:
        if token_ok(token, st.settings.api_token):
            return AuthContext(org_id=None, scopes=None, actor="shared-token")
        return _scoped_token_context(st, token)
    secret = ws.cookies.get(web_sessions.COOKIE)
    if not secret or ws.headers.get("origin") not in st.settings.cors_origins:
        return None
    with st.sessions() as s:
        row = web_sessions.resolve(s, secret)
        return None if row is None else _person_context(s, row.org_id, row.user_id)


def may_read_scan(st: AppState, auth: AuthContext, scan_id: str) -> bool:
    """`require_scope("scans:read")` for a route that cannot use it (a WebSocket): a person needs
    the scope on the scan's project and must be able to see it; a token needs the scope."""
    if auth.access is not None:
        project = _project_of(st, auth, {"scan_id": scan_id})
        if project is _MISSING:
            return False
        where = project if isinstance(project, str) else None
        return "scans:read" in auth.access.scopes_on(where)
    return auth.scopes is None or "scans:read" in auth.scopes


def current_org(request: Request, auth: AuthContext = Depends(require_auth)) -> str:
    """Which organization's data this request should see (ADR-0013). A real scoped token's org is
    fixed and authoritative -- the `X-Bulwark-Org` header is ignored for it, not merely a fallback,
    since trusting a client-suppliable header over what the token actually authenticated as would
    defeat the point of scoping the token in the first place. For the legacy shared token (no
    intrinsic org of its own), the header still selects scope exactly as before Week 29's original
    cut; absent, the bootstrap default org, so a single-tenant deployment never has to know this
    exists."""
    if auth.org_id is not None:
        return auth.org_id
    org = request.headers.get(ORG_HEADER)
    return org.strip() if org and org.strip() else DEFAULT_ORG_ID


def db(
    st: AppState = Depends(state),
    org: str = Depends(current_org),
    auth: AuthContext = Depends(require_auth),
) -> Iterator[Session]:
    projects = auth.access.visible_projects() if auth.access is not None else None
    with st.sessions() as s:
        # Session-scoped, not transaction-local (`core.tenancy.set_session_org`'s docstring has the
        # full reasoning): several `repo.py` functions commit internally more than once in one
        # session (e.g. `create_scan` commits the asset, then commits the scan), and a transaction-
        # local value would reset at the first of those, leaving the rest of the request running
        # with no org context -- which RLS then reads as "see nothing", not "see everything."
        set_session_org(s, org, projects)
        yield s
