"""Dependency wiring. Everything external is injected so tests can substitute fakes."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from core.config import Settings
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
    llm: LLMClient | None = None  # None: AI suggestions are off; guidance is static reference text
    limiter: UsageLimiter = field(default_factory=UsageLimiter)  # caps real model calls (rate)
    llm_budget: BudgetConfig = field(default_factory=BudgetConfig.from_env)  # caps them by tokens
    llm_triage: LLMClient | None = None  # None: the triage assistant is off (plan §21.3)
    llm_hypotheses: LLMClient | None = None  # None: the Hypotheses lane is off (plan §21.4)
    llm_copilot: LLMClient | None = None  # None: the copilot is off (plan §21.5)
    llm_attack_path: LLMClient | None = None  # None: attack-path narratives are off (plan §21.6)


def state(request: Request) -> AppState:
    st: AppState = request.app.state.bulwark
    return st


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
    actor: str  # for audit-log attribution: "token:<display_prefix>" or "shared-token"


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
        return AuthContext(
            org_id=row.org_id, scopes=frozenset(row.scopes), actor=f"token:{row.display_prefix}"
        )


def require_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    st: AppState = Depends(state),
) -> AuthContext:
    if creds is None:
        raise HTTPException(401, "invalid or missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})  # fmt: skip
    if token_ok(creds.credentials, st.settings.api_token):
        return AuthContext(org_id=None, scopes=None, actor="shared-token")
    scoped = _scoped_token_context(st, creds.credentials)
    if scoped is not None:
        return scoped
    raise HTTPException(401, "invalid or missing bearer token",
                        headers={"WWW-Authenticate": "Bearer"})  # fmt: skip


def require_scope(scope: str) -> Callable[[AuthContext], None]:
    """`auth.scopes is None` (the legacy shared token) is treated as "every scope" -- the existing
    self-hosted, single-operator trust model already grants it unrestricted access; scopes only
    narrow what a *real* scoped token (`core/tokens.py`) may do."""

    def _check(auth: AuthContext = Depends(require_auth)) -> None:
        if auth.scopes is not None and scope not in auth.scopes:
            raise HTTPException(403, f"this token does not have the '{scope}' scope")

    return _check


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


def db(st: AppState = Depends(state), org: str = Depends(current_org)) -> Iterator[Session]:
    with st.sessions() as s:
        # Session-scoped, not transaction-local (`core.tenancy.set_session_org`'s docstring has the
        # full reasoning): several `repo.py` functions commit internally more than once in one
        # session (e.g. `create_scan` commits the asset, then commits the scan), and a transaction-
        # local value would reset at the first of those, leaving the rest of the request running
        # with no org context -- which RLS then reads as "see nothing", not "see everything."
        set_session_org(s, org)
        yield s
