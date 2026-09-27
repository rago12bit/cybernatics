"""Dependency wiring. Everything external is injected so tests can substitute fakes."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.config import Settings
from core.llm.client import LLMClient
from core.llm.limits import UsageLimiter
from core.persistence.db import SessionFactory
from core.tenancy import CURRENT_ORG_SETTING, DEFAULT_ORG_ID, ORG_HEADER

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
    limiter: UsageLimiter = field(default_factory=UsageLimiter)  # caps real model calls (cost)


def state(request: Request) -> AppState:
    st: AppState = request.app.state.bulwark
    return st


def token_ok(supplied: str | None, expected: str) -> bool:
    return bool(supplied) and hmac.compare_digest(supplied.encode(), expected.encode())  # type: ignore[union-attr]


def require_auth(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    st: AppState = Depends(state),
) -> None:
    if creds is None or not token_ok(creds.credentials, st.settings.api_token):
        raise HTTPException(401, "invalid or missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})  # fmt: skip


def current_org(request: Request) -> str:
    """Which organization's data this request should see (ADR-0013). No real per-org identity yet
    (see `core.tenancy.ORG_HEADER`'s docstring for exactly what that means) — this only selects a
    scope, on top of the existing bearer token that already gates whether a caller may use the API
    at all. Absent header -> the bootstrap default org, so a single-tenant deployment never has to
    know this exists."""
    org = request.headers.get(ORG_HEADER)
    return org.strip() if org and org.strip() else DEFAULT_ORG_ID


def db(st: AppState = Depends(state), org: str = Depends(current_org)) -> Iterator[Session]:
    with st.sessions() as s:
        if s.bind is not None and s.bind.dialect.name == "postgresql":
            # `set_config` is a function call, not string-built SQL: the org id is always a bound
            # parameter, never concatenated into the SQL text. `false` (session-, not
            # transaction-scoped) is deliberate: several `repo.py` functions commit internally
            # (e.g. `create_scan` commits the asset, then commits the scan), and a `true`/local
            # value would reset at the FIRST of those commits, leaving the rest of the same request
            # running with no org context at all -- which RLS then reads as "see nothing", not "see
            # everything". Safe on a pooled connection because this call always runs first, before
            # any other statement on this session, so a stale value from whoever used the underlying
            # connection last is always overwritten before it could ever be read.
            s.execute(
                text("SELECT set_config(:key, :org, false)"),
                {"key": CURRENT_ORG_SETTING, "org": org},
            )
        yield s
