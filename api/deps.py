"""Dependency wiring. Everything external is injected so tests can substitute fakes."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from core.config import Settings
from core.llm.client import LLMClient
from core.llm.limits import UsageLimiter
from core.persistence.db import SessionFactory

_bearer = HTTPBearer(auto_error=False)


class EventSubscriber(Protocol):
    def subscribe(self, scan_id: str) -> AsyncIterator[dict[str, Any]]: ...


@dataclass
class AppState:
    settings: Settings
    sessions: SessionFactory
    enqueue: Callable[[str], None]  # dispatches a scan job to the worker
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


def db(st: AppState = Depends(state)) -> Iterator[Session]:
    with st.sessions() as s:
        yield s
