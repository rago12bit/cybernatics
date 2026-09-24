from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings

SessionFactory = Callable[[], Session]

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


def make_engine(url: str) -> Engine:
    if url.startswith("postgresql://"):  # default driver name -> psycopg 3
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    kwargs = {"connect_args": {"check_same_thread": False}} if url.startswith("sqlite") else {}
    return create_engine(url, pool_pre_ping=True, **kwargs)


def get_session_factory() -> sessionmaker[Session]:
    global _engine, _factory
    if _factory is None:
        _engine = make_engine(Settings.from_env().database_url)
        _factory = sessionmaker(_engine, expire_on_commit=False)
    return _factory
