from __future__ import annotations

import os
from collections.abc import Callable

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.config import Settings

SessionFactory = Callable[[], Session]

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None

# SQLAlchemy's own defaults (pool_size=5, max_overflow=10 -- 15 connections total) were never sized
# for this app's own request concurrency; found live under k6 load (plan §23, Week 50): 500
# concurrent API requests, each needing one DB connection via api/deps.py's synchronous `db()`
# dependency, mostly queued for a connection and hit the pool's 30s checkout timeout, not the
# database or the app logic itself -- p50 latency was ~30s with a 25% failure rate, both artifacts
# of the pool ceiling, not real work taking that long.
#
# The first fix tried here (pool_size=20, max_overflow=30) traded one ceiling for a worse one: each
# of docker-compose.yml's 4 uvicorn worker PROCESSES gets its own engine and its own pool
# (processes don't share one), so 4 x 50 = up to 200 connections attempted against Postgres's own
# default max_connections=100 -- found live, immediately, as "FATAL: sorry, too many clients
# already" on 71% of requests. Shrinking the per-engine pool alone (tried next, 12/engine = 48
# total) traded back the other way: 500 real concurrent requests queued for a connection and hit
# the pool's own checkout timeout again. There is no per-engine pool size that resolves this alone
# -- this file has no way to know how many sibling processes (uvicorn workers, Celery worker, beat)
# share one Postgres instance, and Postgres's own default max_connections=100 is the real ceiling
# underneath all of them combined. The actual fix is both: Postgres's own max_connections raised
# (300 in docker-compose.yml's postgres service, see its own comment) to give the fleet real
# headroom, and a per-engine size here that adds up sensibly against that raised ceiling -- a real
# deployment running many more API replicas than this default stack's 4 needs to raise
# max_connections further, or lower these per deployment.
_DEFAULT_POOL_SIZE = 15
_DEFAULT_MAX_OVERFLOW = 10


def make_engine(url: str) -> Engine:
    if url.startswith("postgresql://"):  # default driver name -> psycopg 3
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    if url.startswith("sqlite"):
        return create_engine(url, pool_pre_ping=True, connect_args={"check_same_thread": False})
    pool_size = int(os.environ.get("BULWARK_DB_POOL_SIZE", _DEFAULT_POOL_SIZE))
    max_overflow = int(os.environ.get("BULWARK_DB_MAX_OVERFLOW", _DEFAULT_MAX_OVERFLOW))
    return create_engine(url, pool_pre_ping=True, pool_size=pool_size, max_overflow=max_overflow)


def get_session_factory() -> sessionmaker[Session]:
    global _engine, _factory
    if _factory is None:
        _engine = make_engine(Settings.from_env().database_url)
        _factory = sessionmaker(_engine, expire_on_commit=False)
    return _factory
