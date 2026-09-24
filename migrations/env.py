from __future__ import annotations

from alembic import context
from sqlalchemy import pool

from core.config import Settings
from core.persistence.db import make_engine
from core.persistence.models import Base

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=Settings.from_env().database_url, target_metadata=target_metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = make_engine(Settings.from_env().database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


_ = pool
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
