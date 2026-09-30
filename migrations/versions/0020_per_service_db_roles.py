"""Per-service database roles for mTLS (Week 47 task 3, plan §22.2, ADR-0033)

Revision ID: 0020
Revises: 0019
Create Date: 2026-10-01

`bulwark_api`, `bulwark_worker`, and `bulwark_fixagent` replace the single shared `bulwark_app`
connection docker-compose.yml previously gave to all three services. Each is a LOGIN role whose
certificate's CN (`docker/postgres/pg_hba.conf`'s `clientcert=verify-full`) must exactly match its
own role name -- a compromised or rotated credential for one service can never be used to
authenticate as another, and each service's traffic is independently visible in
`pg_stat_activity.usename`.

None of the three duplicates `bulwark_app`'s table grants by hand: each is simply made a MEMBER of
`bulwark_app` (`GRANT bulwark_app TO <role>`), which -- Postgres roles default to INHERIT -- gives
it every privilege `bulwark_app` already has, automatically, including whatever a future migration
grants to `bulwark_app` later. `bulwark_app` itself is set `NOLOGIN`: it still holds every grant, but
nothing can connect directly as it anymore, only through one of the three named roles.

A password is also set for the three new roles (reusing `APP_DB_PASSWORD`, the same value
`bulwark_app` already used), even though `docker/postgres/pg_hba.conf` requires the Postgres `cert`
authentication method for every real network connection, which authenticates from the client
certificate alone and never checks it. This is not a weaker fallback in production -- `cert` auth
simply never looks at the password, whatever it is -- but it does let CI's `tenancy-rls` job
(`.github/workflows/ci.yml`) keep testing RLS itself against a plain Postgres image with no mTLS
configured at all, by connecting as `bulwark_worker` over a normal password-authenticated
connection, the same way it connected as `bulwark_app` before this migration. This is a pure
authentication/identity change either way -- RLS policies (migration 0005 onward) key on
`app.current_org`, not on which of the four roles is connected, so tenant isolation is unaffected.
"""

from __future__ import annotations

import os

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
SERVICE_ROLES = ("bulwark_api", "bulwark_worker", "bulwark_fixagent")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles at all -- nothing here has a SQLite equivalent

    # Same reasoning and the same literal-embedding safety note as migration 0005's bulwark_app
    # password: this only ever comes from scripts/init-env.sh's random hex, never user input.
    password = os.environ.get("APP_DB_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")
    if not password:
        raise RuntimeError(
            "APP_DB_PASSWORD (or POSTGRES_PASSWORD as a fallback) must be set in the migration "
            "container's environment to create the per-service roles."
        )
    pw_literal = "'" + password.replace("'", "''") + "'"

    for role in SERVICE_ROLES:
        op.execute(sa.text(f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                        CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
                            PASSWORD {pw_literal};
                    ELSE
                        ALTER ROLE {role} PASSWORD {pw_literal};
                    END IF;
                END $$;
                """))
        op.execute(sa.text(f'GRANT "{APP_ROLE}" TO "{role}"'))

    op.execute(sa.text(f'ALTER ROLE "{APP_ROLE}" NOLOGIN'))


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f'ALTER ROLE "{APP_ROLE}" LOGIN'))
    for role in SERVICE_ROLES:
        op.execute(sa.text(f'REVOKE "{APP_ROLE}" FROM "{role}"'))
        op.execute(sa.text(f'DROP ROLE IF EXISTS "{role}"'))
