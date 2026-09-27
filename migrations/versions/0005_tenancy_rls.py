"""multi-tenancy: organizations, org_id, Postgres RLS (ADR-0013)

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-27

Schema changes (organizations table, org_id columns) apply on every dialect, including the SQLite
used by the test suite. The role-creation and Row-Level Security block only runs on Postgres —
SQLite has neither concept, and application-level org filtering (`core/persistence/repo.py`) is
what actually protects the fast test suite; this migration's RLS half protects the real deployment.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000000"

# The role the API and worker connect as once this migration has run (docker-compose.yml wires
# BULWARK_DATABASE_URL for those two services to it; `migrate` keeps connecting as the table-owning
# role so it can alter schema). Falls back to POSTGRES_PASSWORD if APP_DB_PASSWORD hasn't been
# generated yet (an environment from before this week's `scripts/init-env.sh` change) so upgrading
# doesn't hard-fail on a stale .env -- rotate it via ALTER ROLE afterwards if that fallback fires.
APP_ROLE = "bulwark_app"
_APP_PASSWORD = os.environ.get("APP_DB_PASSWORD") or os.environ.get("POSTGRES_PASSWORD", "")

_RLS_TABLES = ("assets", "scans", "tool_runs", "findings", "issues")


def upgrade() -> None:
    bind = op.get_bind()

    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.bulk_insert(
        sa.table(
            "organizations",
            sa.column("id", sa.String),
            sa.column("name", sa.String),
            sa.column("created_at", sa.DateTime),
        ),
        [{"id": DEFAULT_ORG_ID, "name": "Default", "created_at": datetime.now(timezone.utc)}],
    )

    # --- assets: add org_id, backfill, then tighten the unique constraint to include it ---
    op.add_column("assets", sa.Column("org_id", sa.String(length=36), nullable=True))
    op.execute(sa.text("UPDATE assets SET org_id = :org").bindparams(org=DEFAULT_ORG_ID))
    op.alter_column("assets", "org_id", nullable=False)
    op.drop_constraint("uq_assets_type_key", "assets", type_="unique")
    op.create_unique_constraint(
        "uq_assets_org_type_key", "assets", ["org_id", "source_type", "key"]
    )
    op.create_index("ix_assets_org_id", "assets", ["org_id"])
    op.create_foreign_key("fk_assets_org_id", "assets", "organizations", ["org_id"], ["id"])

    # --- scans: add org_id, backfill ---
    op.add_column("scans", sa.Column("org_id", sa.String(length=36), nullable=True))
    op.execute(sa.text("UPDATE scans SET org_id = :org").bindparams(org=DEFAULT_ORG_ID))
    op.alter_column("scans", "org_id", nullable=False)
    op.create_index("ix_scans_org_id", "scans", ["org_id"])
    op.create_foreign_key("fk_scans_org_id", "scans", "organizations", ["org_id"], ["id"])

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS. App-level filtering is what protects these runs.

    # --- a non-superuser role for the API/worker to connect as (ADR-0013) ---
    # FORCE ROW LEVEL SECURITY is a no-op against a superuser or a BYPASSRLS role, full stop -- the
    # policies below would silently protect nothing if the app kept connecting as the table-owning
    # role (which, on this project's docker-compose Postgres image, *is* a superuser). This is the
    # change that makes every policy below actually mean something.
    #
    # The password is embedded as a literal, not a bind parameter: a `DO $$ ... $$` body is parsed by
    # Postgres as a single dollar-quoted string, so a driver-level placeholder inside it is not
    # substituted the way it would be in an ordinary statement. Safe here because the value only ever
    # comes from this project's own `scripts/init-env.sh` (random hex, no quotes possible); it's still
    # escaped defensively rather than trusted blindly.
    if not _APP_PASSWORD:
        raise RuntimeError(
            "APP_DB_PASSWORD (or POSTGRES_PASSWORD as a fallback) must be set in the migration "
            "container's environment to create/update the bulwark_app role; a value baked into "
            "another env var's URL string does not count -- it must be its own variable."
        )
    pw_literal = "'" + _APP_PASSWORD.replace("'", "''") + "'"
    # ALTER ... unconditionally on the else branch, not just CREATE on first run: this makes a
    # password rotation in .env take effect on the next `alembic upgrade head` instead of silently
    # keeping whatever password the role happened to be created with (the bug this comment replaced
    # -- Week 29's first live run created the role with an empty password because APP_DB_PASSWORD
    # wasn't yet passed through to the migration container's actual environment).
    op.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
                CREATE ROLE {APP_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
                    PASSWORD {pw_literal};
            ELSE
                ALTER ROLE {APP_ROLE} PASSWORD {pw_literal};
            END IF;
        END $$;
        """
    )
    dbname = bind.execute(sa.text("SELECT current_database()")).scalar()
    op.execute(sa.text(f'GRANT CONNECT ON DATABASE "{dbname}" TO "{APP_ROLE}"'))
    op.execute(sa.text(f'GRANT USAGE ON SCHEMA public TO "{APP_ROLE}"'))
    for table in (*_RLS_TABLES, "organizations", "remediation_cache", "kb_chunks", "kb_meta"):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
    for table, pk_col in (("tool_runs", "id"), ("findings", "pk")):
        op.execute(
            sa.text(f'GRANT USAGE, SELECT ON SEQUENCE "{table}_{pk_col}_seq" TO "{APP_ROLE}"')
        )

    # --- Row-Level Security ---
    # `assets`/`scans` carry org_id directly; `tool_runs`/`findings`/`issues` don't duplicate it --
    # their policy joins back to the table that does (ADR-0013's "cascades through the foreign key").
    for table in ("assets", "scans"):
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                f"USING (org_id = current_setting('app.current_org', true))"
            )
        )

    for table, parent, parent_key, fk_col in (
        ("tool_runs", "scans", "org_id", "scan_id"),
        ("findings", "scans", "org_id", "scan_id"),
        ("issues", "assets", "org_id", "asset_id"),
    ):
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" USING (EXISTS ('
                f'SELECT 1 FROM "{parent}" WHERE "{parent}".id = "{table}"."{fk_col}" '
                f"AND \"{parent}\".{parent_key} = current_setting('app.current_org', true)))"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("issues", "findings", "tool_runs", "scans", "assets"):
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
            op.execute(sa.text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
            op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
        op.execute(f"REASSIGN OWNED BY {APP_ROLE} TO CURRENT_USER")
        op.execute(f"DROP OWNED BY {APP_ROLE}")
        op.execute(f"DROP ROLE IF EXISTS {APP_ROLE}")

    op.drop_constraint("fk_scans_org_id", "scans", type_="foreignkey")
    op.drop_index("ix_scans_org_id", table_name="scans")
    op.drop_column("scans", "org_id")

    op.drop_constraint("fk_assets_org_id", "assets", type_="foreignkey")
    op.drop_index("ix_assets_org_id", table_name="assets")
    op.drop_constraint("uq_assets_org_type_key", "assets", type_="unique")
    op.create_unique_constraint("uq_assets_type_key", "assets", ["source_type", "key"])
    op.drop_column("assets", "org_id")

    op.drop_table("organizations")
