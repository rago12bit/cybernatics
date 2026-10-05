"""Connectors and their run history (Week 60, plan §42.5, ADR-0045)

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-05

Both tables carry a direct `org_id` with the same forced RLS policy as every v3 table.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TABLES = ("connectors", "connector_runs")


def upgrade() -> None:
    op.create_table(
        "connectors",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("config", JSON_T, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False),
        sa.Column("close_on_empty", sa.Boolean(), nullable=False),
        sa.Column("credential_store", sa.String(length=16), nullable=False),
        sa.Column("credential", sa.Text(), nullable=True),
        sa.Column("test_id", sa.String(length=36), nullable=True),
        sa.Column("state", JSON_T, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_items", sa.Integer(), nullable=True),
        sa.Column("max_items_seen", sa.Integer(), nullable=False),
        sa.Column("consecutive_failures", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["test_id"], ["engagement_tests.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_connectors_org_id", "connectors", ["org_id"])
    op.create_index("ix_connectors_asset_id", "connectors", ["asset_id"])
    op.create_index("ix_connectors_status", "connectors", ["status"])
    op.create_table(
        "connector_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("connector_id", sa.String(length=36), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("items", sa.Integer(), nullable=False),
        sa.Column("requests", sa.Integer(), nullable=False),
        sa.Column("import_id", sa.String(length=36), nullable=True),
        sa.Column("counts", JSON_T, nullable=False),
        sa.Column("warnings", JSON_T, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["connector_id"], ["connectors.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_connector_runs_org_id", "connector_runs", ["org_id"])
    op.create_index("ix_connector_runs_connector_id", "connector_runs", ["connector_id"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    for table in TABLES:
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                "USING (org_id = current_setting('app.current_org', true))"
            )
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TABLES:
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    op.drop_index("ix_connector_runs_connector_id", table_name="connector_runs")
    op.drop_index("ix_connector_runs_org_id", table_name="connector_runs")
    op.drop_table("connector_runs")
    op.drop_index("ix_connectors_status", table_name="connectors")
    op.drop_index("ix_connectors_asset_id", table_name="connectors")
    op.drop_index("ix_connectors_org_id", table_name="connectors")
    op.drop_table("connectors")
