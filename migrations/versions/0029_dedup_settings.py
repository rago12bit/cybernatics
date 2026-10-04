"""Deduplication settings per project per source (Week 58, plan §42.3, ADR-0042)

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-04

One table, versioned by insertion (a change is a new row), scoped by a direct `org_id` with the same
RLS shape as migration 0027's tables. No data migration: with no row, a source is matched by
`fingerprint_v2`, which is what every existing Issue was matched by.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "dedup_settings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=60), nullable=False),
        sa.Column("strategy", sa.String(length=24), nullable=False),
        sa.Column("fields", JSON_T, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effect", JSON_T, nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "source", "version", name="uq_dedup_settings"),
    )
    op.create_index("ix_dedup_settings_org_id", "dedup_settings", ["org_id"])
    op.create_index("ix_dedup_settings_asset_id", "dedup_settings", ["asset_id"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "dedup_settings" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "dedup_settings" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "dedup_settings" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "dedup_settings" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "dedup_settings"'))
        op.execute(sa.text('ALTER TABLE "dedup_settings" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "dedup_settings" DISABLE ROW LEVEL SECURITY'))
    op.drop_index("ix_dedup_settings_asset_id", table_name="dedup_settings")
    op.drop_index("ix_dedup_settings_org_id", table_name="dedup_settings")
    op.drop_table("dedup_settings")
