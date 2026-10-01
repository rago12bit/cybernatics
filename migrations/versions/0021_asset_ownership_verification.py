"""Web asset ownership verification (Week 49 task 1, plan §22.4, ADR-0035)

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-01

One row per web Asset, keyed by `asset_id` itself (not a surrogate id): there is exactly one current
verification state per asset, never a history, so the primary key doubles as the uniqueness
constraint. `assets.source_type` already accepted any string before this migration (`git`/`archive`
were a comment, not a DB constraint) -- registering one with `source_type="web"` needs no schema
change there, only this new table to track how, and whether, its ownership was proven.

RLS policy follows `issues`' shape from migration 0005: this table has no `org_id` column of its
own, so tenant isolation joins back through `assets.org_id`, the same "cascades through the foreign
key" pattern ADR-0013 already established.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "asset_verifications",
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id"),
    )
    op.create_index(
        "ix_asset_verifications_status", "asset_verifications", ["status"], unique=False
    )

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles/RLS -- app-level org filtering protects these rows

    op.execute(
        sa.text(
            f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "asset_verifications" TO "{APP_ROLE}"'
        )
    )
    op.execute(sa.text('ALTER TABLE "asset_verifications" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "asset_verifications" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "asset_verifications" USING (EXISTS ('
            'SELECT 1 FROM "assets" WHERE "assets".id = "asset_verifications"."asset_id" '
            "AND \"assets\".org_id = current_setting('app.current_org', true)))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "asset_verifications"'))
        op.execute(sa.text('ALTER TABLE "asset_verifications" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "asset_verifications" DISABLE ROW LEVEL SECURITY'))
    op.drop_index("ix_asset_verifications_status", table_name="asset_verifications")
    op.drop_table("asset_verifications")
