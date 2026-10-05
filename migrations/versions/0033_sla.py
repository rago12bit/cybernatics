"""SLA policies and the per-Issue SLA clock (Week 61, plan §44.1)

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-05

`sla_policies` carries a direct `org_id` with the same forced RLS policy as every v3 table. The new
`issues` columns are covered by that table's existing policy (through its asset).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "sla_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("basis", sa.String(length=16), nullable=False),
        sa.Column("bands", JSON_T, nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "version", name="uq_sla_policies"),
    )
    op.create_index("ix_sla_policies_org_id", "sla_policies", ["org_id"])
    op.create_index("ix_sla_policies_asset_id", "sla_policies", ["asset_id"])
    op.add_column("issues", sa.Column("sla_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("issues", sa.Column("sla_notified", sa.String(length=16), nullable=True))
    op.add_column("issues", sa.Column("sla_notified_at", sa.DateTime(timezone=True), nullable=True))

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "sla_policies" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "sla_policies" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "sla_policies" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "sla_policies" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "sla_policies"'))
    with op.batch_alter_table("issues") as b:
        b.drop_column("sla_notified_at")
        b.drop_column("sla_notified")
        b.drop_column("sla_started_at")
    op.drop_index("ix_sla_policies_asset_id", table_name="sla_policies")
    op.drop_index("ix_sla_policies_org_id", table_name="sla_policies")
    op.drop_table("sla_policies")
