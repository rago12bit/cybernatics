"""Hypotheses lane + Issue source column (Week 43, plan §21.4, ADR-0028)

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-30

`issues.source` ("scanner" | "llm-confirmed"): where an Issue came from. Every existing row and
every row a normal scan creates defaults to "scanner"; only a person confirming a Hypotheses-lane
candidate ever writes "llm-confirmed" (plan §21.4's own rule).

`hypotheses` is a genuinely separate table from `issues`, not a variant state on it: a candidate the
model surfaced must not appear anywhere an Issue does -- the main issue list, the risk score, a
policy gate -- until a person promotes it. Its RLS policy joins through `assets` for `org_id`, the
same shape migration 0005 already gives `issues` itself (a table with `asset_id` but no `org_id`
column of its own).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    op.add_column(
        "issues", sa.Column("source", sa.String(length=20), nullable=False, server_default="scanner")
    )

    bind = op.get_bind()
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("route_method", sa.String(length=16), nullable=False),
        sa.Column("route_path", sa.Text(), nullable=False),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("suggested_check", sa.Text(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("snippet", sa.Text(), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column("promoted_issue_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["promoted_issue_id"], ["issues.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_hypotheses_asset_id", "hypotheses", ["asset_id"])
    op.create_index("ix_hypotheses_status", "hypotheses", ["status"])

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects these

    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "hypotheses" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "hypotheses" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "hypotheses" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "hypotheses" USING (EXISTS ('
            'SELECT 1 FROM "assets" WHERE "assets".id = "hypotheses"."asset_id" '
            "AND \"assets\".org_id = current_setting('app.current_org', true)))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "hypotheses"'))
        op.execute(sa.text('ALTER TABLE "hypotheses" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "hypotheses" DISABLE ROW LEVEL SECURITY'))
    op.drop_index("ix_hypotheses_status", table_name="hypotheses")
    op.drop_index("ix_hypotheses_asset_id", table_name="hypotheses")
    op.drop_table("hypotheses")
    op.drop_column("issues", "source")
