"""Bulk changes to Issues, kept for Undo (Week 73, plan §56)

Revision ID: 0047
Revises: 0046
Create Date: 2026-10-07

- `issue_batches`: one bulk change across the org's Issues -- who, what, the query it was taken
  from, and each changed Issue's previous values, so it can be undone for a short while after
  (core.search.bulk). Under the same forced RLS policy as every v3 table.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0047"
down_revision = "0046"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "issue_batches",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("action", sa.String(length=16), nullable=False),
        sa.Column("params", JSON_T, nullable=False),
        sa.Column("query", sa.String(length=2000), nullable=False),
        sa.Column("selected", sa.Integer(), nullable=False),
        sa.Column("changed", sa.Integer(), nullable=False),
        sa.Column("previous", JSON_T, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("undo_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("undone_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("undone_by", sa.String(length=200), nullable=True),
    )  # fmt: skip
    op.create_index("ix_issue_batches_org_id", "issue_batches", ["org_id"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE issue_batches TO "{APP_ROLE}"')
    )
    op.execute(sa.text("ALTER TABLE issue_batches ENABLE ROW LEVEL SECURITY"))
    op.execute(sa.text("ALTER TABLE issue_batches FORCE ROW LEVEL SECURITY"))
    op.execute(
        sa.text(
            "CREATE POLICY tenant_isolation ON issue_batches "
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text("DROP POLICY IF EXISTS tenant_isolation ON issue_batches"))
    op.drop_index("ix_issue_batches_org_id", table_name="issue_batches")
    op.drop_table("issue_batches")
