"""verified-fix agent run records (Week 42, ADR-0027)

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-30

A direct `org_id` column, same as `assets`/`scans`/`llm_usage`, so it gets the same tenant_isolation
RLS policy (migration 0005/0011) -- org context is already known before any read or write here (a
run belongs to one issue, which belongs to one asset, which has an org), unlike `api_tokens`, which
deliberately has none.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "verified_fix_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("issue_id", sa.String(length=36), nullable=False),
        sa.Column("workflow_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="running"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latest_patch", sa.JSON(), nullable=True),
        sa.Column("verification_record", sa.JSON(), nullable=False),
        sa.Column("ended_reason", sa.String(length=30), nullable=True),
        sa.Column("pr_url", sa.String(length=500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workflow_id", name="uq_verified_fix_runs_workflow_id"),
    )
    op.create_index("ix_verified_fix_runs_org_id", "verified_fix_runs", ["org_id"])
    op.create_index("ix_verified_fix_runs_issue_id", "verified_fix_runs", ["issue_id"])
    op.create_index("ix_verified_fix_runs_status", "verified_fix_runs", ["status"])

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects these runs

    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "verified_fix_runs" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "verified_fix_runs" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "verified_fix_runs" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "verified_fix_runs" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "verified_fix_runs"'))
        op.execute(sa.text('ALTER TABLE "verified_fix_runs" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "verified_fix_runs" DISABLE ROW LEVEL SECURITY'))
    op.drop_index("ix_verified_fix_runs_status", table_name="verified_fix_runs")
    op.drop_index("ix_verified_fix_runs_issue_id", table_name="verified_fix_runs")
    op.drop_index("ix_verified_fix_runs_org_id", table_name="verified_fix_runs")
    op.drop_table("verified_fix_runs")
