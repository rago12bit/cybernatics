"""model gateway token budgets (Week 41, ADR-0026)

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-30

Two additive pieces for `core.llm.budget`: a running per-scan counter on `scans` (same shape as
`sbom_summary` in migration 0010, a column on the row it describes) and a new `llm_usage` table for
the per-organization-per-month counter, which has no single scan to live on. `llm_usage` carries a
direct `org_id` exactly like `assets`/`scans` in migration 0005, so it gets the same tenant_isolation
RLS policy -- unlike `api_tokens` (migration 0007), which deliberately has none because token lookup
is what *resolves* org context in the first place; here org context is already known before any read
or write happens (a scan's own `org_id`).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()

    op.add_column("scans", sa.Column("llm_tokens_used", sa.Integer(), nullable=False, server_default="0"))
    op.alter_column("scans", "llm_tokens_used", server_default=None)

    op.create_table(
        "llm_usage",
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("period", sa.String(length=7), nullable=False),
        sa.Column("tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("org_id", "period"),
    )

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects these runs

    op.execute(sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "llm_usage" TO "{APP_ROLE}"'))
    op.execute(sa.text('ALTER TABLE "llm_usage" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "llm_usage" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "llm_usage" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "llm_usage"'))
        op.execute(sa.text('ALTER TABLE "llm_usage" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "llm_usage" DISABLE ROW LEVEL SECURITY'))
    op.drop_table("llm_usage")
    op.drop_column("scans", "llm_tokens_used")
