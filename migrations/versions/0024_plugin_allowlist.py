"""Per-organization plugin allowlist (Week 51 task 1, plan §23)

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-01

Default-deny, the opposite lazy-creation sense of migration 0019's data_retention_policies: a
plugin discovered via entry-point but never explicitly allowlisted here must never run. See
core.persistence.models.PluginAllowlistRow's own docstring for why this row records trust in a
publisher *identity*, not a one-time image hash -- core.plugins.signing re-verifies the Sigstore
signature on every run, not only when a row is first inserted here.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "plugin_allowlist",
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("plugin_name", sa.String(length=200), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allowed_by", sa.String(length=200), nullable=False),
        sa.Column("allowed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("org_id", "plugin_name"),
    )

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows

    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "plugin_allowlist" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "plugin_allowlist" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "plugin_allowlist" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "plugin_allowlist" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "plugin_allowlist"'))
        op.execute(sa.text('ALTER TABLE "plugin_allowlist" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "plugin_allowlist" DISABLE ROW LEVEL SECURITY'))
    op.drop_table("plugin_allowlist")
