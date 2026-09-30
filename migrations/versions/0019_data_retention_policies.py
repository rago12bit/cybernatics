"""Per-organization data-retention policy (Week 47 task 2, plan §22.2, ADR-0032)

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-01

One row per organization, created lazily on first write (not one per organization automatically):
an org with no row here uses the plan's stated default (7 days) -- core.persistence.repo.
get_retention_days returns that default rather than requiring a row to exist, so this table only
ever holds the organizations that changed the default. `org_id` is the primary key, same shape as
`threat_models`' `asset_id` (migration 0017): one current value per key, not a history.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "data_retention_policies",
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="7"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("org_id"),
    )

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects these rows

    op.execute(
        sa.text(
            f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "data_retention_policies" TO "{APP_ROLE}"'
        )
    )
    op.execute(sa.text('ALTER TABLE "data_retention_policies" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "data_retention_policies" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "data_retention_policies" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "data_retention_policies"'))
        op.execute(sa.text('ALTER TABLE "data_retention_policies" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "data_retention_policies" DISABLE ROW LEVEL SECURITY'))
    op.drop_table("data_retention_policies")
