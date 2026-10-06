"""Dashboards and role homes (Week 71, plan §48.2, §55.4, §55.6)

Revision ID: 0043
Revises: 0042
Create Date: 2026-10-06

- `dashboards`: saved dashboards -- a name, an owner, the roles it is shared with, and its widgets
  (metric, place on the grid, filters) as JSON, with a version for concurrent edits.
- `person_roles`: the role each person picked for their home (lead, engineer, tester).
Both under the same forced RLS policy as every v3 table.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
TABLES = ("dashboards", "person_roles")
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "dashboards",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("shared_with", JSON_T, nullable=False),
        sa.Column("widgets", JSON_T, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
    )  # fmt: skip
    op.create_index("ix_dashboards_org_id", "dashboards", ["org_id"])
    op.create_index("ix_dashboards_org_owner", "dashboards", ["org_id", "owner"])
    op.create_table(
        "person_roles",
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  primary_key=True),
        sa.Column("person", sa.String(length=200), primary_key=True),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )  # fmt: skip

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
    op.drop_table("person_roles")
    op.drop_index("ix_dashboards_org_owner", table_name="dashboards")
    op.drop_index("ix_dashboards_org_id", table_name="dashboards")
    op.drop_table("dashboards")
