"""Saved views of the Issues list and per-person table settings (Week 73, plan §56)

Revision ID: 0046
Revises: 0045
Create Date: 2026-10-07

- `saved_views`: a named query of the org-wide Issues list (core.search.language), with its sort
  and columns; personal, or shared with a role (lead, engineer, tester), like dashboards (0043).
  `version` goes up on every save, so two people editing at once cannot overwrite each other.
- `person_prefs`: what each person chose for a table -- its columns and density -- keyed by the
  table's name ("issues").
Both under the same forced RLS policy as every v3 table.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
TABLES = ("saved_views", "person_prefs")
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "saved_views",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("query", sa.String(length=2000), nullable=False),
        sa.Column("sort", sa.String(length=16), nullable=False),
        sa.Column("columns", JSON_T, nullable=True),
        sa.Column("shared_with", JSON_T, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
    )  # fmt: skip
    op.create_index("ix_saved_views_org_id", "saved_views", ["org_id"])
    op.create_index("ix_saved_views_org_owner", "saved_views", ["org_id", "owner"])
    op.create_table(
        "person_prefs",
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  primary_key=True),
        sa.Column("person", sa.String(length=200), primary_key=True),
        sa.Column("key", sa.String(length=40), primary_key=True),
        sa.Column("value", JSON_T, nullable=False),
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
    op.drop_table("person_prefs")
    op.drop_index("ix_saved_views_org_owner", table_name="saved_views")
    op.drop_index("ix_saved_views_org_id", table_name="saved_views")
    op.drop_table("saved_views")
