"""Universal-mapper mappings (Week 59, plan §42.4, ADR-0043)

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-05

One table, versioned by insertion like `dedup_settings`, with the same direct-`org_id` RLS policy.
The `parser` columns of `engagement_tests` and `import_records` widen from 40 to 64 characters to
hold `universal:<mapping id>` (46).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "ingest_mappings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("spec", JSON_T, nullable=False),
        sa.Column("proposed_by", sa.String(length=120), nullable=True),
        sa.Column("sample_digest", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "name", "version", name="uq_ingest_mappings_version"),
    )
    op.create_index("ix_ingest_mappings_org_id", "ingest_mappings", ["org_id"])
    with op.batch_alter_table("engagement_tests") as batch:
        batch.alter_column("parser", type_=sa.String(length=64), existing_nullable=True)
    with op.batch_alter_table("import_records") as batch:
        batch.alter_column("parser", type_=sa.String(length=64), existing_nullable=False)

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "ingest_mappings" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "ingest_mappings" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "ingest_mappings" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "ingest_mappings" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "ingest_mappings"'))
        op.execute(sa.text('ALTER TABLE "ingest_mappings" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "ingest_mappings" DISABLE ROW LEVEL SECURITY'))
    with op.batch_alter_table("import_records") as batch:
        batch.alter_column("parser", type_=sa.String(length=40), existing_nullable=False)
    with op.batch_alter_table("engagement_tests") as batch:
        batch.alter_column("parser", type_=sa.String(length=40), existing_nullable=True)
    op.drop_index("ix_ingest_mappings_org_id", table_name="ingest_mappings")
    op.drop_table("ingest_mappings")
