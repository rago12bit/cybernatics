"""Component inventory (Week 67, plan §46.1)

Revision ID: 0039
Revises: 0038
Create Date: 2026-10-06

- `libraries`: one row per library per organization (ecosystem plus the name as the ecosystem
  compares it), so a library is one thing however many projects and versions use it; it keeps how
  many projects and versions use it now, so listing libraries reads only this table.
- `components`: a library at a version in one project's SBOM from one scan or import. `current`
  marks each source's latest SBOM -- what the component search reads, through
  `ix_components_library_current`.
Both carry `org_id` under the same forced RLS policy as every v3 table. Existing SBOMs are filled in
by the `inventory_backfill` task, not here: reading them needs the application's purl parsing.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TABLES = ("libraries", "components")


def upgrade() -> None:
    op.create_table(
        "libraries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("ecosystem", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("key", sa.String(length=340), nullable=False),
        sa.Column("purl", sa.String(length=400), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("project_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("version_count", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "key", name="uq_libraries_org_key"),
    )
    op.create_index("ix_libraries_org_projects", "libraries", ["org_id", "project_count"])
    op.create_table(
        "components",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("library_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("current", sa.Boolean(), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("purl", sa.Text(), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("paths", JSON_T, nullable=False),
        sa.Column("license", sa.String(length=200), nullable=False),
        sa.Column("reachable", sa.Boolean(), nullable=True),
        sa.Column("reachable_reason", sa.String(length=300), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["library_id"], ["libraries.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id", "library_id", "version", name="uq_components_scan_lib_version"
        ),
    )
    op.create_index("ix_components_library_current", "components", ["library_id", "current"])
    op.create_index("ix_components_asset_source", "components", ["asset_id", "source", "current"])
    op.create_index("ix_components_scan_id", "components", ["scan_id"])
    for table in TABLES:
        op.create_index(f"ix_{table}_org_id", table, ["org_id"])

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
    for table in TABLES:
        op.drop_index(f"ix_{table}_org_id", table_name=table)
    op.drop_index("ix_components_scan_id", table_name="components")
    op.drop_index("ix_components_asset_source", table_name="components")
    op.drop_index("ix_components_library_current", table_name="components")
    op.drop_table("components")
    op.drop_index("ix_libraries_org_projects", table_name="libraries")
    op.drop_table("libraries")
