"""Manual findings, evidence attachments, and stored entrypoints (Week 59, plan §43.2, ADR-0044)

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-05

Two tables with the direct-`org_id` RLS policy every v3 table has, and `scans.entrypoints` for the
manual finding form's route picker. No data migration: older scans keep a null `entrypoints` and
the picker falls back to their `route_map`.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TABLES = ("manual_findings", "evidence_attachments")


def upgrade() -> None:
    op.add_column("scans", sa.Column("entrypoints", JSON_T, nullable=True))
    op.create_table(
        "manual_findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("test_id", sa.String(length=36), nullable=False),
        sa.Column("issue_id", sa.String(length=36), nullable=False),
        sa.Column("import_id", sa.String(length=36), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("cwe", sa.String(length=16), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("cvss_vector", sa.String(length=300), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("location_kind", sa.String(length=8), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=True),
        sa.Column("route", sa.String(length=500), nullable=True),
        sa.Column("host", sa.String(length=300), nullable=True),
        sa.Column("path", sa.Text(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("steps", sa.Text(), nullable=False),
        sa.Column("impact", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("references", JSON_T, nullable=False),
        sa.Column("related_issue_id", sa.String(length=36), nullable=True),
        sa.Column("related_source", sa.String(length=60), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["test_id"], ["engagement_tests.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["import_id"], ["import_records.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    for col in ("org_id", "asset_id", "test_id", "issue_id"):
        op.create_index(f"ix_manual_findings_{col}", "manual_findings", [col])
    op.create_table(
        "evidence_attachments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("manual_finding_id", sa.String(length=36), nullable=False),
        sa.Column("file_name", sa.String(length=255), nullable=False),
        sa.Column("declared_type", sa.String(length=120), nullable=True),
        sa.Column("sniffed_type", sa.String(length=60), nullable=False),
        sa.Column("active_content", sa.Boolean(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted", sa.Boolean(), nullable=False),
        sa.Column("wrapped_dek", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["manual_finding_id"], ["manual_findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_attachments_org_id", "evidence_attachments", ["org_id"])
    op.create_index(
        "ix_evidence_attachments_manual_finding_id", "evidence_attachments", ["manual_finding_id"]
    )

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
    op.drop_index("ix_evidence_attachments_manual_finding_id", table_name="evidence_attachments")
    op.drop_index("ix_evidence_attachments_org_id", table_name="evidence_attachments")
    op.drop_table("evidence_attachments")
    for col in ("issue_id", "test_id", "asset_id", "org_id"):
        op.drop_index(f"ix_manual_findings_{col}", table_name="manual_findings")
    op.drop_table("manual_findings")
    op.drop_column("scans", "entrypoints")
