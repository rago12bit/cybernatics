"""issues and assets (ADR-0012)

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-27
"""

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_type", sa.String(length=16), nullable=False),
        sa.Column("key", sa.String(length=500), nullable=False),
        sa.Column("label", sa.String(length=300), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_type", "key", name="uq_assets_type_key"),
    )
    op.create_table(
        "issues",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("fingerprint", sa.String(length=80), nullable=False),
        sa.Column("fallback_fingerprint", sa.String(length=80), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "category", "fingerprint", name="uq_issues_asset_category_fingerprint"),
    )
    op.create_index("ix_issues_asset_id", "issues", ["asset_id"])
    op.create_index("ix_issues_asset_state", "issues", ["asset_id", "state"])
    op.create_index("ix_issues_fallback_fingerprint", "issues", ["fallback_fingerprint"])
    op.create_index("ix_issues_state", "issues", ["state"])

    op.add_column("scans", sa.Column("asset_id", sa.String(length=36), nullable=True))
    op.create_index("ix_scans_asset_id", "scans", ["asset_id"])
    op.create_foreign_key(
        "fk_scans_asset_id", "scans", "assets", ["asset_id"], ["id"], ondelete="SET NULL"
    )

    op.add_column("findings", sa.Column("issue_id", sa.String(length=36), nullable=True))
    op.add_column("findings", sa.Column("issue_state", sa.String(length=16), nullable=True))
    op.create_index("ix_findings_issue_id", "findings", ["issue_id"])
    op.create_foreign_key(
        "fk_findings_issue_id", "findings", "issues", ["issue_id"], ["id"], ondelete="SET NULL"
    )


def downgrade() -> None:
    op.drop_constraint("fk_findings_issue_id", "findings", type_="foreignkey")
    op.drop_index("ix_findings_issue_id", table_name="findings")
    op.drop_column("findings", "issue_state")
    op.drop_column("findings", "issue_id")

    op.drop_constraint("fk_scans_asset_id", "scans", type_="foreignkey")
    op.drop_index("ix_scans_asset_id", table_name="scans")
    op.drop_column("scans", "asset_id")

    op.drop_index("ix_issues_state", table_name="issues")
    op.drop_index("ix_issues_fallback_fingerprint", table_name="issues")
    op.drop_index("ix_issues_asset_state", table_name="issues")
    op.drop_index("ix_issues_asset_id", table_name="issues")
    op.drop_table("issues")
    op.drop_table("assets")
