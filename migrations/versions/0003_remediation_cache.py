"""remediation cache

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-25
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "remediation_cache",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("rule_id", sa.String(300), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("prompt_version", sa.String(16), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("payload", JSON_T, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_remediation_cache_rule_id", "remediation_cache", ["rule_id"])


def downgrade() -> None:
    op.drop_index("ix_remediation_cache_rule_id", table_name="remediation_cache")
    op.drop_table("remediation_cache")
