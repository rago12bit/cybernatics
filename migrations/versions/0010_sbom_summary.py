"""SBOM summary on scans (Week 40/dependencies-screen follow-up, plan §20.5)

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-30

Adds one nullable JSON column to the existing `scans` table -- no new table, matching
`FindingRow.data`/`RemediationCache.payload`'s "keep the full document, index only what needs
server-side filtering" pattern. Nothing here needs pagination or filtering at the SQL level: the
Dependencies screen renders one scan's whole SBOM summary at a time. No RLS changes: `scans` already
carries the tenant_isolation policy from migration 0005, which covers the whole row regardless of
which columns exist on it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.add_column("scans", sa.Column("sbom_summary", JSON_T, nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "sbom_summary")
