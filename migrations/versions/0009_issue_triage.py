"""issue triage: not-a-risk / accept-risk (Week 34, plan §28.3)

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-28

Adds triage columns to the existing `issues` table -- no new table, so no RLS changes: `issues`
already carries the tenant_isolation policy from migration 0005 (joined through `assets`), and it
covers the whole row regardless of which columns exist on it.

`triage_status` is deliberately separate from `state` (new/open/fixed/reintroduced, ADR-0012):
`state` tracks whether a scan still finds the issue; `triage_status` tracks a human decision layered
on top of that. An issue can be `state=open, triage_status=accepted` (still present, but a person
decided to live with it for now) -- collapsing the two into one column would lose that distinction.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "issues",
        sa.Column("triage_status", sa.String(length=16), nullable=False, server_default="open"),
    )
    op.add_column("issues", sa.Column("triage_reason", sa.Text(), nullable=True))
    op.add_column(
        "issues", sa.Column("triage_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("issues", sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("issues", sa.Column("triaged_by", sa.String(length=200), nullable=True))
    op.create_index("ix_issues_triage_status", "issues", ["triage_status"])


def downgrade() -> None:
    op.drop_index("ix_issues_triage_status", table_name="issues")
    op.drop_column("issues", "triaged_by")
    op.drop_column("issues", "triaged_at")
    op.drop_column("issues", "triage_expires_at")
    op.drop_column("issues", "triage_reason")
    op.drop_column("issues", "triage_status")
