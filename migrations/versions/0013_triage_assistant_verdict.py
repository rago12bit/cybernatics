"""triage assistant verdict columns (Week 43, plan §21.3, ADR-0028)

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-30

Adds `assistant_*` columns to the existing `issues` table -- no new table, no RLS changes, same
reasoning migration 0009's docstring already gives for the human triage columns it added: `issues`
already carries the tenant_isolation policy from migration 0005 (joined through `assets`), which
covers the whole row regardless of which columns exist on it.

Named `assistant_*`, never `triage_*`: `triage_status`/`triage_reason`/... (migration 0009) already
name a human decision. A model's verdict is a separate, advisory signal layered alongside it, not a
replacement or an input the human columns should ever be confused with.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("issues", sa.Column("assistant_verdict", sa.String(length=24), nullable=True))
    op.add_column(
        "issues", sa.Column("assistant_verdict_confidence", sa.String(length=16), nullable=True)
    )
    op.add_column("issues", sa.Column("assistant_verdict_rationale", sa.Text(), nullable=True))
    op.add_column("issues", sa.Column("assistant_verdict_lines", sa.JSON(), nullable=True))
    op.add_column(
        "issues", sa.Column("assistant_verdict_model", sa.String(length=100), nullable=True)
    )
    op.add_column(
        "issues", sa.Column("assistant_verdict_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_index("ix_issues_assistant_verdict", "issues", ["assistant_verdict"])


def downgrade() -> None:
    op.drop_index("ix_issues_assistant_verdict", table_name="issues")
    op.drop_column("issues", "assistant_verdict_at")
    op.drop_column("issues", "assistant_verdict_model")
    op.drop_column("issues", "assistant_verdict_lines")
    op.drop_column("issues", "assistant_verdict_rationale")
    op.drop_column("issues", "assistant_verdict_confidence")
    op.drop_column("issues", "assistant_verdict")
