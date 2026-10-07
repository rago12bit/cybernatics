"""Ordered indexes for the org-wide Issues search (Week 73, plan §56)

Revision ID: 0045
Revises: 0044
Create Date: 2026-10-07

The Issues list pages by cursor in one of a few orders (core/search/issues.py). With an index on
(the order's key, id), Postgres reads the first page straight off the index instead of sorting every
matching Issue: at 500,000 Issues a page went from 0.23-0.61 s to 6-10 ms
(benchmarks/issues/search-500k.json). Ties break on the id in the same direction as the key, so each
index serves its order both ways (newest and oldest share one).

The priority index is on the expression the query sorts by, `coalesce(priority_score, -1)`, so an
Issue with no score sorts last and the planner can still match the index.

No new table, so no new row-level security: `issues` keeps its policy from migration 0005.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_issues_order_priority", "issues", [sa.text("coalesce(priority_score, -1)"), "id"]
    )
    op.create_index("ix_issues_order_first_seen", "issues", ["first_seen_at", "id"])
    op.create_index("ix_issues_order_last_seen", "issues", ["last_seen_at", "id"])


def downgrade() -> None:
    op.drop_index("ix_issues_order_last_seen", table_name="issues")
    op.drop_index("ix_issues_order_first_seen", table_name="issues")
    op.drop_index("ix_issues_order_priority", table_name="issues")
