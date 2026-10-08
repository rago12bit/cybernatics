"""Issues an import held open at places its tool only samples

Revision ID: 0051
Revises: 0050
Create Date: 2026-10-08

A ZAP report lists a sample of the places an alert fires (its spider reaches different pages each
run, and ZAP lists at most five places for a site-wide alert), so a place missing from the next
report is not a fix while the same rule still fires on the same host. Such Issues are now held open
instead of closed (`core.imports.reimport`).

- `import_records.held_count`: how many, beside the other counts.
- `import_records.held_issue_ids`: which. They stay part of the Test's snapshot, so a later file
  that shows the rule gone from the host can still close them.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None

JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.add_column(
        "import_records",
        sa.Column("held_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "import_records",
        sa.Column("held_issue_ids", JSON_T, nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column("import_records", "held_issue_ids")
    op.drop_column("import_records", "held_count")
