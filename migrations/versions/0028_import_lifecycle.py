"""Import lifecycle: an import record exists before it is applied (Week 54 task 7, plan §42.1)

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-04

`POST /v2/ingest` answers 202 and a worker does the parsing, so the ImportRecord has to exist first
and carry its own progress: `status` gains queued/processing/previewed/failed/duplicate, `mode`
says whether it will be applied or only previewed, and `upload_path`, `error` and `preview` hold
what a person needs to confirm a preview or understand a failure. Same table, same RLS policy
(migration 0027); nothing to back-fill, since no import record predates this.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None

JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.add_column(
        "import_records",
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="apply"),
    )
    op.add_column("import_records", sa.Column("upload_path", sa.Text(), nullable=True))
    op.add_column("import_records", sa.Column("error", sa.Text(), nullable=True))
    op.add_column("import_records", sa.Column("preview", JSON_T, nullable=True))


def downgrade() -> None:
    op.drop_column("import_records", "preview")
    op.drop_column("import_records", "error")
    op.drop_column("import_records", "upload_path")
    op.drop_column("import_records", "mode")
