"""Ingest foundations: persistent Tests, import records, and the event outbox (Week 54 task 1,
plan §41.2/§42.1, ADR-0040)

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-04

Three new tables, all scoped by a direct `org_id` column (same RLS shape as `portfolios` and
`engagements` in migration 0026):

- `engagement_tests`: the persistent "Test" an uploaded report is reimported into.
- `import_records`: one row per upload -- digest, the four counts, and the prior state of every
  Issue it touched (what makes the latest import reversible).
- `outbox_events`: domain events written in the same transaction as the change that caused them.

No data migration: nothing exists yet that these tables would back-fill.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _rls(table: str, *, serial_pk: str | None = None) -> None:
    op.execute(sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"'))
    if serial_pk:
        op.execute(
            sa.text(f'GRANT USAGE, SELECT ON SEQUENCE "{table}_{serial_pk}_seq" TO "{APP_ROLE}"')
        )
    op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            f'CREATE POLICY tenant_isolation ON "{table}" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def _drop_rls(table: str) -> None:
    op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    op.execute(sa.text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
    op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))


def upgrade() -> None:
    op.create_table(
        "engagement_tests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("parser", sa.String(length=40), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "name", name="uq_engagement_tests_name"),
    )
    op.create_index("ix_engagement_tests_org_id", "engagement_tests", ["org_id"])
    op.create_index("ix_engagement_tests_engagement_id", "engagement_tests", ["engagement_id"])

    op.create_table(
        "import_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("test_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("parser", sa.String(length=40), nullable=False),
        sa.Column("file_name", sa.String(length=300), nullable=True),
        sa.Column("file_digest", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="applied"),
        sa.Column("close_missing", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("scope", sa.String(length=16), nullable=False, server_default="test"),
        sa.Column("new_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unchanged_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("closed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detached_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warnings", JSON_T, nullable=False),
        sa.Column("changes", JSON_T, nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reverted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["test_id"], ["engagement_tests.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", name="uq_import_records_scan_id"),
    )
    op.create_index("ix_import_records_org_id", "import_records", ["org_id"])
    op.create_index("ix_import_records_test_id", "import_records", ["test_id"])
    op.create_index("ix_import_records_test_created", "import_records", ["test_id", "created_at"])
    op.create_index("ix_import_records_test_digest", "import_records", ["test_id", "file_digest"])

    op.create_table(
        "outbox_events",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload", JSON_T, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_outbox_events_org_id", "outbox_events", ["org_id"])
    op.create_index("ix_outbox_events_event_type", "outbox_events", ["event_type"])
    op.create_index("ix_outbox_events_dispatched_at", "outbox_events", ["dispatched_at"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows

    _rls("engagement_tests")
    _rls("import_records")
    _rls("outbox_events", serial_pk="id")


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        _drop_rls("outbox_events")
        _drop_rls("import_records")
        _drop_rls("engagement_tests")
    op.drop_table("outbox_events")
    op.drop_table("import_records")
    op.drop_table("engagement_tests")
