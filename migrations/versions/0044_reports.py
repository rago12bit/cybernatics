"""Report builder (Week 72, plan §48.3)

Revision ID: 0044
Revises: 0043
Create Date: 2026-10-07

- `reports`: blocks, period, optional schedule (forced RLS).
- `report_runs`: each generated PDF -- queued by the API, rendered by the worker -- with its
  SHA-256, cosign signature and delivery (forced RLS).
- `report_links`: links that expire and can be revoked; only the token's hash. No RLS, like
  `api_tokens` (migration 0007): following a link is what resolves the organization, so the lookup
  by hash cannot require it; the app filters every other query by `org_id`, and the PDF is read
  from `report_runs` under RLS once the link has set the organization.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
RLS_TABLES = ("reports", "report_runs")
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _org() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                     nullable=False)  # fmt: skip


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), primary_key=True),
        _org(),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("period_days", sa.Integer(), nullable=False),
        sa.Column("blocks", JSON_T, nullable=False),
        sa.Column("schedule", JSON_T, nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
    )
    op.create_index("ix_reports_org_id", "reports", ["org_id"])
    op.create_index("ix_reports_next_run_at", "reports", ["next_run_at"])
    op.create_table(
        "report_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        _org(),
        sa.Column("report_id", sa.String(length=36),
                  sa.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("report_name", sa.String(length=120), nullable=False),
        sa.Column("trigger", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("period_end", sa.Date(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("signed", sa.Boolean(), nullable=False),
        sa.Column("pdf", sa.LargeBinary(), nullable=True),
        sa.Column("signature", sa.LargeBinary(), nullable=True),
        sa.Column("ai_summary", sa.Boolean(), nullable=False),
        sa.Column("delivery", JSON_T, nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )  # fmt: skip
    op.create_index("ix_report_runs_org_id", "report_runs", ["org_id"])
    op.create_index("ix_report_runs_report_id", "report_runs", ["report_id"])
    op.create_table(
        "report_links",
        sa.Column("id", sa.String(length=36), primary_key=True),
        _org(),
        sa.Column("run_id", sa.String(length=36),
                  sa.ForeignKey("report_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=200), nullable=True),
        sa.Column("opens", sa.Integer(), nullable=False),
        sa.Column("last_opened_at", sa.DateTime(timezone=True), nullable=True),
    )  # fmt: skip
    op.create_index("ix_report_links_org_id", "report_links", ["org_id"])
    op.create_index("ix_report_links_run_id", "report_links", ["run_id"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    for table in (*RLS_TABLES, "report_links"):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
    for table in RLS_TABLES:
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
        for table in RLS_TABLES:
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    op.drop_index("ix_report_links_run_id", table_name="report_links")
    op.drop_index("ix_report_links_org_id", table_name="report_links")
    op.drop_table("report_links")
    op.drop_index("ix_report_runs_report_id", table_name="report_runs")
    op.drop_index("ix_report_runs_org_id", table_name="report_runs")
    op.drop_table("report_runs")
    op.drop_index("ix_reports_next_run_at", table_name="reports")
    op.drop_index("ix_reports_org_id", table_name="reports")
    op.drop_table("reports")
