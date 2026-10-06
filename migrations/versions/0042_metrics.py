"""Metrics layer (Week 70, plan §48.1, ADR-0054)

Revision ID: 0042
Revises: 0041
Create Date: 2026-10-06

Summary tables kept per organization and refreshed when Issues change (`core.metrics.rollup`), each
under the same forced RLS policy as every v3 table:
- `metric_open_issues`: one row per open, not dismissed Issue (band, score, age, SLA deadline).
- `metric_issue_days`: per project, day and band -- first seen, fixed, time to fix, risk.
- `metric_sla_days`: per project, deadline day and band -- met, missed, still open, exempt.
- `metric_asset_status`: per project -- last full scan, scanners that ran of those that applied.
- `metric_components`: per library and project -- vulnerabilities and known-exploited ones.
- `metric_dirty`: what needs refreshing.
Ordinary tables, not materialized views: those cannot have RLS (ADR-0054). They start empty; the
worker's refresh fills them (and `bulwark metrics refresh` does so at once).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
TABLES = ("metric_open_issues", "metric_issue_days", "metric_sla_days", "metric_asset_status",
          "metric_components", "metric_dirty")  # fmt: skip


def _org(primary_key: bool = False) -> sa.Column:  # type: ignore[type-arg]
    # Derived data: it goes with its organization.
    return sa.Column("org_id", sa.String(length=36),
                     sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                     nullable=False, primary_key=primary_key)  # fmt: skip


def _asset() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("asset_id", sa.String(length=36),
                     sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)  # fmt: skip


def upgrade() -> None:
    op.create_table(
        "metric_open_issues",
        sa.Column("issue_id", sa.String(length=36),
                  sa.ForeignKey("issues.id", ondelete="CASCADE"), primary_key=True),  # fmt: skip
        _org(), _asset(),
        sa.Column("portfolio_id", sa.String(length=36), nullable=True),
        sa.Column("band", sa.String(length=8), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("priority_score", sa.Integer(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=True),
    )  # fmt: skip
    op.create_index("ix_metric_open_issues_org_asset", "metric_open_issues", ["org_id", "asset_id"])
    op.create_index("ix_metric_open_issues_org_due", "metric_open_issues", ["org_id", "due_at"])
    op.create_index(
        "ix_metric_open_issues_org_seen", "metric_open_issues", ["org_id", "first_seen_at"]
    )  # noqa: E501
    op.create_table(
        "metric_issue_days",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        _org(), _asset(),
        sa.Column("portfolio_id", sa.String(length=36), nullable=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("band", sa.String(length=8), nullable=False),
        sa.Column("opened", sa.Integer(), nullable=False),
        sa.Column("fixed", sa.Integer(), nullable=False),
        sa.Column("fix_seconds", sa.BigInteger(), nullable=False),
        sa.Column("risk_opened", sa.BigInteger(), nullable=False),
        sa.Column("risk_fixed", sa.BigInteger(), nullable=False),
    )  # fmt: skip
    op.create_index("ix_metric_issue_days_org_day", "metric_issue_days", ["org_id", "day"])
    op.create_index("ix_metric_issue_days_asset", "metric_issue_days", ["asset_id"])
    op.create_table(
        "metric_sla_days",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        _org(), _asset(),
        sa.Column("portfolio_id", sa.String(length=36), nullable=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("band", sa.String(length=16), nullable=False),
        sa.Column("met", sa.Integer(), nullable=False),
        sa.Column("missed", sa.Integer(), nullable=False),
        sa.Column("unfixed", sa.Integer(), nullable=False),
        sa.Column("exempt", sa.Integer(), nullable=False),
    )  # fmt: skip
    op.create_index("ix_metric_sla_days_org_day", "metric_sla_days", ["org_id", "day"])
    op.create_index("ix_metric_sla_days_asset", "metric_sla_days", ["asset_id"])
    op.create_table(
        "metric_asset_status",
        sa.Column("asset_id", sa.String(length=36),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),  # fmt: skip
        _org(),
        sa.Column("portfolio_id", sa.String(length=36), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanners_ok", sa.Integer(), nullable=False),
        sa.Column("scanners_applicable", sa.Integer(), nullable=False),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False),
    )  # fmt: skip
    op.create_table(
        "metric_components",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True),
        _org(),
        sa.Column("library_id", sa.String(length=36),
                  sa.ForeignKey("libraries.id", ondelete="CASCADE"), nullable=False),  # fmt: skip
        _asset(),
        sa.Column("portfolio_id", sa.String(length=36), nullable=True),
        sa.Column("vulns", sa.Integer(), nullable=False),
        sa.Column("kev", sa.Integer(), nullable=False),
    )  # fmt: skip
    op.create_index(
        "ix_metric_components_org_library", "metric_components", ["org_id", "library_id"]
    )  # noqa: E501
    op.create_table(
        "metric_dirty",
        _org(primary_key=True),
        sa.Column("scope", sa.String(length=40), primary_key=True),
        sa.Column("marked_at", sa.DateTime(timezone=True), nullable=False),
    )  # fmt: skip
    for table in TABLES[:-1]:
        op.create_index(f"ix_{table}_org_id", table, ["org_id"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    for table in TABLES:
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                "USING (org_id = current_setting('app.current_org', true))"
            )
        )
    for seq in ("metric_issue_days_id_seq", "metric_sla_days_id_seq", "metric_components_id_seq"):
        op.execute(sa.text(f'GRANT USAGE, SELECT ON SEQUENCE "{seq}" TO "{APP_ROLE}"'))


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TABLES:
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    for table in TABLES[:-1]:
        op.drop_index(f"ix_{table}_org_id", table_name=table)
    op.drop_table("metric_dirty")
    op.drop_index("ix_metric_components_org_library", table_name="metric_components")
    op.drop_table("metric_components")
    op.drop_table("metric_asset_status")
    op.drop_index("ix_metric_sla_days_asset", table_name="metric_sla_days")
    op.drop_index("ix_metric_sla_days_org_day", table_name="metric_sla_days")
    op.drop_table("metric_sla_days")
    op.drop_index("ix_metric_issue_days_asset", table_name="metric_issue_days")
    op.drop_index("ix_metric_issue_days_org_day", table_name="metric_issue_days")
    op.drop_table("metric_issue_days")
    op.drop_index("ix_metric_open_issues_org_seen", table_name="metric_open_issues")
    op.drop_index("ix_metric_open_issues_org_due", table_name="metric_open_issues")
    op.drop_index("ix_metric_open_issues_org_asset", table_name="metric_open_issues")
    op.drop_table("metric_open_issues")
