"""Portfolio and Engagement: the hierarchy v3 adds above Project/Asset (Week 53 task 3, plan §40
change C11, ADR-0039).

Teams group projects by business unit (Portfolio); pen tests and audits are time-boxed activities
against one project, not a single scan (Engagement). "Test" -- one tool's results within an
engagement -- is NOT a new table: `tool_runs` (migration 0001/0005) already is exactly that, one row
per tool per scan. This migration gives every existing and future ToolRun an `engagement_id` instead
of duplicating its columns into a parallel table (ADR-0039 explains the reuse decision).

Data migration, not just schema: every existing Asset gets one new "ci" Engagement (status=
"completed" if nothing has ever scanned it, "active" otherwise), and every ToolRun whose scan
belongs to that asset is linked to it -- "one CI engagement per project with one Test per scanner"
(the plan's own words), where a Test is a ToolRun, not a new row for it to go in.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def _rls(table: str) -> None:
    op.execute(sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"'))
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
    bind = op.get_bind()

    op.create_table(
        "portfolios",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_portfolios_org_id", "portfolios", ["org_id"])

    op.create_table(
        "engagements",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("portfolio_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=300), nullable=False),
        # ci | pentest | audit | adhoc -- "ci" is what this migration's own backfill creates; a
        # person creates the other kinds explicitly (v3 UI/API, not built this week).
        sa.Column("engagement_type", sa.String(length=16), nullable=False, server_default="ci"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("target_end_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["portfolio_id"], ["portfolios.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_engagements_org_id", "engagements", ["org_id"])
    op.create_index("ix_engagements_asset_id", "engagements", ["asset_id"])
    op.create_index("ix_engagements_portfolio_id", "engagements", ["portfolio_id"])

    op.add_column(
        "tool_runs", sa.Column("engagement_id", sa.String(length=36), nullable=True)
    )
    op.create_index("ix_tool_runs_engagement_id", "tool_runs", ["engagement_id"])
    op.create_foreign_key(
        "fk_tool_runs_engagement_id", "tool_runs", "engagements",
        ["engagement_id"], ["id"], ondelete="SET NULL",
    )  # fmt: skip

    # --- Data migration: one "ci" Engagement per Asset, every existing ToolRun linked to it ---
    now = datetime.now(timezone.utc)
    assets = bind.execute(sa.text('SELECT id, org_id, label, created_at FROM "assets"')).fetchall()
    for asset_id, org_id, label, created_at in assets:
        has_scans = bind.execute(
            sa.text('SELECT 1 FROM "scans" WHERE asset_id = :a LIMIT 1'), {"a": asset_id}
        ).first()
        engagement_id = str(uuid.uuid4())
        bind.execute(
            sa.text(
                'INSERT INTO "engagements" '
                "(id, org_id, asset_id, portfolio_id, name, engagement_type, status, started_at, "
                "target_end_at, created_at) VALUES "
                "(:id, :org_id, :asset_id, NULL, :name, 'ci', :status, :started_at, NULL, :now)"
            ),
            {
                "id": engagement_id, "org_id": org_id, "asset_id": asset_id,
                "name": f"{label} CI", "status": "active" if has_scans else "completed",
                "started_at": created_at, "now": now,
            },
        )  # fmt: skip
        bind.execute(
            sa.text(
                'UPDATE "tool_runs" SET engagement_id = :e WHERE scan_id IN '
                '(SELECT id FROM "scans" WHERE asset_id = :a)'
            ),
            {"e": engagement_id, "a": asset_id},
        )

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows

    _rls("portfolios")
    _rls("engagements")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _drop_rls("engagements")
        _drop_rls("portfolios")
    op.drop_constraint("fk_tool_runs_engagement_id", "tool_runs", type_="foreignkey")
    op.drop_index("ix_tool_runs_engagement_id", table_name="tool_runs")
    op.drop_column("tool_runs", "engagement_id")
    op.drop_table("engagements")
    op.drop_table("portfolios")
