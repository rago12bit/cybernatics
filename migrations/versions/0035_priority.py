"""Priority policies and each Issue's priority (Week 63, plan §44.3)

Revision ID: 0035
Revises: 0034
Create Date: 2026-10-05

`priority_policies` carries a direct `org_id` with the same forced RLS policy as every v3 table. The
new `issues` columns are covered by that table's existing policy (through its asset).

Every existing Issue gets a priority without anyone saving a policy: with no policy, priority is the
v2 risk score unchanged, which is already stored on each occurrence -- so the backfill copies the
latest occurrence's score and its band, organization by organization (forced RLS hides every row
until `app.current_org` is set, even from the owner).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

_BACKFILL_SCORE = """
UPDATE issues SET priority_version = 0, priority_score = (
    SELECT f.risk_score FROM findings f JOIN scans sc ON sc.id = f.scan_id
    WHERE f.issue_id = issues.id ORDER BY sc.created_at DESC, f.pk DESC LIMIT 1)
WHERE priority_version IS NULL AND asset_id IN (SELECT id FROM assets WHERE org_id = :o)
"""
_BACKFILL_BAND = """
UPDATE issues SET priority_band = CASE
    WHEN priority_score >= 80 THEN 'P1' WHEN priority_score >= 60 THEN 'P2'
    WHEN priority_score >= 30 THEN 'P3' ELSE 'P4' END
WHERE priority_score IS NOT NULL AND priority_band IS NULL
    AND asset_id IN (SELECT id FROM assets WHERE org_id = :o)
"""


def upgrade() -> None:
    op.create_table(
        "priority_policies",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("weights", JSON_T, nullable=False),
        sa.Column("context", JSON_T, nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("processed", sa.Integer(), nullable=False),
        sa.Column("changed", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "version", name="uq_priority_policies"),
    )
    op.create_index("ix_priority_policies_org_id", "priority_policies", ["org_id"])
    op.create_index("ix_priority_policies_asset_id", "priority_policies", ["asset_id"])
    op.add_column("issues", sa.Column("priority_score", sa.Integer(), nullable=True))
    op.add_column("issues", sa.Column("priority_band", sa.String(length=4), nullable=True))
    op.add_column("issues", sa.Column("priority_factors", JSON_T, nullable=True))
    op.add_column("issues", sa.Column("priority_version", sa.Integer(), nullable=True))
    op.create_index("ix_issues_priority_score", "issues", ["priority_score"])
    op.create_index("ix_issues_priority_band", "issues", ["priority_band"])

    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"
    if pg:
        op.execute(
            sa.text(
                f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "priority_policies" TO "{APP_ROLE}"'
            )
        )
        op.execute(sa.text('ALTER TABLE "priority_policies" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "priority_policies" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                'CREATE POLICY tenant_isolation ON "priority_policies" '
                "USING (org_id = current_setting('app.current_org', true))"
            )
        )
    for (org_id,) in bind.execute(sa.text('SELECT id FROM "organizations"')).fetchall():
        if pg:
            bind.execute(sa.text("SELECT set_config('app.current_org', :o, true)"), {"o": org_id})
        bind.execute(sa.text(_BACKFILL_SCORE), {"o": org_id})
        bind.execute(sa.text(_BACKFILL_BAND), {"o": org_id})


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "priority_policies"'))
    op.drop_index("ix_issues_priority_band", table_name="issues")
    op.drop_index("ix_issues_priority_score", table_name="issues")
    with op.batch_alter_table("issues") as b:
        b.drop_column("priority_version")
        b.drop_column("priority_factors")
        b.drop_column("priority_band")
        b.drop_column("priority_score")
    op.drop_index("ix_priority_policies_asset_id", table_name="priority_policies")
    op.drop_index("ix_priority_policies_org_id", table_name="priority_policies")
    op.drop_table("priority_policies")
