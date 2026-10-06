"""The rules engine (Week 65, plan §45)

Revision ID: 0037
Revises: 0036
Create Date: 2026-10-06

New tables `automation_rules` and `rule_runs` carry a direct `org_id` under the same forced RLS
policy as every v3 table. Issues gain an assignee and a priority override (both set by a person or
a rule); risk acceptances record when their expiry warning went out, so it goes out once.

Every outbox event already waiting is marked dispatched: until now nothing read the outbox, and a
rule written next week must not fire on a month of history the first time the dispatcher runs.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TABLES = ("automation_rules", "rule_runs")


def _per_org(*statements: str) -> None:
    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"
    for (org_id,) in bind.execute(sa.text('SELECT id FROM "organizations"')).fetchall():
        if pg:
            bind.execute(sa.text("SELECT set_config('app.current_org', :o, true)"), {"o": org_id})
        for sql in statements:
            bind.execute(sa.text(sql), {"o": org_id})


def upgrade() -> None:
    op.create_table(
        "automation_rules",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("trigger", sa.String(length=40), nullable=False),
        sa.Column("trigger_params", JSON_T, nullable=False),
        sa.Column("condition", sa.Text(), nullable=False),
        sa.Column("actions", JSON_T, nullable=False),
        sa.Column("confirm_over", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("template", sa.String(length=64), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_fired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_automation_rules_asset_id", "automation_rules", ["asset_id"])
    op.create_index("ix_automation_rules_trigger", "automation_rules", ["trigger"])
    op.create_table(
        "rule_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=36), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("trigger", sa.String(length=40), nullable=False),
        sa.Column("cause", sa.String(length=160), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=True),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("subject_ids", JSON_T, nullable=False),
        sa.Column("event_keys", JSON_T, nullable=False),
        sa.Column("results", JSON_T, nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(length=200), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["rule_id"], ["automation_rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rule_runs_rule_id", "rule_runs", ["rule_id"])
    op.create_index("ix_rule_runs_cause", "rule_runs", ["rule_id", "cause"])
    op.create_index("ix_rule_runs_status", "rule_runs", ["status"])
    for table in TABLES:
        op.create_index(f"ix_{table}_org_id", table, ["org_id"])

    with op.batch_alter_table("issues") as b:
        b.add_column(sa.Column("assignee", sa.String(length=200), nullable=True))
        b.add_column(sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("priority_override", sa.String(length=4), nullable=True))
        b.add_column(sa.Column("priority_override_by", sa.String(length=200), nullable=True))
        b.create_index("ix_issues_assignee", ["assignee"])
    with op.batch_alter_table("risk_acceptances") as b:
        b.add_column(sa.Column("expiry_warned_at", sa.DateTime(timezone=True), nullable=True))

    _per_org(
        "UPDATE outbox_events SET dispatched_at = CURRENT_TIMESTAMP "
        "WHERE org_id = :o AND dispatched_at IS NULL"
    )

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


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TABLES:
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    with op.batch_alter_table("risk_acceptances") as b:
        b.drop_column("expiry_warned_at")
    with op.batch_alter_table("issues") as b:
        b.drop_index("ix_issues_assignee")
        for col in ("priority_override_by", "priority_override", "assigned_at", "assignee"):
            b.drop_column(col)
    for table in TABLES:
        op.drop_index(f"ix_{table}_org_id", table_name=table)
    op.drop_index("ix_rule_runs_status", table_name="rule_runs")
    op.drop_index("ix_rule_runs_cause", table_name="rule_runs")
    op.drop_index("ix_rule_runs_rule_id", table_name="rule_runs")
    op.drop_table("rule_runs")
    op.drop_index("ix_automation_rules_trigger", table_name="automation_rules")
    op.drop_index("ix_automation_rules_asset_id", table_name="automation_rules")
    op.drop_table("automation_rules")
