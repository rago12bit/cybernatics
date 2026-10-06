"""Notifications, issue groups and ticket sync (Week 66, plan §49)

Revision ID: 0038
Revises: 0037
Create Date: 2026-10-06

New tables, each with a direct `org_id` under the same forced RLS policy as every v3 table:
- `notifications`: one per person (or the team channels) per thing worth saying; read in the app,
  sent by email or in the daily digest.
- `issue_watchers`: who follows an Issue (assignees, note authors, people mentioned, by hand).
- `notification_prefs`: per person (or "team"), per kind of event, per channel: off, instant or
  digest; an email address and the digest hour.
- `issue_groups`: Issues one ticket tracks together; `issues.group_id`.
- `ticket_configs`: per project, where tickets go and which side owns the status.
`external_issue_links` gains the group it was filed for and what the ticket last said;
`integration_settings` gains a Microsoft Teams webhook.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TABLES = ("notifications", "issue_watchers", "notification_prefs", "issue_groups", "ticket_configs")


def _base() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "issue_groups",
        *_base(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "name", name="uq_issue_groups_asset_name"),
    )
    op.create_index("ix_issue_groups_asset_id", "issue_groups", ["asset_id"])
    with op.batch_alter_table("issues") as b:
        b.add_column(sa.Column("group_id", sa.String(length=36), nullable=True))
        b.create_foreign_key(
            "fk_issues_group_id", "issue_groups", ["group_id"], ["id"], ondelete="SET NULL"
        )
        b.create_index("ix_issues_group_id", ["group_id"])

    op.create_table(
        "ticket_configs",
        *_base(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("target", sa.String(length=200), nullable=False),
        sa.Column("issue_type", sa.String(length=64), nullable=True),
        sa.Column("status_source", sa.String(length=16), nullable=False),
        sa.Column("status_map", JSON_T, nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", name="uq_ticket_configs_asset"),
    )
    with op.batch_alter_table("external_issue_links") as b:
        b.add_column(sa.Column("group_id", sa.String(length=36), nullable=True))
        b.add_column(sa.Column("raw_status", sa.String(length=100), nullable=True))
        b.add_column(sa.Column("external_assignee", sa.String(length=200), nullable=True))
        b.add_column(sa.Column("synced_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("pushed_digest", sa.String(length=64), nullable=True))
        b.create_foreign_key(
            "fk_external_issue_links_group_id", "issue_groups", ["group_id"], ["id"],
            ondelete="SET NULL",
        )  # fmt: skip
    with op.batch_alter_table("integration_settings") as b:
        b.add_column(sa.Column("teams_webhook_url", sa.Text(), nullable=True))

    op.create_table(
        "notifications",
        *_base(),
        sa.Column("recipient", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("link", sa.Text(), nullable=True),
        sa.Column("issue_id", sa.String(length=36), nullable=True),
        sa.Column("actor", sa.String(length=200), nullable=True),
        sa.Column("in_app", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("email_state", sa.String(length=16), nullable=True),
        sa.Column("emailed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("recipient", "event_id", "kind", name="uq_notifications_event"),
    )
    op.create_index("ix_notifications_recipient", "notifications", ["org_id", "recipient"])
    op.create_index("ix_notifications_email_state", "notifications", ["email_state"])
    op.create_table(
        "issue_watchers",
        *_base(),
        sa.Column("issue_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("reason", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issue_id", "actor", name="uq_issue_watchers"),
    )
    op.create_index("ix_issue_watchers_issue_id", "issue_watchers", ["issue_id"])
    op.create_table(
        "notification_prefs",
        *_base(),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=True),
        sa.Column("digest_hour", sa.Integer(), nullable=False),
        sa.Column("prefs", JSON_T, nullable=False),
        sa.Column("last_digest_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "owner", name="uq_notification_prefs_owner"),
    )
    for table in TABLES:
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


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TABLES:
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    for table in TABLES:
        op.drop_index(f"ix_{table}_org_id", table_name=table)
    op.drop_table("notification_prefs")
    op.drop_index("ix_issue_watchers_issue_id", table_name="issue_watchers")
    op.drop_table("issue_watchers")
    op.drop_index("ix_notifications_email_state", table_name="notifications")
    op.drop_index("ix_notifications_recipient", table_name="notifications")
    op.drop_table("notifications")
    with op.batch_alter_table("integration_settings") as b:
        b.drop_column("teams_webhook_url")
    with op.batch_alter_table("external_issue_links") as b:
        b.drop_constraint("fk_external_issue_links_group_id", type_="foreignkey")
        for col in ("pushed_digest", "synced_at", "external_assignee", "raw_status", "group_id"):
            b.drop_column(col)
    op.drop_table("ticket_configs")
    with op.batch_alter_table("issues") as b:
        b.drop_index("ix_issues_group_id")
        b.drop_constraint("fk_issues_group_id", type_="foreignkey")
        b.drop_column("group_id")
    op.drop_index("ix_issue_groups_asset_id", table_name="issue_groups")
    op.drop_table("issue_groups")
