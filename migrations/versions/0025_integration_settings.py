"""Per-organization integrations: Slack/Discord/outbound-webhook/GitHub/Jira settings, and the
external-ticket link table two-way sync needs (Week 51 task 2, plan §23)

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-02

Same lazy-creation, default-deny shape as migration 0024's plugin_allowlist: no
integration_settings row means every integration is off. external_issue_links has no "lazy
default" semantics of its own -- it only ever holds rows core.integrations.dispatch actually
creates when an Issue gets filed externally.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0025"
down_revision = "0024"
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
        "integration_settings",
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("slack_webhook_url", sa.Text(), nullable=True),
        sa.Column("discord_webhook_url", sa.Text(), nullable=True),
        sa.Column("outbound_webhook_url", sa.Text(), nullable=True),
        sa.Column("outbound_webhook_secret", sa.Text(), nullable=True),
        sa.Column("github_token", sa.Text(), nullable=True),
        sa.Column("github_issues_repo", sa.String(length=200), nullable=True),
        sa.Column("github_webhook_secret", sa.Text(), nullable=True),
        sa.Column("jira_base_url", sa.Text(), nullable=True),
        sa.Column("jira_email", sa.String(length=320), nullable=True),
        sa.Column("jira_api_token", sa.Text(), nullable=True),
        sa.Column("jira_project_key", sa.String(length=64), nullable=True),
        sa.Column("jira_webhook_secret", sa.Text(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("org_id"),
    )
    op.create_table(
        "external_issue_links",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("issue_id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("external_id", sa.String(length=300), nullable=False),
        sa.Column("external_url", sa.Text(), nullable=False),
        sa.Column("external_status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issue_id", "provider", name="uq_external_links_issue_provider"),
    )
    op.create_index(
        "ix_external_links_org_provider_external_id",
        "external_issue_links",
        ["org_id", "provider", "external_id"],
    )
    op.create_index("ix_external_links_issue_id", "external_issue_links", ["issue_id"])

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows

    _rls("integration_settings")
    _rls("external_issue_links")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _drop_rls("external_issue_links")
        _drop_rls("integration_settings")
    op.drop_table("external_issue_links")
    op.drop_table("integration_settings")
