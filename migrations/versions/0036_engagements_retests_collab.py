"""Assessments, retests, notes and tags (Week 64, plan §43.1, §43.3, §49)

Revision ID: 0036
Revises: 0035
Create Date: 2026-10-05

New tables -- `engagement_checklist_items`, `retest_runs`, `issue_notes`, `tags` -- each carry a
direct `org_id` with the same forced RLS policy as every v3 table. The new columns on `engagements`,
`issues`, `assets` and `evidence_attachments` are covered by those tables' existing policies.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TABLES = ("engagement_checklist_items", "retest_runs", "issue_notes", "tags")


def _org() -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
    ]


def _per_org(*statements: str) -> None:
    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"
    for (org_id,) in bind.execute(sa.text('SELECT id FROM "organizations"')).fetchall():
        if pg:
            bind.execute(sa.text("SELECT set_config('app.current_org', :o, true)"), {"o": org_id})
        for sql in statements:
            bind.execute(sa.text(sql), {"o": org_id})


def upgrade() -> None:
    with op.batch_alter_table("engagements") as b:
        b.add_column(sa.Column("scope_targets", JSON_T, nullable=True))
        b.add_column(sa.Column("scope_routes", JSON_T, nullable=True))
        b.add_column(sa.Column("out_of_scope", sa.Text(), nullable=True))
        b.add_column(sa.Column("lead", sa.String(length=200), nullable=True))
        b.add_column(sa.Column("testers", JSON_T, nullable=True))
        b.add_column(sa.Column("checklist", sa.String(length=32), nullable=True))
        b.add_column(sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("report", JSON_T, nullable=True))
        b.add_column(sa.Column("report_generated_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("created_by", sa.String(length=200), nullable=True))
    # Existing rows get empty lists, so readers never see null where the model promises a list, and
    # an assessment created before this (only "active"/"completed") moves onto the lifecycle. Forced
    # RLS hides every row until `app.current_org` is set, so organization by organization.
    _per_org(
        "UPDATE engagements SET scope_targets = '[]', scope_routes = '[]', testers = '[]' "
        "WHERE org_id = :o",
        "UPDATE engagements SET status = CASE status WHEN 'completed' THEN 'closed' "
        "ELSE 'in_progress' END WHERE org_id = :o AND engagement_type NOT IN ('ci', 'import')",
    )

    with op.batch_alter_table("issues") as b:
        b.add_column(sa.Column("retest_status", sa.String(length=16), nullable=True))
        b.add_column(sa.Column("retest_requested_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("retest_requested_by", sa.String(length=200), nullable=True))
        b.add_column(sa.Column("retest_note", sa.Text(), nullable=True))
        b.add_column(sa.Column("retest_decided_at", sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column("retest_decided_by", sa.String(length=200), nullable=True))
        b.create_index("ix_issues_retest_status", ["retest_status"])

    with op.batch_alter_table("assets") as b:
        b.add_column(sa.Column("portfolio_id", sa.String(length=36), nullable=True))
        b.create_foreign_key(
            "fk_assets_portfolio_id", "portfolios", ["portfolio_id"], ["id"], ondelete="SET NULL"
        )
        b.create_index("ix_assets_portfolio_id", ["portfolio_id"])

    op.create_table(
        "engagement_checklist_items",
        *_org(),
        sa.Column("engagement_id", sa.String(length=36), nullable=False),
        sa.Column("item_id", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("updated_by", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["engagement_id"], ["engagements.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("engagement_id", "item_id", name="uq_engagement_checklist_item"),
    )
    op.create_index(
        "ix_engagement_checklist_items_engagement_id",
        "engagement_checklist_items",
        ["engagement_id"],
    )
    op.create_table(
        "retest_runs",
        *_org(),
        sa.Column("issue_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("rule", sa.String(length=300), nullable=False),
        sa.Column("location", sa.Text(), nullable=False),
        sa.Column("source_ref", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("result", sa.String(length=16), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_retest_runs_issue_id", "retest_runs", ["issue_id"])
    op.create_table(
        "issue_notes",
        *_org(),
        sa.Column("issue_id", sa.String(length=36), nullable=False),
        sa.Column("parent_id", sa.String(length=36), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("author", sa.String(length=200), nullable=False),
        sa.Column("mentions", JSON_T, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("edited_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_id"], ["issue_notes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_issue_notes_issue_id", "issue_notes", ["issue_id"])
    op.create_index("ix_issue_notes_parent_id", "issue_notes", ["parent_id"])
    op.create_table(
        "tags",
        *_org(),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("target_type", "target_id", "name", name="uq_tags"),
    )
    op.create_index("ix_tags_target_id", "tags", ["target_id"])
    for table in TABLES:
        op.create_index(f"ix_{table}_org_id", table, ["org_id"])

    with op.batch_alter_table("evidence_attachments") as b:
        b.add_column(sa.Column("note_id", sa.String(length=36), nullable=True))
        b.create_foreign_key(
            "fk_evidence_attachments_note_id", "issue_notes", ["note_id"], ["id"],
            ondelete="CASCADE",
        )  # fmt: skip
        b.create_index("ix_evidence_attachments_note_id", ["note_id"])

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
    op.execute(sa.text('DELETE FROM "evidence_attachments" WHERE note_id IS NOT NULL'))
    with op.batch_alter_table("evidence_attachments") as b:
        b.drop_index("ix_evidence_attachments_note_id")
        b.drop_constraint("fk_evidence_attachments_note_id", type_="foreignkey")
        b.drop_column("note_id")
    for table in TABLES:
        op.drop_index(f"ix_{table}_org_id", table_name=table)
    op.drop_index("ix_tags_target_id", table_name="tags")
    op.drop_table("tags")
    op.drop_index("ix_issue_notes_parent_id", table_name="issue_notes")
    op.drop_index("ix_issue_notes_issue_id", table_name="issue_notes")
    op.drop_table("issue_notes")
    op.drop_index("ix_retest_runs_issue_id", table_name="retest_runs")
    op.drop_table("retest_runs")
    op.drop_index(
        "ix_engagement_checklist_items_engagement_id", table_name="engagement_checklist_items"
    )
    op.drop_table("engagement_checklist_items")
    with op.batch_alter_table("assets") as b:
        b.drop_index("ix_assets_portfolio_id")
        b.drop_constraint("fk_assets_portfolio_id", type_="foreignkey")
        b.drop_column("portfolio_id")
    with op.batch_alter_table("issues") as b:
        b.drop_index("ix_issues_retest_status")
        for col in ("retest_decided_by", "retest_decided_at", "retest_note",
                    "retest_requested_by", "retest_requested_at", "retest_status"):  # fmt: skip
            b.drop_column(col)
    _per_org(
        "UPDATE engagements SET status = CASE status WHEN 'closed' THEN 'completed' "
        "ELSE 'active' END WHERE org_id = :o AND engagement_type NOT IN ('ci', 'import')"
    )
    with op.batch_alter_table("engagements") as b:
        for col in (
            "created_by", "report_generated_at", "report", "closed_at", "checklist", "testers",
            "lead", "out_of_scope", "scope_routes", "scope_targets",
        ):  # fmt: skip
            b.drop_column(col)
