"""/fix on pull requests (Week 76, plan §50, ADR-0059)

Revision ID: 0050
Revises: 0049
Create Date: 2026-10-08

- `users.github_login`: the GitHub account an admin linked to a person, so a `/fix` comment can be
  traced to someone with a Bulwark role. Unique per organization, compared without case (GitHub
  logins are case-insensitive). Only an admin sets it: a person naming their own login could name
  someone else's.
- `scans.github_head_sha`: the commit a pull request scan looked at, so `/fix` can tell whether the
  pull request has moved since.
- `pr_fix_requests`: one `/fix` -- the pull request, its head commit, the findings, the token cap
  shown in the preview, the confirmation code, who asked and who confirmed. Forced RLS by
  organization, and the project-scope policy for people limited to some projects.
- `verified_fix_runs`: a run for a pull request has no Issue (a pull request scan mints none), so
  `issue_id` becomes optional, and the run names its request and finding instead; one of the two
  is always set (a CHECK), so no run escapes both project-scope links.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
GUEST_ROLE = "bulwark_guest"
LISTED = "string_to_array(current_setting('app.project_scope', true), ',')"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

_RUNS_BEFORE = (
    '("verified_fix_runs".issue_id IS NULL OR EXISTS (SELECT 1 FROM "issues" p '
    'WHERE p.id = "verified_fix_runs".issue_id))'
)
_RUNS_AFTER = (
    f"({_RUNS_BEFORE} AND "
    '("verified_fix_runs".pr_fix_request_id IS NULL OR EXISTS (SELECT 1 FROM "pr_fix_requests" p '
    'WHERE p.id = "verified_fix_runs".pr_fix_request_id)))'
)


def upgrade() -> None:
    with op.batch_alter_table("users") as b:
        b.add_column(sa.Column("github_login", sa.String(length=39), nullable=True))
    op.create_index(
        "uq_users_org_github_login",
        "users",
        ["org_id", sa.text("lower(github_login)")],
        unique=True,
    )
    with op.batch_alter_table("scans") as b:
        b.add_column(sa.Column("github_head_sha", sa.String(length=40), nullable=True))

    op.create_table(
        "pr_fix_requests",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("installation_id", sa.String(length=40), nullable=False),
        sa.Column("repo", sa.String(length=200), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("head_sha", sa.String(length=40), nullable=False),
        sa.Column("code", sa.String(length=12), nullable=False),
        sa.Column("finding_ids", JSON_T, nullable=False),
        sa.Column("tokens_per_finding", sa.Integer(), nullable=False),
        sa.Column("token_cap", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("requested_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("requested_login", sa.String(length=39), nullable=False),
        sa.Column("confirmed_by", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "code", name="uq_pr_fix_requests_code"),
    )  # fmt: skip
    op.create_index("ix_pr_fix_requests_org_id", "pr_fix_requests", ["org_id"])
    op.create_index("ix_pr_fix_requests_pr", "pr_fix_requests", ["repo", "pr_number"])

    with op.batch_alter_table("verified_fix_runs") as b:
        b.alter_column("issue_id", existing_type=sa.String(length=36), nullable=True)
        b.add_column(sa.Column("pr_fix_request_id", sa.String(length=36), nullable=True))
        b.add_column(sa.Column("finding_id", sa.String(length=300), nullable=True))
        b.create_foreign_key(
            "fk_verified_fix_runs_pr_fix_request", "pr_fix_requests", ["pr_fix_request_id"],
            ["id"], ondelete="CASCADE",
        )  # fmt: skip
        b.create_index("ix_verified_fix_runs_pr_fix_request_id", ["pr_fix_request_id"])
        b.create_check_constraint(
            "ck_verified_fix_runs_issue_or_request",
            "issue_id IS NOT NULL OR pr_fix_request_id IS NOT NULL",
        )

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS
    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "pr_fix_requests" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "pr_fix_requests" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "pr_fix_requests" FORCE ROW LEVEL SECURITY'))
    op.execute(sa.text(
        'CREATE POLICY tenant_isolation ON "pr_fix_requests" '
        "USING (org_id = current_setting('app.current_org', true))"
    ))  # fmt: skip
    to = f'AS RESTRICTIVE TO "{GUEST_ROLE}"'
    op.execute(sa.text(
        f'CREATE POLICY project_scope ON "pr_fix_requests" {to} '
        f'USING ("pr_fix_requests".asset_id = ANY ({LISTED}))'
    ))  # fmt: skip
    op.execute(sa.text('DROP POLICY IF EXISTS project_scope ON "verified_fix_runs"'))
    op.execute(
        sa.text(f'CREATE POLICY project_scope ON "verified_fix_runs" {to} USING {_RUNS_AFTER}')
    )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        to = f'AS RESTRICTIVE TO "{GUEST_ROLE}"'
        op.execute(sa.text('DROP POLICY IF EXISTS project_scope ON "verified_fix_runs"'))
        op.execute(
            sa.text(f'CREATE POLICY project_scope ON "verified_fix_runs" {to} USING {_RUNS_BEFORE}')
        )
        op.execute(sa.text('DROP POLICY IF EXISTS project_scope ON "pr_fix_requests"'))
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "pr_fix_requests"'))
    op.execute(sa.text("DELETE FROM verified_fix_runs WHERE issue_id IS NULL"))
    with op.batch_alter_table("verified_fix_runs") as b:
        b.drop_constraint("ck_verified_fix_runs_issue_or_request", type_="check")
        b.drop_index("ix_verified_fix_runs_pr_fix_request_id")
        b.drop_constraint("fk_verified_fix_runs_pr_fix_request", type_="foreignkey")
        b.drop_column("finding_id")
        b.drop_column("pr_fix_request_id")
        b.alter_column("issue_id", existing_type=sa.String(length=36), nullable=False)
    op.drop_index("ix_pr_fix_requests_pr", table_name="pr_fix_requests")
    op.drop_index("ix_pr_fix_requests_org_id", table_name="pr_fix_requests")
    op.drop_table("pr_fix_requests")
    with op.batch_alter_table("scans") as b:
        b.drop_column("github_head_sha")
    op.drop_index("uq_users_org_github_login", table_name="users")
    with op.batch_alter_table("users") as b:
        b.drop_column("github_login")
