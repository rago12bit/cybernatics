"""GitHub App integration: installations, PR-scan fields on scans (Week 30, ADR-0017)

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-27

`github_installations` deliberately gets no Row-Level Security policy, unlike every other table this
migration touches indirectly -- see `core/persistence/repo.py`'s `get_installation` docstring for why:
it's the directory a webhook's org context is *resolved from*, so it can't itself require that
context to already exist. It's granted to `bulwark_app` the same as any other table, just without a
policy restricting which rows are visible.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()

    op.create_table(
        "github_installations",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("account_login", sa.String(length=200), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_github_installations_org_id", "github_installations", ["org_id"])

    op.add_column("scans", sa.Column("ref", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("github_repo", sa.String(length=200), nullable=True))
    op.add_column("scans", sa.Column("github_pr_number", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("github_installation_id", sa.String(length=32), nullable=True))

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles to grant.

    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "github_installations" TO "{APP_ROLE}"')
    )


def downgrade() -> None:
    op.drop_column("scans", "github_installation_id")
    op.drop_column("scans", "github_pr_number")
    op.drop_column("scans", "github_repo")
    op.drop_column("scans", "ref")

    op.drop_index("ix_github_installations_org_id", table_name="github_installations")
    op.drop_table("github_installations")
