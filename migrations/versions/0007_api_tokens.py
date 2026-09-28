"""scoped API tokens (Week 29 backfill, ADR-0018)

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-28

`api_tokens` carries no Row-Level Security policy, for the same reason `github_installations`
doesn't (migration 0006): authenticating a request with a token is what *resolves* org context in
the first place, so the lookup that does it can't itself require org context to already be set.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("display_prefix", sa.String(length=20), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash", name="uq_api_tokens_token_hash"),
    )
    op.create_index("ix_api_tokens_org_id", "api_tokens", ["org_id"])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"])

    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "api_tokens" TO "{APP_ROLE}"'))


def downgrade() -> None:
    op.drop_index("ix_api_tokens_token_hash", table_name="api_tokens")
    op.drop_index("ix_api_tokens_org_id", table_name="api_tokens")
    op.drop_table("api_tokens")
