"""Copilot conversations and messages (Week 44 task 3, plan §21.5)

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-30

`copilot_conversations`: one row per chat session against one asset, optionally carrying page
context (`context_kind`/`context_id` -- "issue"/<issue id> or "scan"/<scan id>, per §28.6's panel
keeping "this issue"/"this scan" context). RLS via `assets`, same shape migration 0014/0015 already
give `hypotheses`/`code_chunks`.

`copilot_messages`: one row per turn (a user question or the copilot's cited answer). It has no
`asset_id` of its own -- its tenant check is a two-hop EXISTS through `copilot_conversations` into
`assets`, since a message's only path to an org is through the conversation it belongs to.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"

    op.create_table(
        "copilot_conversations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("context_kind", sa.String(length=16), nullable=True),
        sa.Column("context_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_message_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_copilot_conversations_asset_id", "copilot_conversations", ["asset_id"])

    op.create_table(
        "copilot_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("conversation_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("citations", JSON_T, nullable=True),
        sa.Column("tokens_used", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["conversation_id"], ["copilot_conversations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_copilot_messages_conversation_id", "copilot_messages", ["conversation_id"])

    if not pg:
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects these

    for table in ("copilot_conversations", "copilot_messages"):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))

    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "copilot_conversations" USING (EXISTS ('
            'SELECT 1 FROM "assets" WHERE "assets".id = "copilot_conversations"."asset_id" '
            "AND \"assets\".org_id = current_setting('app.current_org', true)))"
        )
    )
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "copilot_messages" USING (EXISTS ('
            'SELECT 1 FROM "copilot_conversations" JOIN "assets" '
            'ON "assets".id = "copilot_conversations"."asset_id" '
            'WHERE "copilot_conversations".id = "copilot_messages"."conversation_id" '
            "AND \"assets\".org_id = current_setting('app.current_org', true)))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("copilot_messages", "copilot_conversations"):
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
            op.execute(sa.text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
            op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
    op.drop_index("ix_copilot_messages_conversation_id", table_name="copilot_messages")
    op.drop_table("copilot_messages")
    op.drop_index("ix_copilot_conversations_asset_id", table_name="copilot_conversations")
    op.drop_table("copilot_conversations")
