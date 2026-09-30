"""Threat model drafts (Week 45 task 3, plan §21.7)

Revision ID: 0017
Revises: 0016
Create Date: 2026-09-30

One current row per asset (`asset_id` is the primary key, not a generated id): unlike
`copilot_conversations` (many conversations per asset) or `hypotheses` (many candidates per asset),
a project has exactly one threat-model draft at a time -- editing or regenerating replaces it in
place, and `version` is a plain incrementing counter (not a full history table), enough for the API
to tell "this is newer than what you last saw" without the point-in-time recovery the plan does not
ask for. RLS via `assets`, same single-hop shape migration 0014/0015/0016 already give
`hypotheses`/`code_chunk_indexes`/`copilot_conversations`.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"

    op.create_table(
        "threat_models",
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("mermaid", sa.Text(), nullable=False),
        sa.Column("stride", JSON_T, nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id"),
    )

    if not pg:
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects this

    op.execute(
        sa.text('GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "threat_models" TO "bulwark_app"')
    )
    op.execute(sa.text('ALTER TABLE "threat_models" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "threat_models" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "threat_models" USING (EXISTS ('
            'SELECT 1 FROM "assets" WHERE "assets".id = "threat_models"."asset_id" '
            "AND \"assets\".org_id = current_setting('app.current_org', true)))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "threat_models"'))
        op.execute(sa.text('ALTER TABLE "threat_models" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "threat_models" DISABLE ROW LEVEL SECURITY'))
    op.drop_table("threat_models")
