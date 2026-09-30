"""Code chunk embeddings for the security copilot's retrieval (Week 44, plan §21.5)

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-30

`code_chunk_indexes`: one row per asset holding the `HashingEmbedder` weights its `code_chunks`
rows were embedded with (mirrors `kb_meta`'s "record which embedder built the index" rule from
ADR-009, but per-asset rather than one global fit -- each asset's source is its own small corpus).

`code_chunks`: one row per function-level symbol `core.codeintel` found in an asset's latest-indexed
checkout, `id`-keyed by `core.codeintel.models.symbol_id()` so a re-index of unchanged code is a
no-op replace, not row growth. RLS joins through `assets` for `org_id`, the same shape migration
0014 already gives `hypotheses` (a table with `asset_id` but no `org_id` column of its own). The
`vector(1024)` column and its HNSW index reuse migration 0002's exact pattern (`kb_chunks`); the
extension is already created there, but `CREATE EXTENSION IF NOT EXISTS` is repeated defensively
since this migration must not assume 0002 ran first in some hypothetical reordered history.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
DIM = 1024  # must match core.rag.embed.DIM


def upgrade() -> None:
    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"

    op.create_table(
        "code_chunk_indexes",
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("embedder", sa.String(length=50), nullable=False),
        sa.Column("dim", sa.Integer(), nullable=False),
        sa.Column("idf", JSON_T, nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("asset_id"),
    )

    if pg:
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
        op.execute(f"""
            CREATE TABLE code_chunks (
                id varchar(600) PRIMARY KEY,
                asset_id varchar(36) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
                path text NOT NULL, symbol_name varchar(300) NOT NULL, qualified_name text NOT NULL,
                kind varchar(16) NOT NULL, language varchar(16) NOT NULL,
                start_line integer NOT NULL, end_line integer NOT NULL, snippet text NOT NULL,
                embedding vector({DIM}) NOT NULL, created_at timestamptz NOT NULL
            )""")  # fmt: skip
        op.execute("CREATE INDEX ix_code_chunks_asset_id ON code_chunks (asset_id)")
        op.execute(
            "CREATE INDEX ix_code_chunks_embedding ON code_chunks "
            "USING hnsw (embedding vector_cosine_ops)"
        )
    else:
        op.create_table(
            "code_chunks",
            sa.Column("id", sa.String(600), primary_key=True),
            sa.Column("asset_id", sa.String(36), nullable=False),
            sa.Column("path", sa.Text(), nullable=False),
            sa.Column("symbol_name", sa.String(300), nullable=False),
            sa.Column("qualified_name", sa.Text(), nullable=False),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("language", sa.String(16), nullable=False),
            sa.Column("start_line", sa.Integer(), nullable=False),
            sa.Column("end_line", sa.Integer(), nullable=False),
            sa.Column("snippet", sa.Text(), nullable=False),
            sa.Column("embedding", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        )
        op.create_index("ix_code_chunks_asset_id", "code_chunks", ["asset_id"])

    if not pg:
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects these

    for table in ("code_chunk_indexes", "code_chunks"):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" USING (EXISTS ('
                f'SELECT 1 FROM "assets" WHERE "assets".id = "{table}"."asset_id" '
                "AND \"assets\".org_id = current_setting('app.current_org', true)))"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in ("code_chunks", "code_chunk_indexes"):
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
            op.execute(sa.text(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY'))
            op.execute(sa.text(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY'))
    op.drop_index("ix_code_chunks_asset_id", table_name="code_chunks")
    op.drop_table("code_chunks")
    op.drop_table("code_chunk_indexes")
