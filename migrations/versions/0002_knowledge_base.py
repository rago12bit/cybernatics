"""knowledge base (pgvector) for remediation retrieval

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-25
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
DIM = 1024  # must match core.rag.embed.DIM


def upgrade() -> None:
    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"
    if pg:
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    if pg:
        op.execute(f"""
            CREATE TABLE kb_chunks (
                id varchar(200) PRIMARY KEY, kind varchar(16) NOT NULL, title varchar(300) NOT NULL,
                section text NOT NULL, body text NOT NULL, owasp jsonb NOT NULL, cwes jsonb NOT NULL,
                url varchar(500) NOT NULL, content_hash varchar(64) NOT NULL, embedding vector({DIM}) NOT NULL
            )""")
        op.execute("CREATE INDEX ix_kb_chunks_kind ON kb_chunks (kind)")
        # Approximate nearest neighbour index; cosine distance matches the `<=>` operator used by search.
        op.execute("CREATE INDEX ix_kb_chunks_embedding ON kb_chunks USING hnsw (embedding vector_cosine_ops)")
    else:
        op.create_table(
            "kb_chunks",
            sa.Column("id", sa.String(200), primary_key=True),
            sa.Column("kind", sa.String(16), nullable=False),
            sa.Column("title", sa.String(300), nullable=False),
            sa.Column("section", sa.Text(), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("owasp", JSON_T, nullable=False),
            sa.Column("cwes", JSON_T, nullable=False),
            sa.Column("url", sa.String(500), nullable=False),
            sa.Column("content_hash", sa.String(64), nullable=False),
            sa.Column("embedding", sa.JSON(), nullable=False),
        )
        op.create_index("ix_kb_chunks_kind", "kb_chunks", ["kind"])
    op.create_table(
        "kb_meta",
        sa.Column("key", sa.String(50), primary_key=True),
        sa.Column("value", JSON_T, nullable=False),
        sa.Column("n", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("kb_meta")
    op.drop_table("kb_chunks")
