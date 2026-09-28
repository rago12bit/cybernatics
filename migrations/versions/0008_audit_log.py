"""tamper-evident audit log (Week 30 backfill, ADR-0019)

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-28

A single, global, operator-facing ledger -- no `org_id`, no RLS. There's no per-org sign-in yet for
a per-org audit screen to gate against; see `core/persistence/models.py`'s `AuditEntry` docstring.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "audit_entries",
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("target", sa.String(length=200), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("seq"),
        sa.UniqueConstraint("entry_hash", name="uq_audit_entries_entry_hash"),
    )
    op.create_index("ix_audit_entries_entry_hash", "audit_entries", ["entry_hash"])
    op.create_index("ix_audit_entries_action", "audit_entries", ["action"])

    op.create_table(
        "audit_checkpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("seq_end", sa.Integer(), nullable=False),
        sa.Column("chain_hash", sa.String(length=64), nullable=False),
        sa.Column("signature_bundle", sa.Text(), nullable=False),
        sa.Column("rekor_log_index", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_checkpoints_seq_end", "audit_checkpoints", ["seq_end"])

    if bind.dialect.name != "postgresql":
        return
    for table in ("audit_entries", "audit_checkpoints"):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )


def downgrade() -> None:
    op.drop_index("ix_audit_checkpoints_seq_end", table_name="audit_checkpoints")
    op.drop_table("audit_checkpoints")
    op.drop_index("ix_audit_entries_action", table_name="audit_entries")
    op.drop_index("ix_audit_entries_entry_hash", table_name="audit_entries")
    op.drop_table("audit_entries")
