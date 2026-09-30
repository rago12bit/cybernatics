"""Per-scan envelope-encryption data keys (Week 47 task 1, plan §22.2, ADR-0032)

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-01

One row per scan whose artifacts are envelope-encrypted: `wrapped_dek` is OpenBao's own
"vault:v1:..." ciphertext, never a plaintext key -- the plaintext data key exists only for one
encrypt/decrypt call (core.secrets.envelope) and is never persisted anywhere. Deleting this row
("crypto-shredding", Week 47 task 2) makes every object encrypted under it permanently unreadable,
including in backups, without needing to find and overwrite the ciphertext itself.

A direct `org_id` column, same reasoning as `verified_fix_runs` (migration 0012): the org is already
known before any read or write here (a scan belongs to one org), so this gets the same
`tenant_isolation` RLS policy directly rather than a join through `scans`.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "scan_data_keys",
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("scan_id"),
    )
    op.create_index("ix_scan_data_keys_org_id", "scan_data_keys", ["org_id"])

    if bind.dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- application-level org filtering protects these rows

    op.execute(
        sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "scan_data_keys" TO "{APP_ROLE}"')
    )
    op.execute(sa.text('ALTER TABLE "scan_data_keys" ENABLE ROW LEVEL SECURITY'))
    op.execute(sa.text('ALTER TABLE "scan_data_keys" FORCE ROW LEVEL SECURITY'))
    op.execute(
        sa.text(
            'CREATE POLICY tenant_isolation ON "scan_data_keys" '
            "USING (org_id = current_setting('app.current_org', true))"
        )
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(sa.text('DROP POLICY IF EXISTS tenant_isolation ON "scan_data_keys"'))
        op.execute(sa.text('ALTER TABLE "scan_data_keys" NO FORCE ROW LEVEL SECURITY'))
        op.execute(sa.text('ALTER TABLE "scan_data_keys" DISABLE ROW LEVEL SECURITY'))
    op.drop_index("ix_scan_data_keys_org_id", table_name="scan_data_keys")
    op.drop_table("scan_data_keys")
