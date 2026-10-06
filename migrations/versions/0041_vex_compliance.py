"""VEX, compliance and evidence packs (Week 69, plan §46.3, §47)

Revision ID: 0041
Revises: 0040
Create Date: 2026-10-06

- `audit_entries.version`, `.org_id`, `.body_digest`: version-2 entries name their organization
  inside the hash, through a digest of the entry's body, so an organization's evidence pack can
  show its own entries in full and every other entry as hashes only -- and an auditor can still
  recompute every link. Existing entries stay version 1, unchanged.
- `issues.triage_justification`: why a dependency Issue is not a risk, in OpenVEX's vocabulary.
- `code_usage`: per project, what its Go code imports and calls (the evidence behind a VEX draft).
- `vex_statements`: VEX statements proposed, confirmed or rejected.
- `compliance_statuses`: a person's status for one requirement of a framework in one project.
- `evidence_packs`: generated, signed evidence packs.
The Go advisory feed's cursor is reset, so the next run reads the whole Go dump again and picks up
the vulnerable functions each Go record names (stored from now on).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TENANT = ("code_usage", "vex_statements", "compliance_statuses", "evidence_packs")


def _org() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"), nullable=False)  # fmt: skip


def upgrade() -> None:
    with op.batch_alter_table("audit_entries") as b:
        b.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
        b.add_column(sa.Column("org_id", sa.String(length=36), nullable=True))
        b.add_column(sa.Column("body_digest", sa.String(length=64), nullable=True))
    op.create_index("ix_audit_entries_org_id", "audit_entries", ["org_id"])
    op.create_index("ix_audit_entries_timestamp", "audit_entries", ["timestamp"])
    with op.batch_alter_table("issues") as b:
        b.add_column(sa.Column("triage_justification", sa.String(length=48), nullable=True))

    op.create_table(
        "code_usage",
        sa.Column("id", sa.String(length=36), nullable=False),
        _org(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("data", JSON_T, nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", name="uq_code_usage_asset"),
    )
    op.create_table(
        "vex_statements",
        sa.Column("id", sa.String(length=36), nullable=False),
        _org(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("library_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("vuln_key", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("justification", sa.String(length=48), nullable=True),
        sa.Column("impact_statement", sa.Text(), nullable=False),
        sa.Column("evidence", JSON_T, nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=True),
        sa.Column("proposed_by", sa.String(length=200), nullable=False),
        sa.Column("proposed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_by", sa.String(length=200), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["library_id"], ["libraries.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vex_statements_org_vuln", "vex_statements", ["org_id", "vuln_key"])
    op.create_index("ix_vex_statements_asset_id", "vex_statements", ["asset_id"])
    op.create_table(
        "compliance_statuses",
        sa.Column("id", sa.String(length=36), nullable=False),
        _org(),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("framework", sa.String(length=40), nullable=False),
        sa.Column("requirement", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("links", JSON_T, nullable=False),
        sa.Column("set_by", sa.String(length=200), nullable=False),
        sa.Column("set_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id", "framework", "requirement", name="uq_compliance_status"),
    )
    op.create_table(
        "evidence_packs",
        sa.Column("id", sa.String(length=36), nullable=False),
        _org(),
        sa.Column("period_start", sa.Date(), nullable=False),
        sa.Column("period_end", sa.Date(), nullable=False),
        sa.Column("frameworks", JSON_T, nullable=False),
        sa.Column("summary", JSON_T, nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("signed", sa.Boolean(), nullable=False),
        sa.Column("bundle", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for table in TENANT:
        op.create_index(f"ix_{table}_org_id", table, ["org_id"])
    op.execute(sa.text("UPDATE advisory_feeds SET cursor = '' WHERE source = 'osv:Go'"))

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    for table in TENANT:
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
        for table in TENANT:
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    for table in TENANT:
        op.drop_index(f"ix_{table}_org_id", table_name=table)
    op.drop_table("evidence_packs")
    op.drop_table("compliance_statuses")
    op.drop_index("ix_vex_statements_asset_id", table_name="vex_statements")
    op.drop_index("ix_vex_statements_org_vuln", table_name="vex_statements")
    op.drop_table("vex_statements")
    op.drop_table("code_usage")
    with op.batch_alter_table("issues") as b:
        b.drop_column("triage_justification")
    op.drop_index("ix_audit_entries_timestamp", table_name="audit_entries")
    op.drop_index("ix_audit_entries_org_id", table_name="audit_entries")
    with op.batch_alter_table("audit_entries") as b:
        b.drop_column("body_digest")
        b.drop_column("org_id")
        b.drop_column("version")
