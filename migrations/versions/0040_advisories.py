"""Advisory engine (Week 68, plan §46.2, §55.5)

Revision ID: 0040
Revises: 0039
Create Date: 2026-10-06

Public data, shared by every organization (no `org_id`, no RLS; the application roles may read and
write it):
- `advisories`, `advisory_packages`: OSV records and the packages and version ranges they affect.
- `kev_entries`: CISA's Known Exploited Vulnerabilities catalog.
- `cve_records`: CVEs as NVD describes them.
- `advisory_feeds`: where each source stands.
Per organization, under the same forced RLS policy as every v3 table:
- `advisory_impacts`: a vulnerability at a library version in a project's current SBOM.
- `advisory_states`: what the organization has done about each vulnerability.
`assets.owner`: who to ask about a project.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
SHARED = ("advisories", "advisory_packages", "kev_entries", "cve_records", "advisory_feeds")
TENANT = ("advisory_impacts", "advisory_states")


def upgrade() -> None:
    with op.batch_alter_table("assets") as b:
        b.add_column(sa.Column("owner", sa.String(length=200), nullable=True))
    op.create_table(
        "advisories",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("vuln_key", sa.String(length=100), nullable=False),
        sa.Column("modified", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn", sa.DateTime(timezone=True), nullable=True),
        sa.Column("aliases", JSON_T, nullable=False),
        sa.Column("summary", sa.String(length=500), nullable=False),
        sa.Column("details", sa.Text(), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=False),
        sa.Column("db_severity", sa.String(length=16), nullable=False),
        sa.Column("cwe", JSON_T, nullable=False),
        sa.Column("references", JSON_T, nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_advisories_vuln_key", "advisories", ["vuln_key"])
    op.create_table(
        "advisory_packages",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("advisory_id", sa.String(length=100), nullable=False),
        sa.Column("ecosystem", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("lib_key", sa.String(length=340), nullable=False),
        sa.Column("data", JSON_T, nullable=False),
        sa.ForeignKeyConstraint(["advisory_id"], ["advisories.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_advisory_packages_advisory_id", "advisory_packages", ["advisory_id"])
    op.create_index("ix_advisory_packages_lib_key", "advisory_packages", ["lib_key"])
    op.create_table(
        "kev_entries",
        sa.Column("cve", sa.String(length=32), nullable=False),
        sa.Column("date_added", sa.String(length=10), nullable=False),
        sa.Column("due_date", sa.String(length=10), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("ransomware", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("cve"),
    )
    op.create_table(
        "cve_records",
        sa.Column("id", sa.String(length=32), nullable=False),
        sa.Column("published", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_modified", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "advisory_feeds",
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor", sa.String(length=200), nullable=False),
        sa.Column("records", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("source"),
    )
    op.create_table(
        "advisory_impacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("vuln_key", sa.String(length=100), nullable=False),
        sa.Column("advisory_ids", JSON_T, nullable=False),
        sa.Column("library_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("fixed_version", sa.String(length=200), nullable=True),
        sa.Column("certain", sa.Boolean(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["library_id"], ["libraries.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id", "library_id", "version", "vuln_key", name="uq_advisory_impacts_use"
        ),
    )
    op.create_index("ix_advisory_impacts_org_vuln", "advisory_impacts", ["org_id", "vuln_key"])
    op.create_index("ix_advisory_impacts_library", "advisory_impacts", ["library_id"])
    op.create_index("ix_advisory_impacts_asset_id", "advisory_impacts", ["asset_id"])
    op.create_table(
        "advisory_states",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("vuln_key", sa.String(length=100), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "vuln_key", name="uq_advisory_states_vuln"),
    )
    for table in TENANT:
        op.create_index(f"ix_{table}_org_id", table, ["org_id"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level org filtering protects these rows
    for table in (*SHARED, *TENANT):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
    op.execute(
        sa.text(f'GRANT USAGE, SELECT ON SEQUENCE "advisory_packages_id_seq" TO "{APP_ROLE}"')
    )
    for table in TENANT:
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
    op.drop_table("advisory_states")
    op.drop_index("ix_advisory_impacts_asset_id", table_name="advisory_impacts")
    op.drop_index("ix_advisory_impacts_library", table_name="advisory_impacts")
    op.drop_index("ix_advisory_impacts_org_vuln", table_name="advisory_impacts")
    op.drop_table("advisory_impacts")
    op.drop_table("advisory_feeds")
    op.drop_table("cve_records")
    op.drop_table("kev_entries")
    op.drop_index("ix_advisory_packages_lib_key", table_name="advisory_packages")
    op.drop_index("ix_advisory_packages_advisory_id", table_name="advisory_packages")
    op.drop_table("advisory_packages")
    op.drop_index("ix_advisories_vuln_key", table_name="advisories")
    op.drop_table("advisories")
    with op.batch_alter_table("assets") as b:
        b.drop_column("owner")
