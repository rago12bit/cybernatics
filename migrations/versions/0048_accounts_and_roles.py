"""User accounts, sign-in sessions and scoped roles (Week 75, plan §51)

Revision ID: 0048
Revises: 0047
Create Date: 2026-10-07

- `users`: a person in an organization -- email, name, an organization role (admin, member,
  viewer, or none: only the projects granted below), active or disabled, and how they came to be
  (SCIM, a first sign-in, an admin), and when the identity provider deleted them over SCIM (kept,
  turned off, for the audit trail). Under the same forced RLS as every v3 table.
- `role_overrides`: a higher role on one business unit or one project. They only raise access,
  never lower it, as DefectDojo's product permissions do; a business unit's role covers its
  projects. Forced RLS.
- `user_sessions` and the `users` lookup a sign-in needs happen before any organization is known,
  like `api_tokens` (ADR-0018): `user_sessions` carries no RLS. Only the session secret's SHA-256 is
  stored.
- `api_tokens.user_id`: a token made by a signed-in person acts as that person, and never for more
  than their role allows now.

**Project scope.** A person whose organization role is `none` sees only the projects granted to
them. Their requests run as the `bulwark_guest` database role (`SET LOCAL ROLE`, in
`core.tenancy`), with `app.project_scope` listing the visible project ids. Restrictive policies
*for that role only* -- on `assets` and on every organization table that names a project,
directly or through an Issue, a scan, an engagement or an engagement test -- hide the rest; tables
whose policy already goes through `assets` (issues, hypotheses, code chunks, ...) inherit it.
Unset, the scope matches nothing.

Why a role and not a policy for everyone: a policy for every session ("all projects, or these")
is evaluated on every query, and Postgres badly underestimates how many rows it lets through --
2 projects of 200 -- so plans through `assets` collapse: at a million Occurrences the
organization-wide "past SLA" metric went from a 7 ms median to 224 ms. Applied to `bulwark_guest` only, the policies
cost nothing for everyone else. The role is a member of `bulwark_app` (so it has its grants, now
and in future migrations), and each service role may switch to it -- `WITH INHERIT FALSE, SET TRUE`
(Postgres 16): a policy applies to the roles whose privileges a session has, so with an inherited
membership the policies would apply to every session, not only after the switch.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

GUEST_ROLE = "bulwark_guest"
SERVICE_ROLES = ("bulwark_api", "bulwark_worker", "bulwark_fixagent")
LISTED = "string_to_array(current_setting('app.project_scope', true), ',')"

#: Tables that name a project directly.
BY_ASSET = (
    "scans", "advisory_impacts", "automation_rules", "code_usage", "compliance_statuses",
    "dedup_settings", "engagements", "issue_groups", "metric_asset_status", "metric_components",
    "metric_issue_days", "metric_sla_days", "priority_policies", "risk_acceptances",
    "sla_policies", "ticket_configs", "vex_statements", "components", "connectors",
    "metric_open_issues", "manual_findings",
)  # fmt: skip

#: Tables that name a project through a parent row: (table, [(column, parent table)]).
BY_PARENT = (
    ("engagement_checklist_items", [("engagement_id", "engagements")]),
    ("engagement_tests", [("engagement_id", "engagements")]),
    ("scan_data_keys", [("scan_id", "scans")]),
    ("import_records", [("test_id", "engagement_tests")]),
    ("external_issue_links", [("issue_id", "issues")]),
    ("issue_notes", [("issue_id", "issues")]),
    ("issue_watchers", [("issue_id", "issues")]),
    ("notifications", [("issue_id", "issues")]),
    ("retest_runs", [("issue_id", "issues")]),
    ("risk_acceptance_issues", [("acceptance_id", "risk_acceptances")]),
    ("verified_fix_runs", [("issue_id", "issues")]),
    ("evidence_attachments", [("manual_finding_id", "manual_findings"),
                              ("risk_acceptance_id", "risk_acceptances"),
                              ("note_id", "issue_notes")]),
)  # fmt: skip


def _by_asset(table: str, column: str = "asset_id") -> str:
    return f'("{table}".{column} IS NULL OR "{table}".{column} = ANY ({LISTED}))'


def _by_parent(table: str, links: list[tuple[str, str]]) -> str:
    parts = [
        f'("{table}".{col} IS NULL OR EXISTS (SELECT 1 FROM "{parent}" p '
        f'WHERE p.id = "{table}".{col}))'
        for col, parent in links
    ]
    return f"({' AND '.join(parts)})"


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("external_id", sa.String(length=200), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deprovisioned_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("org_id", "email", name="uq_users_org_email"),
    )  # fmt: skip
    op.create_index("ix_users_org_id", "users", ["org_id"])
    op.create_table(
        "role_overrides",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("target_type", sa.String(length=16), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "target_type", "target_id", name="uq_role_overrides"),
    )  # fmt: skip
    op.create_index("ix_role_overrides_user_id", "role_overrides", ["user_id"])
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(length=64), primary_key=True),  # SHA-256 of the secret
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("method", sa.String(length=16), nullable=False),
        sa.Column("csrf", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_agent", sa.String(length=200), nullable=True),
    )  # fmt: skip
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    with op.batch_alter_table("api_tokens") as b:
        b.add_column(sa.Column("user_id", sa.String(length=36), nullable=True))
        b.create_foreign_key("fk_api_tokens_user_id", "users", ["user_id"], ["id"])
        b.create_index("ix_api_tokens_user_id", ["user_id"])

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level filtering protects these rows
    for table in ("users", "role_overrides", "user_sessions"):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
    for table in ("users", "role_overrides"):
        op.execute(sa.text(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY'))
        op.execute(sa.text(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY'))
        op.execute(
            sa.text(
                f'CREATE POLICY tenant_isolation ON "{table}" '
                "USING (org_id = current_setting('app.current_org', true))"
            )
        )
    if int(op.get_bind().execute(sa.text("SHOW server_version_num")).scalar() or 0) < 160000:
        raise RuntimeError(
            "Bulwark needs Postgres 16 or later from migration 0048 (role grants WITH INHERIT "
            "FALSE, which keep the project-scope policies off ordinary sessions)."
        )
    op.execute(sa.text(f"""
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{GUEST_ROLE}') THEN
                CREATE ROLE {GUEST_ROLE} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
            END IF;
        END $$;
    """))  # fmt: skip
    op.execute(sa.text(f'GRANT "{APP_ROLE}" TO "{GUEST_ROLE}"'))
    for role in SERVICE_ROLES:
        op.execute(sa.text(f"""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                    GRANT "{GUEST_ROLE}" TO "{role}" WITH INHERIT FALSE, SET TRUE;
                END IF;
            END $$;
        """))  # fmt: skip
    to = f'AS RESTRICTIVE TO "{GUEST_ROLE}"'
    op.execute(sa.text(f"CREATE POLICY project_scope ON assets {to} USING (id = ANY ({LISTED}))"))
    for table in BY_ASSET:
        op.execute(
            sa.text(f'CREATE POLICY project_scope ON "{table}" {to} USING {_by_asset(table)}')
        )
    for table, links in BY_PARENT:
        op.execute(sa.text(
            f'CREATE POLICY project_scope ON "{table}" {to} USING {_by_parent(table, links)}'
        ))  # fmt: skip


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in ("assets", *BY_ASSET, *(t for t, _ in BY_PARENT)):
            op.execute(sa.text(f'DROP POLICY IF EXISTS project_scope ON "{table}"'))
        for table in ("users", "role_overrides"):
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
        for role in SERVICE_ROLES:
            op.execute(sa.text(f"""
                DO $$
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}')
                       AND EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{GUEST_ROLE}') THEN
                        REVOKE "{GUEST_ROLE}" FROM "{role}";
                    END IF;
                END $$;
            """))  # fmt: skip
        op.execute(sa.text(f'DROP ROLE IF EXISTS "{GUEST_ROLE}"'))
    with op.batch_alter_table("api_tokens") as b:
        b.drop_index("ix_api_tokens_user_id")
        b.drop_constraint("fk_api_tokens_user_id", type_="foreignkey")
        b.drop_column("user_id")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_index("ix_role_overrides_user_id", table_name="role_overrides")
    op.drop_table("role_overrides")
    op.drop_index("ix_users_org_id", table_name="users")
    op.drop_table("users")
