"""Single sign-on: identity providers, sign-in attempts, linked identities (Week 75, plan §51)

Revision ID: 0049
Revises: 0048
Create Date: 2026-10-07

- `identity_providers`: an organization's OIDC or SAML provider -- its settings as JSON (issuer,
  client id and endpoints; or the IdP's entity id, sign-in URL and certificate), where its secret
  is kept, which email domains it vouches for, and whether a first sign-in creates the account.
  Forced RLS.
- `sso_domains`: which provider an email domain signs in with. Read before any organization is
  known (the sign-in page asks for an email first), so it carries no RLS, and holds nothing but the
  domain, the provider and its organization. A domain belongs to one provider anywhere.
- `login_attempts`: a sign-in in flight -- the hash of its `state`, the OIDC nonce and PKCE
  verifier, or the SAML request id -- used once, for ten minutes. Resolved by the callback before
  the organization is known: no RLS, like `user_sessions`.
- `user_identities`: a person's account at a provider (its stable subject or NameID). Once linked,
  another account at the provider with the same email cannot take the person's place. Forced RLS.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "identity_providers",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config", JSON_T, nullable=False),
        sa.Column("secret_store", sa.String(length=16), nullable=False),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("email_domains", JSON_T, nullable=False),
        sa.Column("auto_create", sa.Boolean(), nullable=False),
        sa.Column("default_role", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
    )  # fmt: skip
    op.create_index("ix_identity_providers_org_id", "identity_providers", ["org_id"])
    op.create_table(
        "sso_domains",
        sa.Column("domain", sa.String(length=253), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("provider_id", sa.String(length=36),
                  sa.ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False),
    )  # fmt: skip
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.String(length=64), primary_key=True),  # SHA-256 of `state`
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("provider_id", sa.String(length=36),
                  sa.ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=True),
        sa.Column("verifier", sa.String(length=128), nullable=True),
        sa.Column("request_id", sa.String(length=128), nullable=True),
        sa.Column("next_path", sa.String(length=500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )  # fmt: skip
    op.create_index("ix_login_attempts_request_id", "login_attempts", ["request_id"])
    op.create_table(
        "user_identities",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("org_id", sa.String(length=36), sa.ForeignKey("organizations.id"),
                  nullable=False),
        sa.Column("provider_id", sa.String(length=36),
                  sa.ForeignKey("identity_providers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider_id", "subject", name="uq_user_identities_subject"),
        sa.UniqueConstraint("provider_id", "user_id", name="uq_user_identities_user"),
    )  # fmt: skip

    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (tests): no roles, no RLS -- app-level filtering protects these rows
    for table in ("identity_providers", "sso_domains", "login_attempts", "user_identities"):
        op.execute(
            sa.text(f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "{table}" TO "{APP_ROLE}"')
        )
    for table in ("identity_providers", "user_identities"):
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
        for table in ("identity_providers", "user_identities"):
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    op.drop_table("user_identities")
    op.drop_index("ix_login_attempts_request_id", table_name="login_attempts")
    op.drop_table("login_attempts")
    op.drop_table("sso_domains")
    op.drop_index("ix_identity_providers_org_id", table_name="identity_providers")
    op.drop_table("identity_providers")
