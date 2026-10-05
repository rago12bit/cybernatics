"""Risk acceptance with four-eyes approval (Week 62, plan §44.2, ADR-0046)

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-05

Both new tables carry a direct `org_id` with the same forced RLS policy as every v3 table. An
evidence attachment may now belong to a risk acceptance instead of a manual finding.

Data: every Issue someone accepted alone through triage (`triage_status = 'accepted'`) becomes part
of a *legacy* risk acceptance -- one per (project, person, expiry, reason) -- so no acceptance and
no expiry date is lost. They are marked legacy because nobody else approved them; one whose date
has passed is recorded as expired. The Issues themselves are not changed. Rows are read and written
one organization at a time with that org's scope set, so this works under forced RLS.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None

APP_ROLE = "bulwark_app"
JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")
TABLES = ("risk_acceptances", "risk_acceptance_issues")
LEGACY_NOTE = "Accepted by one person through triage, before four-eyes approval existed (migrated)."


def _aware(value: Any) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def upgrade() -> None:
    bind = op.get_bind()
    pg = bind.dialect.name == "postgresql"
    op.create_table(
        "risk_acceptances",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("controls", sa.Text(), nullable=False),
        sa.Column("proof_links", JSON_T, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("restart_sla", sa.Boolean(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("requested_by", sa.String(length=200), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approver", sa.String(length=200), nullable=True),
        sa.Column("decided_by", sa.String(length=200), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_by", sa.String(length=200), nullable=True),
        sa.Column("ended_reason", sa.String(length=24), nullable=True),
        sa.Column("extends_id", sa.String(length=36), nullable=True),
        sa.Column("legacy", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["extends_id"], ["risk_acceptances.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_risk_acceptances_org_id", "risk_acceptances", ["org_id"])
    op.create_index("ix_risk_acceptances_asset_id", "risk_acceptances", ["asset_id"])
    op.create_index("ix_risk_acceptances_state", "risk_acceptances", ["state"])
    op.create_table(
        "risk_acceptance_issues",
        sa.Column("acceptance_id", sa.String(length=36), nullable=False),
        sa.Column("issue_id", sa.String(length=36), nullable=False),
        sa.Column("org_id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["acceptance_id"], ["risk_acceptances.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["issue_id"], ["issues.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("acceptance_id", "issue_id"),
    )
    op.create_index("ix_risk_acceptance_issues_issue_id", "risk_acceptance_issues", ["issue_id"])
    op.create_index("ix_risk_acceptance_issues_org_id", "risk_acceptance_issues", ["org_id"])
    with op.batch_alter_table("evidence_attachments") as b:
        b.alter_column("manual_finding_id", existing_type=sa.String(length=36), nullable=True)
        b.add_column(sa.Column("risk_acceptance_id", sa.String(length=36), nullable=True))
        b.create_foreign_key(
            "fk_evidence_attachments_risk_acceptance_id", "risk_acceptances",
            ["risk_acceptance_id"], ["id"], ondelete="CASCADE",
        )  # fmt: skip
        b.create_index("ix_evidence_attachments_risk_acceptance_id", ["risk_acceptance_id"])

    if pg:
        for table in TABLES:
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
    _migrate_triage_acceptances(bind, pg)


def _migrate_triage_acceptances(bind: Any, pg: bool) -> None:
    now = datetime.now(timezone.utc)
    for (org_id,) in bind.execute(sa.text('SELECT id FROM "organizations"')).fetchall():
        if pg:
            bind.execute(sa.text("SELECT set_config('app.current_org', :o, true)"), {"o": org_id})
        rows = bind.execute(
            sa.text(
                "SELECT i.id, i.asset_id, i.triage_reason, i.triage_expires_at, i.triaged_by, "
                'i.triaged_at FROM "issues" i JOIN "assets" a ON a.id = i.asset_id '
                "WHERE a.org_id = :o AND i.triage_status = 'accepted' "
                "AND i.triage_expires_at IS NOT NULL ORDER BY i.id"
            ),
            {"o": org_id},
        ).fetchall()
        groups: dict[tuple[Any, ...], list[Any]] = {}
        for r in rows:
            groups.setdefault((r[1], r[4], str(r[3]), r[2]), []).append(r)
        for (asset_id, by, _, reason), members in groups.items():
            expires = _aware(members[0][3])
            at = _aware(members[0][5]) if members[0][5] else now
            live = expires > now
            acceptance_id = str(uuid.uuid4())
            bind.execute(
                sa.text(
                    'INSERT INTO "risk_acceptances" (id, org_id, asset_id, decision, '
                    "justification, controls, proof_links, expires_at, restart_sla, state, "
                    "requested_by, "
                    "requested_at, approver, decided_by, decided_at, decision_note, ended_at, "
                    "ended_by, ended_reason, extends_id, legacy) VALUES (:id, :org, :asset, "
                    "'accept', :why, '', :links, :expires, :f, :state, :by, :at, NULL, NULL, :at, "
                    ":note, :ended, :ended_by, :reason, NULL, :t)"
                ).bindparams(
                    sa.bindparam("links", type_=JSON_T),
                    sa.bindparam("expires", type_=sa.DateTime(timezone=True)),
                    sa.bindparam("at", type_=sa.DateTime(timezone=True)),
                    sa.bindparam("ended", type_=sa.DateTime(timezone=True)),
                ),
                {
                    "id": acceptance_id, "org": org_id, "asset": asset_id,
                    "why": reason or "No reason was recorded when this was accepted.",
                    "links": [], "expires": expires, "f": False,
                    "state": "approved" if live else "expired", "by": by or "unknown",
                    "at": at, "note": LEGACY_NOTE, "ended": None if live else expires,
                    "ended_by": None if live else "system", "reason": None if live else "expiry",
                    "t": True,
                },  # fmt: skip
            )
            for m in members:
                bind.execute(
                    sa.text(
                        'INSERT INTO "risk_acceptance_issues" (acceptance_id, issue_id, org_id) '
                        "VALUES (:a, :i, :o)"
                    ),
                    {"a": acceptance_id, "i": m[0], "o": org_id},
                )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in TABLES:
            op.execute(sa.text(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"'))
    op.execute(sa.text('DELETE FROM "evidence_attachments" WHERE manual_finding_id IS NULL'))
    with op.batch_alter_table("evidence_attachments") as b:
        b.drop_index("ix_evidence_attachments_risk_acceptance_id")
        b.drop_constraint("fk_evidence_attachments_risk_acceptance_id", type_="foreignkey")
        b.drop_column("risk_acceptance_id")
        b.alter_column("manual_finding_id", existing_type=sa.String(length=36), nullable=False)
    op.drop_index("ix_risk_acceptance_issues_org_id", table_name="risk_acceptance_issues")
    op.drop_index("ix_risk_acceptance_issues_issue_id", table_name="risk_acceptance_issues")
    op.drop_table("risk_acceptance_issues")
    op.drop_index("ix_risk_acceptances_state", table_name="risk_acceptances")
    op.drop_index("ix_risk_acceptances_asset_id", table_name="risk_acceptances")
    op.drop_index("ix_risk_acceptances_org_id", table_name="risk_acceptances")
    op.drop_table("risk_acceptances")
