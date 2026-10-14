"""One standing "ci" and one "import" engagement per project

Revision ID: 0052
Revises: 0051
Create Date: 2026-10-14

`repo.get_or_create_ci_engagement` and `get_or_create_import_engagement` create these lazily, and
nothing in the database stopped two transactions doing it at once (two uploads to a new project,
say), each creating one. A partial unique index now does; the code takes the other's row when its
insert loses.

Duplicates made before this are merged first, into the oldest of each pair: their tool runs and
Tests move to it. A Test whose name the oldest engagement already has keeps its history under a new
name, "<name> (merged <8 characters of its id>)", rather than being folded into the other: the two
were reimported separately, and combining their snapshots would close Issues that are still open.
Standing engagements have no checklist (only assessments do); if one somehow has entries, the
migration stops rather than delete them.

Runs as the migration role, which row-level security does not restrict, so it sees every
organization's rows.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None

STANDING = "engagement_type IN ('ci', 'import')"


def _merge_duplicates(bind: sa.engine.Connection) -> None:
    groups = bind.execute(sa.text(
        f'SELECT asset_id, engagement_type FROM "engagements" WHERE {STANDING} '
        "GROUP BY asset_id, engagement_type HAVING count(*) > 1"
    )).fetchall()  # fmt: skip
    for asset_id, kind in groups:
        ids = [r[0] for r in bind.execute(sa.text(
            'SELECT id FROM "engagements" WHERE asset_id = :a AND engagement_type = :k '
            "ORDER BY created_at, id"
        ), {"a": asset_id, "k": kind})]  # fmt: skip
        keep, extra = ids[0], ids[1:]
        for dup in extra:
            if bind.execute(sa.text(
                'SELECT 1 FROM "engagement_checklist_items" WHERE engagement_id = :d LIMIT 1'
            ), {"d": dup}).first():  # fmt: skip
                raise RuntimeError(
                    f'engagement {dup} is a duplicate standing "{kind}" engagement with checklist '
                    "entries, which only assessments have; move or delete them, then migrate again"
                )
            bind.execute(sa.text(
                'UPDATE "tool_runs" SET engagement_id = :k WHERE engagement_id = :d'
            ), {"k": keep, "d": dup})  # fmt: skip
            taken = {r[0] for r in bind.execute(sa.text(
                'SELECT name FROM "engagement_tests" WHERE engagement_id = :k'
            ), {"k": keep})}  # fmt: skip
            for test_id, name in bind.execute(sa.text(
                'SELECT id, name FROM "engagement_tests" WHERE engagement_id = :d'
            ), {"d": dup}).fetchall():  # fmt: skip
                if name in taken:
                    suffix = f" (merged {test_id[:8]})"
                    name = name[: 200 - len(suffix)] + suffix
                bind.execute(sa.text(
                    'UPDATE "engagement_tests" SET engagement_id = :k, name = :n WHERE id = :t'
                ), {"k": keep, "n": name, "t": test_id})  # fmt: skip
                taken.add(name)
            bind.execute(sa.text('DELETE FROM "engagements" WHERE id = :d'), {"d": dup})


def upgrade() -> None:
    _merge_duplicates(op.get_bind())
    op.create_index(
        "uq_engagements_standing", "engagements", ["asset_id", "engagement_type"], unique=True,
        postgresql_where=sa.text(STANDING), sqlite_where=sa.text(STANDING),
    )  # fmt: skip


def downgrade() -> None:
    op.drop_index("uq_engagements_standing", table_name="engagements")
