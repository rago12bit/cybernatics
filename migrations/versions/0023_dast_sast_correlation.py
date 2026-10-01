"""SAST/DAST correlation: scans.route_map, issues.confirmed_at_runtime (Week 49 task 4, plan §22.4)

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-01

`scans.route_map` is populated by an ordinary SAST/archive/git scan (core.pipeline.
_extract_route_map, best-effort, Python-only for now) -- a snapshot of "this route is handled
here," taken while the scan's workspace still exists, since nothing else persists that source after
the scan finishes. `issues.confirmed_at_runtime_at`/`confirmed_by_scan_id` are set later, by a DAST
campaign (core.dast.pipeline) whose own finding matched one of those routes on CWE too
(core.dast.correlate). Same JSON-column pattern as migration 0010's `sbom_summary`; no RLS
changes, both tables already carry migration 0005's tenant_isolation policy regardless of which
columns exist.

`assets.linked_source_asset_id`: a `web` Asset's SAST scans and DAST campaigns are never the same
Asset row (different `source_type`, different identity) -- correlation needs an explicit link from
the web Asset to the git/archive Asset whose route map it should be checked against, since nothing
else in the schema connects "this live site" to "this source repository."
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None

JSON_T = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.add_column("scans", sa.Column("route_map", JSON_T, nullable=True))
    op.add_column(
        "issues", sa.Column("confirmed_at_runtime_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("issues", sa.Column("confirmed_by_scan_id", sa.String(length=36), nullable=True))
    op.add_column(
        "assets", sa.Column("linked_source_asset_id", sa.String(length=36), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("assets", "linked_source_asset_id")
    op.drop_column("issues", "confirmed_by_scan_id")
    op.drop_column("issues", "confirmed_at_runtime_at")
    op.drop_column("scans", "route_map")
