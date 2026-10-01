"""DAST campaigns: scans.dast_mode (Week 49 task 3, plan §22.4)

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-01

A DAST campaign against a web Asset is just a `Scan` row with `source_type="web"` -- it needed no
new table of its own, `scans`/`tool_runs`/`findings` already carry everything a campaign's result
is (which tools ran, what they found). The one new thing a campaign needs that an ordinary scan
doesn't is `dast_mode` ("passive" | "active", null for every non-DAST scan): it drives the active-
scan rate limit (`core.dast.campaign.check_active_scan_rate_limit`), which has to tell one asset's
past ACTIVE campaigns apart from its past PASSIVE ones.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("dast_mode", sa.String(length=16), nullable=True))
    op.create_index("ix_scans_dast_mode", "scans", ["dast_mode"])


def downgrade() -> None:
    op.drop_index("ix_scans_dast_mode", table_name="scans")
    op.drop_column("scans", "dast_mode")
