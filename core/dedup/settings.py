"""Reading, writing and applying a project's deduplication settings (plan §42.3, ADR-0042).

A setting is per (project, source) and versioned by insertion. `rekey` is the one place a
finding's identity is overridden: it runs before findings are matched to Issues, for imports and for
native scans alike, so a source is matched the same way however its findings arrive.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.dedup.strategies import DEFAULT, key_for, source_of, validate
from core.models import Finding
from core.persistence.models import DedupSetting
from core.tenancy import DEFAULT_ORG_ID


@dataclass(frozen=True)
class Setting:
    source: str
    strategy: str
    fields: tuple[str, ...]
    version: int


def current_settings(s: Session, asset_id: str) -> dict[str, Setting]:
    """The setting in force for each source of a project: its highest version."""
    rows = s.scalars(
        select(DedupSetting).where(DedupSetting.asset_id == asset_id).order_by(DedupSetting.version)
    )
    return {r.source: Setting(r.source, r.strategy, tuple(r.fields or ()), r.version) for r in rows}


def history(s: Session, asset_id: str, source: str | None = None) -> list[DedupSetting]:
    q = select(DedupSetting).where(DedupSetting.asset_id == asset_id)
    if source:
        q = q.where(DedupSetting.source == source)
    return list(s.scalars(q.order_by(DedupSetting.source, DedupSetting.version.desc())))


def save_setting(
    s: Session,
    *,
    org_id: str = DEFAULT_ORG_ID,
    asset_id: str,
    source: str,
    strategy: str,
    fields: tuple[str, ...] = (),
    created_by: str | None = None,
    note: str | None = None,
    effect: dict[str, object] | None = None,
) -> DedupSetting:
    """Record the next version of a source's setting. Never edits an earlier row; the caller owns
    the commit (the dry-run service writes it in the same transaction as the Issues it changes)."""
    fields = validate(strategy, fields)
    latest = s.scalar(
        select(DedupSetting.version)
        .where(DedupSetting.asset_id == asset_id, DedupSetting.source == source)
        .order_by(DedupSetting.version.desc())
        .limit(1)
    )
    row = DedupSetting(
        org_id=org_id,
        asset_id=asset_id,
        source=source,
        strategy=strategy,
        fields=list(fields),
        version=(latest or 0) + 1,
        note=note,
        created_by=created_by,
        effect=dict(effect or {}),
    )
    s.add(row)
    s.flush()
    return row


def rekey(findings: list[Finding], settings: dict[str, Setting]) -> int:
    """Give each finding the key its source's strategy says, in place. Returns how many findings'
    keys changed. A source with no setting, or the default strategy, is left alone."""
    changed = 0
    for f in findings:
        setting = settings.get(source_of(f))
        if setting is None or setting.strategy == DEFAULT:
            continue
        key = key_for(setting.strategy, f, setting.fields)
        if key != f.fingerprint:
            f.fingerprint = key
            changed += 1
    return changed


def rekey_for_asset(s: Session, asset_id: str, findings: list[Finding]) -> int:
    settings = current_settings(s, asset_id)
    return rekey(findings, settings) if settings else 0
