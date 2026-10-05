"""SLA rules, without a database (plan §44.1, Week 61).

An Issue has `days` from first detection to be fixed, by its severity band, and is "due soon" in the
last `warn` days of that window. The clock is `first_seen_at`, which reimport never resets (so
re-uploading a report cannot restart a deadline -- DefectDojo behaves the same way), unless a risk
acceptance restarted it (`sla_started_at`, Week 62).

States:
- `on_track`, `due_soon`, `breached` -- an open Issue with a deadline.
- `met`, `missed` -- a fixed Issue, by whether it was fixed before its deadline.
- `exempt` -- a person took it out of the queue (not a risk, or a risk accepted until a date still
  ahead); the clock still runs from first detection, and the deadline applies again once that
  decision lapses.
- `none` -- no policy, the policy is off, or the band has no deadline (by default, Info).

Priority bands (§44.1's alternative basis) arrive with the priority engine (Week 63); until then
the basis is severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

BANDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
BASES = ("severity",)
OPEN_STATES = ("new", "open", "reintroduced")
OPEN_SLA = ("on_track", "due_soon", "breached")
MAX_DAYS = 3650

# Offered, not imposed: a project has no SLA until someone saves a policy.
STARTER: dict[str, dict[str, int | None]] = {
    "CRITICAL": {"days": 7, "warn": 2},
    "HIGH": {"days": 30, "warn": 7},
    "MEDIUM": {"days": 90, "warn": 14},
    "LOW": {"days": 180, "warn": 30},
    "INFO": {"days": None, "warn": None},
}


class PolicyError(ValueError):
    def __init__(self, field_name: str, message: str) -> None:
        super().__init__(message)
        self.field = field_name


@dataclass(frozen=True)
class Band:
    days: int | None
    warn: int


@dataclass(frozen=True)
class Policy:
    enabled: bool = False
    basis: str = "severity"
    bands: dict[str, Band] = field(default_factory=dict)

    def band(self, severity: str) -> Band | None:
        b = self.bands.get(severity.upper())
        return b if self.enabled and b is not None and b.days is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "basis": self.basis,
            "bands": {k: {"days": b.days, "warn": b.warn} for k, b in self.bands.items()},
        }


def parse_bands(raw: Any) -> dict[str, Band]:
    """Validated bands; every severity present, so a stored policy says what it means for each."""
    if not isinstance(raw, dict):
        raise PolicyError("bands", "bands maps each severity to {days, warn}")
    unknown = sorted(set(map(str, raw)) - set(BANDS) - {b.lower() for b in BANDS})
    if unknown:
        raise PolicyError("bands", f"unknown severity: {', '.join(unknown)}")
    out: dict[str, Band] = {}
    for name in BANDS:
        entry = raw.get(name, raw.get(name.lower()))
        entry = entry if isinstance(entry, dict) else {}
        days, warn = entry.get("days"), entry.get("warn")
        if days in (None, ""):
            out[name] = Band(None, 0)
            continue
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
            raise PolicyError(f"bands.{name}.days", f"{name.title()}: days is 1 to {MAX_DAYS}")
        if warn in (None, ""):
            warn = 0
        if isinstance(warn, bool) or not isinstance(warn, int) or not 0 <= warn < days:
            raise PolicyError(
                f"bands.{name}.warn",
                f"{name.title()}: the warning is 0 to {days - 1} days before the deadline",
            )
        out[name] = Band(days, warn)
    return out


def from_row(enabled: bool, basis: str, bands: dict[str, Any]) -> Policy:
    return Policy(enabled, basis, parse_bands(bands))


STARTER_POLICY = Policy(False, "severity", parse_bands(STARTER))


@dataclass(frozen=True)
class Status:
    state: str
    due_at: datetime | None = None
    started_at: datetime | None = None
    days: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "due_at": self.due_at,
            "started_at": self.started_at,
            "days": self.days,
        }


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def evaluate(
    policy: Policy,
    *,
    severity: str,
    state: str,
    first_seen_at: datetime,
    sla_started_at: datetime | None,
    fixed_at: datetime | None,
    triage_status: str,
    triage_expires_at: datetime | None,
    now: datetime,
) -> Status:
    band = policy.band(severity)
    if band is None or band.days is None:
        return Status("none")
    started = _utc(sla_started_at or first_seen_at)
    due = started + timedelta(days=band.days)

    def at(state: str) -> Status:
        return Status(state, due, started, band.days)

    if state not in OPEN_STATES:
        if fixed_at is None:
            return Status("none")
        return at("met" if _utc(fixed_at) <= due else "missed")
    if triage_status == "not_a_risk" or (
        triage_status == "accepted" and (triage_expires_at is None or _utc(triage_expires_at) > now)
    ):
        return at("exempt")
    if now >= due:
        return at("breached")
    if now >= due - timedelta(days=band.warn):
        return at("due_soon")
    return at("on_track")
