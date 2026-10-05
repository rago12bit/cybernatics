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

The basis is the severity, or the priority band (P1-P4) the priority engine gives each Issue (Week
63, plan §44.3). By priority, re-weighting a project moves its deadlines, as changing a severity
does.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

BANDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
PRIORITY_BANDS = ("P1", "P2", "P3", "P4")
BASES = ("severity", "priority")
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
STARTER_BY_PRIORITY: dict[str, dict[str, int | None]] = {
    "P1": {"days": 7, "warn": 2},
    "P2": {"days": 30, "warn": 7},
    "P3": {"days": 90, "warn": 14},
    "P4": {"days": 180, "warn": 30},
}


def band_names(basis: str) -> tuple[str, ...]:
    return PRIORITY_BANDS if basis == "priority" else BANDS


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

    def band(self, key: str | None) -> Band | None:
        b = self.bands.get(key.upper()) if key else None
        return b if self.enabled and b is not None and b.days is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "basis": self.basis,
            "bands": {k: {"days": b.days, "warn": b.warn} for k, b in self.bands.items()},
        }


def parse_bands(raw: Any, basis: str = "severity") -> dict[str, Band]:
    """Validated bands; every band of the basis present, so a stored policy says what it means for
    each."""
    what = "priority band" if basis == "priority" else "severity"
    names = band_names(basis)
    if not isinstance(raw, dict):
        raise PolicyError("bands", f"bands maps each {what} to {{days, warn}}")
    unknown = sorted(set(map(str, raw)) - set(names) - {b.lower() for b in names})
    if unknown:
        raise PolicyError("bands", f"unknown {what}: {', '.join(unknown)}")
    out: dict[str, Band] = {}
    for name in names:
        entry = raw.get(name, raw.get(name.lower()))
        entry = entry if isinstance(entry, dict) else {}
        days, warn = entry.get("days"), entry.get("warn")
        if days in (None, ""):
            out[name] = Band(None, 0)
            continue
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_DAYS:
            raise PolicyError(f"bands.{name}.days", f"{_title(name)}: days is 1 to {MAX_DAYS}")
        if warn in (None, ""):
            warn = 0
        if isinstance(warn, bool) or not isinstance(warn, int) or not 0 <= warn < days:
            raise PolicyError(
                f"bands.{name}.warn",
                f"{_title(name)}: the warning is 0 to {days - 1} days before the deadline",
            )
        out[name] = Band(days, warn)
    return out


def _title(name: str) -> str:
    return name if name in PRIORITY_BANDS else name.title()


def from_row(enabled: bool, basis: str, bands: dict[str, Any]) -> Policy:
    return Policy(enabled, basis, parse_bands(bands, basis))


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
    priority_band: str | None = None,
    state: str,
    first_seen_at: datetime,
    sla_started_at: datetime | None,
    fixed_at: datetime | None,
    triage_status: str,
    triage_expires_at: datetime | None,
    now: datetime,
) -> Status:
    band = policy.band(priority_band if policy.basis == "priority" else severity)
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
