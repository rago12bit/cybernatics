"""Safe-by-default DAST campaign rules: what tools a mode runs, and the one check that makes active
scanning opt-in rather than ambient (Week 49 task 3, plan §22.4). Pure logic, no I/O -- `core.dast.
pipeline` is the orchestration that actually runs a campaign end to end.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

MODES = frozenset({"passive", "active"})

# passive: ZAP baseline only -- spiders and observes, never sends an attack payload. Safe by default
# for any ownership-verified target, no extra gate beyond ownership itself.
# active: adds curated Nuclei (core.dast.adapters.nuclei's own EXCLUDED_TAGS keeps out anything
# intrusive/DoS-shaped even here) -- opt-in per campaign, and rate-limited below.
TOOLS_FOR_MODE: dict[str, tuple[str, ...]] = {
    "passive": ("zap-baseline",),
    "active": ("zap-baseline", "nuclei"),
}

# How often ONE asset may run an active campaign. A passive baseline has no such limit: it generates
# at most one crawl's worth of ordinary page requests, the same load a single real visitor would.
ACTIVE_SCAN_MIN_INTERVAL = timedelta(hours=24)


class CampaignError(Exception):
    """Raised for a campaign that must not start: unverified ownership, or rate-limited."""


@dataclass(frozen=True)
class RateLimitState:
    allowed: bool
    retry_after: timedelta | None = None


def check_active_scan_rate_limit(
    last_active_started_at: datetime | None, *, now: datetime | None = None
) -> RateLimitState:
    """`last_active_started_at` is the asset's most recent active-campaign start, or None if it has
    never run one. Always allowed when there's no prior active campaign -- the limit polices
    back-to-back active scans of the SAME target, not a brand-new one's first run."""
    if last_active_started_at is None:
        return RateLimitState(allowed=True)
    now = now or datetime.now(timezone.utc)
    elapsed = now - last_active_started_at
    if elapsed >= ACTIVE_SCAN_MIN_INTERVAL:
        return RateLimitState(allowed=True)
    return RateLimitState(allowed=False, retry_after=ACTIVE_SCAN_MIN_INTERVAL - elapsed)


def tools_for_mode(mode: str) -> tuple[str, ...]:
    if mode not in MODES:
        raise CampaignError(f"unknown campaign mode: {mode!r}; valid: {sorted(MODES)}")
    return TOOLS_FOR_MODE[mode]
