"""Token budgets: per scan and per organization per month, a hard stop before any model call
(plan §21.1: "Token limits per scan and per organization per month, with a hard stop and a clear
message in the UI").

Two different lifetimes, two different homes, matching how the rest of this schema already
separates a one-off snapshot from a running counter (ADR-0025's `Scan.sbom_summary` discussion):
  - Per-scan usage lives on the `Scan` row itself (`llm_tokens_used`) -- one scan, one counter,
    updated in place.
  - Per-org-per-month usage lives in its own `LlmUsage` table, keyed by (org_id, period) -- many
    scans across a month share one organization's budget, so it can't live on any single Scan row.

Enforcement is check-before / record-after: the same class of imprecision `UsageLimiter`
(limits.py) already accepts for call counts, and `RemediationCache.hits`'s own non-atomic
increment (cache.py) already accepts for hit counts -- a budget can be exceeded by at most one
call's worth of tokens under concurrent requests, never silently, and the caller always gets a
clear, specific reason (which cap, how much used, how much allowed) to show the user.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from core.persistence.models import LlmUsage, Scan


@dataclass(frozen=True)
class BudgetConfig:
    per_scan: int = 200_000
    per_org_month: int = 2_000_000

    @staticmethod
    def from_env() -> BudgetConfig:
        env = os.environ
        return BudgetConfig(
            per_scan=int(env.get("BULWARK_LLM_MAX_TOKENS_PER_SCAN", "200000")),
            per_org_month=int(env.get("BULWARK_LLM_MAX_TOKENS_PER_ORG_MONTH", "2000000")),
        )


class BudgetExceeded(Exception):
    def __init__(self, scope: str, used: int, limit: int) -> None:
        super().__init__(
            f"AI token budget reached ({scope}): {used}/{limit} tokens used this period"
        )
        self.scope, self.used, self.limit = scope, used, limit


def current_period(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


def org_usage(s: Session, org_id: str, period: str | None = None) -> int:
    row = s.get(LlmUsage, (org_id, period or current_period()))
    return row.tokens if row else 0


def check(s: Session, scan: Scan, cfg: BudgetConfig | None = None) -> None:
    """Call this immediately before a model call. Raises when either cap is already reached; never
    tries to predict whether the *upcoming* call would exceed it, since the real cost isn't known
    until the provider replies (the same limitation `UsageLimiter.acquire` already has)."""
    cfg = cfg or BudgetConfig.from_env()
    if scan.llm_tokens_used >= cfg.per_scan:
        raise BudgetExceeded("this scan", scan.llm_tokens_used, cfg.per_scan)
    used = org_usage(s, scan.org_id)
    if used >= cfg.per_org_month:
        raise BudgetExceeded("this organization this month", used, cfg.per_org_month)


def record(s: Session, scan: Scan, tokens: int) -> None:
    """Add a real call's actual token cost to both counters. A no-op for tokens<=0 (a static
    fallback or a cache hit spent nothing) -- never called for those in the first place, but safe
    either way."""
    if tokens <= 0:
        return
    scan.llm_tokens_used += tokens
    period = current_period()
    row = s.get(LlmUsage, (scan.org_id, period))
    if row is None:
        s.add(LlmUsage(org_id=scan.org_id, period=period, tokens=tokens))
    else:
        row.tokens += tokens
    s.commit()


def check_org(s: Session, org_id: str, cfg: BudgetConfig | None = None) -> None:
    """`check` for a model call that belongs to no scan (drafting an import mapping, plan §42.4):
    only the organization's monthly cap applies."""
    cfg = cfg or BudgetConfig.from_env()
    used = org_usage(s, org_id)
    if used >= cfg.per_org_month:
        raise BudgetExceeded("this organization this month", used, cfg.per_org_month)


def record_org(s: Session, org_id: str, tokens: int) -> None:
    """`record` for a call that belongs to no scan: the organization's counter only."""
    if tokens <= 0:
        return
    period = current_period()
    row = s.get(LlmUsage, (org_id, period))
    if row is None:
        s.add(LlmUsage(org_id=org_id, period=period, tokens=tokens))
    else:
        row.tokens += tokens
    s.commit()
