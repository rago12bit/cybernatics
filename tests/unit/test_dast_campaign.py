"""core.dast.campaign's safe-by-default rules (Week 49 task 3, plan §22.4): tool selection per mode
and the active-scan rate limit, in isolation from any I/O."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.dast.campaign import (
    ACTIVE_SCAN_MIN_INTERVAL,
    CampaignError,
    check_active_scan_rate_limit,
    tools_for_mode,
)


def test_passive_mode_is_zap_only() -> None:
    assert tools_for_mode("passive") == ("zap-baseline",)


def test_active_mode_adds_nuclei() -> None:
    assert tools_for_mode("active") == ("zap-baseline", "nuclei")


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(CampaignError, match="unknown campaign mode"):
        tools_for_mode("aggressive")


def test_no_prior_active_campaign_is_always_allowed() -> None:
    assert check_active_scan_rate_limit(None).allowed is True


def test_an_active_campaign_just_started_is_rate_limited() -> None:
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    result = check_active_scan_rate_limit(now - timedelta(hours=1), now=now)
    assert result.allowed is False
    assert result.retry_after == ACTIVE_SCAN_MIN_INTERVAL - timedelta(hours=1)


def test_an_active_campaign_from_exactly_the_interval_ago_is_allowed() -> None:
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    result = check_active_scan_rate_limit(now - ACTIVE_SCAN_MIN_INTERVAL, now=now)
    assert result.allowed is True


def test_an_active_campaign_from_well_over_the_interval_ago_is_allowed() -> None:
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    result = check_active_scan_rate_limit(now - timedelta(days=30), now=now)
    assert result.allowed is True
