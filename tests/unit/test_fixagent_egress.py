"""core.fixagent.egress's ruleset construction and sidecar invocation (Week 46 task 3, plan §22.1).

The ruleset content and ordering were verified live against a real container (Docker Desktop on
macOS: DNS-before-deny ordering, the IPv6 drop, metadata/RFC1918 blocking, pypi.org still reachable
-- see docs/v2-week46-verification.md). Unit tests here cover what's mechanically checkable without
a live container: the generated ruleset's shape/ordering, and that apply_egress_policy invokes the
sidecar correctly and surfaces its failures as EgressPolicyError."""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from core.fixagent.egress import (
    DEFAULT_DENIED_CIDRS,
    EGRESS_SIDECAR_IMAGE,
    EgressPolicyError,
    apply_egress_policy,
    build_egress_nft_ruleset,
)


def test_ruleset_denies_by_default_and_allows_dns_and_http_https() -> None:
    ruleset = build_egress_nft_ruleset()
    assert "policy drop;" in ruleset
    assert "tcp dport { 80, 443 } accept" in ruleset
    for cidr in DEFAULT_DENIED_CIDRS:
        assert cidr in ruleset


def test_ruleset_allows_dns_before_denying_internal_ranges() -> None:
    """Docker's own embedded DNS resolver commonly lives in RFC1918 space -- denying that range
    before DNS is allowed breaks every package install, not just internal-network access (found by
    live testing, not by inspection alone -- see the module docstring)."""
    ruleset = build_egress_nft_ruleset()
    dns_line = next(i for i, line in enumerate(ruleset.splitlines()) if "dport 53" in line)
    deny_line = next(
        i for i, line in enumerate(ruleset.splitlines()) if "drop" in line and "daddr" in line
    )
    assert dns_line < deny_line


def test_ruleset_drops_ipv6_outright() -> None:
    """An unmirrored IPv6 allow silently bypassed the IPv4 deny rules in live testing (curl -6
    reached a host the IPv4 rule blocked) -- see the module docstring."""
    ruleset = build_egress_nft_ruleset()
    assert "meta nfproto ipv6 drop" in ruleset


def test_ruleset_uses_a_custom_denylist_when_given_one() -> None:
    ruleset = build_egress_nft_ruleset(["203.0.113.0/24"])
    assert "203.0.113.0/24" in ruleset
    assert "10.0.0.0/8" not in ruleset


def test_apply_egress_policy_runs_the_sidecar_against_the_targets_netns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        seen["argv"] = argv
        seen["input"] = kw.get("input")
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    apply_egress_policy("target-container")
    assert "--network=container:target-container" in seen["argv"]
    assert "--cap-add=NET_ADMIN" in seen["argv"]
    assert seen["argv"][-3] == EGRESS_SIDECAR_IMAGE
    assert b"table inet bulwark_egress" in seen["input"]


def test_apply_egress_policy_raises_on_sidecar_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"syntax error")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(EgressPolicyError, match="syntax error"):
        apply_egress_policy("target-container")


def test_apply_egress_policy_raises_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(argv, kw.get("timeout", 0))

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(EgressPolicyError):
        apply_egress_policy("target-container")


def test_apply_egress_policy_raises_when_docker_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError("no docker")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(EgressPolicyError):
        apply_egress_policy("target-container")
