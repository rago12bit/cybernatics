"""core.dast.egress's ruleset construction and sidecar invocation (Week 49 task 2, plan §22.4).

Same split as test_fixagent_egress.py: the generated ruleset's shape/ordering and the sidecar-
invocation wiring are covered here; actually loading nftables rules into a real network namespace is
Linux-only and cannot run on this (macOS) dev machine -- disclosed, not silently skipped, in
docs/v2-week49-verification.md, the same honest boundary Week 46's egress work already drew.
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from core.dast.egress import (
    EgressPolicyError,
    apply_dast_egress_policy,
    build_dast_egress_nft_ruleset,
)
from core.fixagent.egress import EGRESS_SIDECAR_IMAGE


def test_ruleset_denies_all_direct_egress_and_allows_only_the_proxy() -> None:
    ruleset = build_dast_egress_nft_ruleset("10.0.5.7", 8080)
    assert "policy drop;" in ruleset
    assert "ip daddr 10.0.5.7 tcp dport 8080 accept" in ruleset
    # unlike the fix-verification ruleset, direct 80/443 to anywhere is never allowed
    assert "tcp dport { 80, 443 } accept" not in ruleset


def test_ruleset_allows_dns_before_the_only_other_accept_rule() -> None:
    ruleset = build_dast_egress_nft_ruleset("10.0.5.7", 8080)
    dns_line = next(i for i, line in enumerate(ruleset.splitlines()) if "dport 53" in line)
    proxy_line = next(i for i, line in enumerate(ruleset.splitlines()) if "daddr 10.0.5.7" in line)
    assert dns_line < proxy_line


def test_ruleset_drops_ipv6_outright() -> None:
    assert "meta nfproto ipv6 drop" in build_dast_egress_nft_ruleset("10.0.5.7", 8080)


def test_apply_dast_egress_policy_runs_the_sidecar_against_the_runners_netns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        seen["argv"] = argv
        seen["input"] = kw.get("input")
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    apply_dast_egress_policy("runner-container", proxy_host="10.0.5.7", proxy_port=8080)
    assert "--network=container:runner-container" in seen["argv"]
    assert seen["argv"][-3] == EGRESS_SIDECAR_IMAGE
    assert b"ip daddr 10.0.5.7 tcp dport 8080 accept" in seen["input"]


def test_apply_dast_egress_policy_raises_on_sidecar_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"syntax error")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(EgressPolicyError, match="syntax error"):
        apply_dast_egress_policy("runner-container", proxy_host="10.0.5.7", proxy_port=8080)


def test_apply_dast_egress_policy_raises_when_docker_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        raise FileNotFoundError("no docker")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(EgressPolicyError):
        apply_dast_egress_policy("runner-container", proxy_host="10.0.5.7", proxy_port=8080)
