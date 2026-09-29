"""core/supplychain/scorecard.py (plan §20.5): OpenSSF Scorecard for direct dependencies, via
deps.dev (purl -> source repo) and the Scorecard REST API. `fetch` is always injected here -- these
tests never touch the network -- but the JSON shapes come from the real, live endpoints
(`api.deps.dev/v3alpha/purl/...`, `api.securityscorecards.dev/projects/...`), fetched while
validating this feature (github.com/psf/requests, github.com/sirupsen/logrus)."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from core.supplychain.scorecard import (
    ScorecardResult,
    enrich_direct_dependencies,
    fetch_scorecard,
    resolve_source_repo,
)

DEPS_DEV_RESPONSE = json.dumps(
    {
        "version": {
            "relatedProjects": [
                {"projectKey": {"id": "github.com/psf/requests"}, "relationType": "SOURCE_REPO"}
            ]
        }
    }
).encode()

SCORECARD_RESPONSE = json.dumps(
    {
        "date": "2026-09-28",
        "score": 8.3,
        "checks": [{"name": "Code-Review", "score": 9}, {"name": "Maintained", "score": 10}],
    }
).encode()


def _fetch(deps_dev: bytes = DEPS_DEV_RESPONSE, scorecard: bytes = SCORECARD_RESPONSE):
    def fetch(url: str) -> bytes:
        return deps_dev if "deps.dev" in url else scorecard

    return fetch


def _isolated_workdir():
    return patch.dict("os.environ", {"BULWARK_WORKDIR": tempfile.mkdtemp()})


def test_resolve_source_repo_reads_the_source_repo_link() -> None:
    assert (
        resolve_source_repo("pkg:pypi/requests@2.31.0", fetch=_fetch()) == "github.com/psf/requests"
    )


def test_resolve_source_repo_is_none_without_a_github_source_repo_link() -> None:
    empty = json.dumps({"version": {"relatedProjects": []}}).encode()
    assert resolve_source_repo("pkg:pypi/x@1.0.0", fetch=_fetch(deps_dev=empty)) is None


def test_resolve_source_repo_is_none_on_a_network_error_not_a_raised_exception() -> None:
    def fails(url: str) -> bytes:
        raise OSError("network down")

    assert resolve_source_repo("pkg:pypi/x@1.0.0", fetch=fails) is None


def test_fetch_scorecard_parses_score_and_checks() -> None:
    with _isolated_workdir():
        result = fetch_scorecard("github.com/psf/requests", fetch=_fetch())
    assert result == ScorecardResult(
        "github.com/psf/requests", 8.3, {"Code-Review": 9.0, "Maintained": 10.0}, "2026-09-28"
    )


def test_fetch_scorecard_is_none_when_scorecard_has_no_data_for_the_repo() -> None:
    def fetch(url: str) -> bytes:
        raise OSError("404")

    with _isolated_workdir():
        assert fetch_scorecard("github.com/nobody/nothing", fetch=fetch) is None


def test_fetch_scorecard_uses_the_cache_on_a_second_call() -> None:
    calls = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        return SCORECARD_RESPONSE

    with _isolated_workdir():
        fetch_scorecard("github.com/psf/requests", fetch=fetch)
        fetch_scorecard("github.com/psf/requests", fetch=fetch)
    assert len(calls) == 1  # the second call was served from the on-disk cache


def test_fetch_scorecard_refetches_once_the_cache_is_stale() -> None:
    calls = []

    def fetch(url: str) -> bytes:
        calls.append(url)
        return SCORECARD_RESPONSE

    with _isolated_workdir():
        now = datetime.now(timezone.utc)
        fetch_scorecard("github.com/psf/requests", fetch=fetch, now=now)
        fetch_scorecard("github.com/psf/requests", fetch=fetch, now=now + timedelta(days=8))
    assert len(calls) == 2


def test_enrich_direct_dependencies_skips_purls_deps_dev_cannot_resolve() -> None:
    empty = json.dumps({"version": {"relatedProjects": []}}).encode()
    with _isolated_workdir():
        out = enrich_direct_dependencies(
            frozenset({"pkg:pypi/unknown@1.0.0"}), fetch=_fetch(deps_dev=empty)
        )
    assert out == {}


def test_enrich_direct_dependencies_maps_purl_to_its_scorecard_result() -> None:
    with _isolated_workdir():
        out = enrich_direct_dependencies(frozenset({"pkg:pypi/requests@2.31.0"}), fetch=_fetch())
    assert out["pkg:pypi/requests@2.31.0"].repo == "github.com/psf/requests"
