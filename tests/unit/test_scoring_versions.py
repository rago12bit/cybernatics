"""core/scoring/versions.py: picking the smallest fixed version a scanner reported, not just
`fixed[0]` (plan §20.5)."""

from __future__ import annotations

from core.scoring.versions import smallest_safe_upgrade


def test_picks_the_numerically_smallest_not_the_lexicographically_smallest() -> None:
    # "1.10.0" < "1.9.0" lexicographically but not numerically -- this is the bug being fixed.
    assert smallest_safe_upgrade(["1.10.0", "1.9.0", "1.2.0"]) == "1.2.0"


def test_single_version_is_returned_as_is() -> None:
    assert smallest_safe_upgrade(["2.20.0"]) == "2.20.0"


def test_empty_list_is_none() -> None:
    assert smallest_safe_upgrade([]) is None


def test_a_git_commit_hash_mixed_in_refuses_to_guess_an_order() -> None:
    # Real OSV data: PYSEC-2023-62 lists two commit hashes and two real releases for the same fix.
    fixed = [
        "70f906c51ce49c485f1d355703e9cc3386b1cc2b",
        "afd63b16170b7c047f5758eb910c416511e9c965",
        "2.2.5",
        "2.3.2",
    ]
    assert smallest_safe_upgrade(fixed) is None


def test_a_prerelease_tag_also_refuses_to_guess() -> None:
    assert smallest_safe_upgrade(["1.2.0", "1.2.0-beta"]) is None
