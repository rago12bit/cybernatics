"""core.sandbox.seccomp's current, deliberately conservative behavior (Week 46 task 2, plan §22.1):
no profile is authored yet, so every scanner gets None -- see the module docstring for why shipping
a custom profile now would be a regression, not hardening."""

from __future__ import annotations

from core.sandbox.seccomp import SCANNER_FAMILY, seccomp_profile_path


def test_seccomp_profile_path_is_none_for_every_known_scanner() -> None:
    for scanner in SCANNER_FAMILY:
        assert seccomp_profile_path(scanner) is None


def test_seccomp_profile_path_is_none_for_an_unknown_scanner() -> None:
    assert seccomp_profile_path("some-future-scanner") is None
