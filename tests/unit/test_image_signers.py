"""THREAT-MODEL T10: every pinned image is either signature-checked or recorded as unsigned, and
the scanners whose publishers sign release files are built from those files, checked.

The signatures themselves are checked against the registries in CI (the `image-signatures` job runs
scripts/verify-image-signatures.py) and in each scanner image's own build; these tests keep the
lists and the Dockerfiles from drifting."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from image_pins import pinned_images, repository  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "verify_sigs", ROOT / "scripts" / "verify-image-signatures.py"
)
assert _spec and _spec.loader
verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify)

PINS = pinned_images()
SIGNERS = verify.load_signers()


def test_the_finder_sees_every_place_an_image_is_named() -> None:
    files = {f for refs in PINS.values() for f in refs}
    for expected in ("docker-compose.yml", ".github/workflows/ci.yml", "core/reports/pdf.py",
                     "helm/bulwark/values.yaml", "helm/bulwark/templates/_helpers.tpl", "docker/trivy/Dockerfile"):  # fmt: skip
        assert expected in files, expected
    # a reference split over two Python string literals is still one reference
    assert any(r.startswith("mcr.microsoft.com/playwright:") for r in PINS)
    assert (
        repository("ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:" + "0" * 64)
        == "ghcr.io/sigstore/cosign/cosign"
    )
    assert repository("alpine:3.20@sha256:" + "0" * 64) == "alpine"


def test_every_pinned_image_is_signed_by_someone_known_or_recorded_as_unsigned() -> None:
    to_verify, unknown = verify.plan(PINS, SIGNERS)
    assert (
        unknown == []
    ), "add these to docker/image-signers.json, signed (with the signer) or unsigned (with why)"
    assert {repository(r) for r in to_verify} == set(SIGNERS["signed"])


def test_the_lists_name_only_images_that_are_pinned() -> None:
    pinned = {repository(r) for r in PINS}
    listed = set(SIGNERS["signed"]) | set(SIGNERS["unsigned"])
    assert listed - pinned == set(), "stale entries in docker/image-signers.json"
    assert set(SIGNERS["signed"]).isdisjoint(SIGNERS["unsigned"])
    assert all(len(why) > 20 for why in SIGNERS["unsigned"].values())


# What each publisher's certificate said on 2026-10-15 (cosign verify), for the patterns to match.
SEEN = {
    "aquasec/trivy": "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.55.2",
    "openbao/openbao": "https://github.com/openbao/openbao/.github/workflows/release.yml@refs/tags/v2.1.1",
}


@pytest.mark.parametrize("repo", sorted(SIGNERS["signed"]))
def test_each_signer_is_one_exact_identity_or_an_anchored_pattern(repo: str) -> None:
    s = SIGNERS["signed"][repo]
    assert s["issuer"].startswith("https://")
    assert ("identity" in s) != ("identity_regexp" in s)
    if "identity_regexp" in s:
        pattern = s["identity_regexp"]
        assert pattern.startswith("^") and pattern.endswith(
            "$"
        ), "an unanchored pattern accepts other workflows"
        assert re.match(pattern, SEEN[repo])
        assert not re.match(
            pattern, SEEN[repo].replace("@refs/tags/", "@refs/heads/")
        )  # a branch build is not a release
        assert not re.match(pattern, SEEN[repo].replace("github.com/", "github.com/evil-"))


def test_cosign_is_asked_for_the_recorded_signer() -> None:
    ref = "aquasec/trivy:0.55.2@sha256:" + "a" * 64
    args = verify.cosign_args(ref, SIGNERS["signed"]["aquasec/trivy"])
    assert args[0] == "verify" and args[-1] == ref
    assert (
        args[args.index("--certificate-identity-regexp") + 1]
        == SIGNERS["signed"]["aquasec/trivy"]["identity_regexp"]
    )
    assert (
        args[args.index("--certificate-oidc-issuer") + 1]
        == "https://token.actions.githubusercontent.com"
    )
    exact = verify.cosign_args(ref, {"identity": "a@b", "issuer": "https://accounts.google.com"})
    assert exact[exact.index("--certificate-identity") + 1] == "a@b"


# Scanners built from their publisher's signed release files rather than an unsigned image.
BUILT_FROM_SIGNED_RELEASES = {
    "grype": [
        "cosign verify-blob",
        "https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main",
        "sha256sum -c",
    ],
    "syft": [
        "cosign verify-blob",
        "https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main",
        "sha256sum -c",
    ],
    "opengrep": [
        "cosign verify-blob",
        "https://github.com/opengrep/opengrep/.github/workflows/rolling-release.yml@refs/heads/main",
        "sha256sum -c",
    ],
    "osv-scanner": [
        "slsa-verifier verify-artifact",
        "--source-uri github.com/google/osv-scanner",
        '--source-tag "v${OSV_VERSION}"',
    ],
    "checkov": [
        "pypi-attestations verify pypi --repository https://github.com/bridgecrewio/checkov"
    ],
}


@pytest.mark.parametrize("tool", sorted(BUILT_FROM_SIGNED_RELEASES))
def test_scanners_are_built_from_signature_checked_releases(tool: str) -> None:
    text = (ROOT / "docker" / tool / "Dockerfile").read_text()
    flat = re.sub(r"\\\n\s*", "", text)  # join continuation lines
    for needle in BUILT_FROM_SIGNED_RELEASES[tool]:
        assert needle in flat or needle.replace("./", "") in flat, f"{tool}: {needle}"
    assert "--certificate-identity-regexp" not in flat  # release files name one exact workflow
    for upstream in ("anchore/grype", "anchore/syft", "ghcr.io/google/osv-scanner"):
        assert f"FROM {upstream}" not in text  # not the unsigned upstream image any more


# Scanners whose publishers sign nothing, built from Go source checked against Go's checksum database.
BUILT_FROM_GO_SOURCE = {
    "gitleaks": "github.com/zricethezav/gitleaks/v8@v${GITLEAKS_VERSION}",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v${NUCLEI_VERSION}",
    "dockle": "github.com/goodwithtech/dockle/cmd/dockle@v${DOCKLE_VERSION}",
}


@pytest.mark.parametrize("tool", sorted(BUILT_FROM_GO_SOURCE))
def test_scanners_nobody_signs_are_built_from_source_checked_against_the_go_checksum_db(
    tool: str,
) -> None:
    """`go install mod@version` checks every module's hash against sum.golang.org unless told not
    to; these settings make sure nothing tells it not to."""
    text = (ROOT / "docker" / tool / "Dockerfile").read_text()
    flat = re.sub(r"\\\n\s*", "", text)
    assert "go install" in flat and BUILT_FROM_GO_SOURCE[tool] in flat, tool
    env = re.search(r"(?m)^ENV (.*)$", text)
    assert env, tool
    settings = dict(kv.split("=", 1) for kv in env.group(1).split())
    assert settings["GOSUMDB"] == "sum.golang.org"
    assert settings["GOPROXY"] == "https://proxy.golang.org"
    assert settings["GONOSUMDB"] == settings["GOPRIVATE"] == settings["GOINSECURE"] == ""
    assert "-insecure" not in settings.get("GOFLAGS", "")
    for upstream in ("zricethezav/gitleaks", "projectdiscovery/nuclei", "goodwithtech/dockle"):
        assert f"FROM {upstream}" not in text
