"""core.plugins.signing with a mocked subprocess (fast, deterministic, no real network or Docker).

The real cosign-calling path, against real Sigstore infrastructure and a real public signed image,
is proven in tests/integration/test_plugin_signing_live.py -- this file only verifies the argv built,
the JSON parsing of cosign's real output shape (copied verbatim from a live run, see that shape's own
comment below), and that every failure mode raises PluginSignatureError rather than silently passing.
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from core.plugins.signing import (
    PluginSignatureError,
    VerifiedSignature,
    pinned_reference,
    verify_plugin_image,
)

IMAGE = "ghcr.io/example/scanner:1.0.0"
IDENTITY = "https://github.com/example/scanner/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"

# A trimmed, real shape (fields that matter to _parse_verify_output), taken from a genuine
# `cosign verify -o json` run against ghcr.io/stefanprodan/podinfo:6.4.0.
_REAL_SHAPED_STDOUT = (
    b'[{"critical":{"identity":{"docker-reference":"ghcr.io/example/scanner"},'
    b'"image":{"docker-manifest-digest":"sha256:' + b"a" * 64 + b'"},'
    b'"type":"cosign container image signature"},'
    b'"optional":{"Bundle":{"Payload":{"logIndex":25064476}},'
    b'"Issuer":"https://token.actions.githubusercontent.com",'
    b'"Subject":"https://github.com/example/scanner/.github/workflows/release.yml@refs/heads/main"}}]'
)


def _fake_run(returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> Any:
    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)

    return run


def test_verify_plugin_image_returns_signatures_on_real_shaped_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "run", _fake_run(0, _REAL_SHAPED_STDOUT))
    sigs = verify_plugin_image(IMAGE, IDENTITY, ISSUER)
    assert len(sigs) == 1
    assert sigs[0].certificate_identity == IDENTITY
    assert sigs[0].certificate_oidc_issuer == ISSUER
    assert sigs[0].log_index == 25064476
    assert sigs[0].image_digest == "sha256:" + "a" * 64  # what was signed, from the payload


def test_verify_plugin_image_passes_the_declared_identity_and_issuer_as_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, _REAL_SHAPED_STDOUT, b"")

    monkeypatch.setattr(subprocess, "run", run)
    verify_plugin_image(IMAGE, IDENTITY, ISSUER)
    argv = captured["argv"]
    assert f"--certificate-identity={IDENTITY}" in argv
    assert f"--certificate-oidc-issuer={ISSUER}" in argv
    assert argv[-1] == IMAGE
    assert "--network=none" not in argv  # keyless verify genuinely needs the network


def test_verify_plugin_image_raises_on_cosign_nonzero_exit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", _fake_run(1, b"", b"Error: no matching signatures: ...\n")
    )
    with pytest.raises(PluginSignatureError, match="no matching signatures"):
        verify_plugin_image(IMAGE, IDENTITY, ISSUER)


def test_verify_plugin_image_raises_on_empty_signature_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exit 0 with an empty array would mean cosign itself regressed -- treated as a failure, never
    silently "verified"."""
    monkeypatch.setattr(subprocess, "run", _fake_run(0, b"[]"))
    with pytest.raises(PluginSignatureError, match="verified no signatures"):
        verify_plugin_image(IMAGE, IDENTITY, ISSUER)


def test_verify_plugin_image_raises_on_unparseable_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", _fake_run(0, b"not json"))
    with pytest.raises(PluginSignatureError, match="unparseable"):
        verify_plugin_image(IMAGE, IDENTITY, ISSUER)


def test_verify_plugin_image_raises_when_docker_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **kw: Any) -> None:
        raise FileNotFoundError("docker")

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(PluginSignatureError, match="docker is not installed"):
        verify_plugin_image(IMAGE, IDENTITY, ISSUER)


def test_verify_plugin_image_raises_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(argv: list[str], **kw: Any) -> None:
        raise subprocess.TimeoutExpired(argv, 60)

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(PluginSignatureError, match="timed out"):
        verify_plugin_image(IMAGE, IDENTITY, ISSUER)


@pytest.mark.parametrize("bad_image", ["", "has a space", "weird\nnewline", "x" * 600])
def test_verify_plugin_image_rejects_an_implausible_image_reference(bad_image: str) -> None:
    with pytest.raises(PluginSignatureError, match="not a plausible image reference"):
        verify_plugin_image(bad_image, IDENTITY, ISSUER)


D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64


def _sig(digest: str) -> VerifiedSignature:
    return VerifiedSignature(IDENTITY, ISSUER, 1, image_digest=digest)


@pytest.mark.parametrize(
    ("image", "pinned"),
    [
        ("ghcr.io/example/scanner:1.0.0", f"ghcr.io/example/scanner:1.0.0@{D1}"),
        ("ghcr.io/example/scanner", f"ghcr.io/example/scanner@{D1}"),
        ("localhost:5000/scanner:1", f"localhost:5000/scanner:1@{D1}"),
        (f"ghcr.io/example/scanner@{D1}", f"ghcr.io/example/scanner@{D1}"),
    ],
)
def test_a_plugin_runs_by_the_digest_its_signature_covers(image: str, pinned: str) -> None:
    assert pinned_reference(image, [_sig(D1), _sig(D1)]) == pinned


@pytest.mark.parametrize(
    ("image", "sigs", "why"),
    [
        (IMAGE, [], "name 0 image digests"),
        (IMAGE, [_sig(D1), _sig(D2)], "name 2 image digests"),
        (IMAGE, [_sig("")], "names no image digest"),
        (IMAGE, [_sig("sha256:aaaa")], "names no image digest"),
        (f"ghcr.io/example/scanner@{D2}", [_sig(D1)], "is not the one named"),
    ],
)
def test_no_single_signed_digest_means_the_plugin_does_not_run(
    image: str, sigs: list[VerifiedSignature], why: str
) -> None:
    with pytest.raises(PluginSignatureError, match=why):
        pinned_reference(image, sigs)
