"""Real cosign, real network, real Sigstore Fulcio/Rekor infrastructure, a real public image --
not mocks (Week 51 task 1, plan §23). The unit tests in tests/unit/test_plugin_signing.py cover
argv construction and JSON-parsing logic against a mocked subprocess; this file proves the actual
keyless-verify code path genuinely talks to Sigstore and genuinely fails closed.

Target: ghcr.io/stefanprodan/podinfo:6.4.0 -- a well-known public image the Sigstore community
itself uses in cosign's own documentation as a keyless-verify demo, specifically because it is
real, small, stable (pinned to an exact tag, never republished), and will keep carrying this exact
signature indefinitely. This is the same target core.plugins.signing's own module docstring and
examples/bulwark-plugin-demo/README.md reference.

Skips when Docker isn't available or the network can't reach Sigstore's infrastructure -- the same
"skip, don't fail, when the environment can't support it" convention as
tests/integration/test_dast_adapters_live.py.
"""

from __future__ import annotations

import shutil
import socket
import subprocess

import pytest

from core.plugins.signing import PluginSignatureError, verify_plugin_image

IMAGE = "ghcr.io/stefanprodan/podinfo:6.4.0"
REAL_IDENTITY = (
    "https://github.com/stefanprodan/podinfo/.github/workflows/release.yml@refs/tags/6.4.0"
)
ISSUER = "https://token.actions.githubusercontent.com"


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except Exception:  # noqa: BLE001 - any failure means "not available"
        return False


def _sigstore_reachable() -> bool:
    try:
        socket.create_connection(("rekor.sigstore.dev", 443), timeout=5).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not (_docker_available() and _sigstore_reachable()),
    reason="docker and/or network access to Sigstore's infrastructure is not available",
)


def test_verify_plugin_image_succeeds_against_a_real_signed_public_image() -> None:
    sigs = verify_plugin_image(IMAGE, REAL_IDENTITY, ISSUER)
    assert len(sigs) >= 1
    assert sigs[0].certificate_identity == REAL_IDENTITY
    assert sigs[0].certificate_oidc_issuer == ISSUER
    assert sigs[0].log_index is not None and sigs[0].log_index > 0


def test_verify_plugin_image_fails_closed_for_the_wrong_declared_identity() -> None:
    """The image really is signed -- just not by the identity this call claims. A plugin lying
    about who published it must be refused exactly as loudly as one with no signature at all."""
    wrong_identity = (
        "https://github.com/some-attacker/evil-fork/.github/workflows/release.yml@refs/tags/6.4.0"
    )
    with pytest.raises(PluginSignatureError, match="no matching signatures"):
        verify_plugin_image(IMAGE, wrong_identity, ISSUER)


def test_verify_plugin_image_fails_closed_for_an_unsigned_image() -> None:
    """hello-world carries no Sigstore signature of any kind -- the baseline "not signed at all"
    case, as common as a wrong identity."""
    with pytest.raises(PluginSignatureError):
        verify_plugin_image("docker.io/library/hello-world:latest", REAL_IDENTITY, ISSUER)
