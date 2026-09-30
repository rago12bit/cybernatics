"""core.secrets.openbao against a REAL OpenBao dev-mode container, not mocked HTTP (Week 47 task 1,
plan §22.2). Manages its own container (start, wait for readiness, tear down) rather than requiring
an already-running instance, since a fixed `openbao/openbao:2.1` dev-mode boot is cheap and fast.
Skips everywhere Docker isn't available, the same way the scanner integration tests do.
"""

from __future__ import annotations

import shutil
import subprocess
import time
import uuid
from collections.abc import Iterator

import pytest

from core.secrets import envelope
from core.secrets.openbao import OpenBaoClient, OpenBaoError

_IMAGE = "openbao/openbao:2.1"
_TOKEN = "test-root-token"


def _docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _wait_until_ready(client: OpenBaoClient, timeout: float = 20.0) -> None:
    """Retries on ANY exception, not just OpenBaoError: a container mid-startup can drop the
    connection outright (http.client.RemoteDisconnected), which urllib does not always wrap as a
    urllib.error.URLError -- this loop's only job is "keep trying until the deadline," so a broad
    except is the right tool here, unlike in production code."""
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            client.ensure_transit_engine_enabled()
            return
        except Exception as exc:  # noqa: BLE001 - see docstring
            last_error = exc
            time.sleep(0.3)
    raise TimeoutError(f"OpenBao never became ready: {last_error}")


@pytest.fixture
def openbao_client() -> Iterator[OpenBaoClient]:
    name = f"bulwark-openbao-test-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        [
            "docker", "run", "-d", "--name", name, "-p", "127.0.0.1::8200",
            "-e", f"BAO_DEV_ROOT_TOKEN_ID={_TOKEN}", _IMAGE,
        ],  # fmt: skip
        check=True,
        capture_output=True,
    )
    try:
        port_out = subprocess.run(
            ["docker", "port", name, "8200/tcp"], check=True, capture_output=True, text=True
        ).stdout.strip()
        port = port_out.rsplit(":", 1)[-1]
        client = OpenBaoClient(addr=f"http://127.0.0.1:{port}", token=_TOKEN)
        _wait_until_ready(client)
        yield client
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_generate_and_unwrap_data_key_round_trips(openbao_client: OpenBaoClient) -> None:
    openbao_client.ensure_org_key("org-a")
    dk = openbao_client.generate_data_key("org-a")
    assert len(dk.plaintext) == 32
    unwrapped = openbao_client.unwrap_data_key("org-a", dk.wrapped)
    assert unwrapped == dk.plaintext


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_ensure_org_key_is_idempotent(openbao_client: OpenBaoClient) -> None:
    openbao_client.ensure_org_key("org-b")
    openbao_client.ensure_org_key("org-b")  # must not raise the second time
    openbao_client.generate_data_key("org-b")  # proves the key still works


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_a_wrapped_key_cannot_be_unwrapped_under_a_different_org(
    openbao_client: OpenBaoClient,
) -> None:
    openbao_client.ensure_org_key("org-c")
    openbao_client.ensure_org_key("org-d")
    dk = openbao_client.generate_data_key("org-c")
    with pytest.raises(OpenBaoError):
        openbao_client.unwrap_data_key("org-d", dk.wrapped)


@pytest.mark.skipif(not _docker_ready(), reason="docker not available")
def test_full_envelope_encryption_round_trip_against_a_real_key(
    openbao_client: OpenBaoClient,
) -> None:
    """The exact pattern core.persistence.storage.EncryptingObjectStore uses: mint a data key from
    a real KEK, encrypt with it locally, discard the plaintext, unwrap the SAME wrapped key later,
    decrypt."""
    openbao_client.ensure_org_key("org-e")
    dk = openbao_client.generate_data_key("org-e")
    blob = envelope.encrypt(dk.plaintext, b"raw scanner output", associated_data=b"scans/1/raw/x")
    wrapped = dk.wrapped
    del dk  # the plaintext key is never held longer than one call needs it

    recovered_key = openbao_client.unwrap_data_key("org-e", wrapped)
    plaintext = envelope.decrypt(recovered_key, blob, associated_data=b"scans/1/raw/x")
    assert plaintext == b"raw scanner output"

    with pytest.raises(envelope.DecryptionError):
        envelope.decrypt(recovered_key, blob, associated_data=b"scans/OTHER/raw/x")
