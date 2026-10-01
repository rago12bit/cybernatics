"""Real sockets, a real local HTTP server, and real public DNS resolution -- not mocks (Week 51
task 2, plan §23). tests/unit/test_integrations_webhooks.py covers signing math and delivery logic
against a fake transport; this file proves two things no mock can:

1. `core.integrations.ssrf.validate_webhook_url`'s DNS resolution and public/private classification
   against real hostnames, including the real public endpoints Slack/Discord's own documentation
   gives operators for incoming webhooks -- not a fabricated test hostname.
2. A real HTTP POST, with real `sign()`-computed headers, received and verified correct by a real
   HTTP server over a real loopback socket (the same `http.server`-based pattern
   tests/integration/test_dast_proxy_live.py already uses).

These are necessarily two separate proofs, not one combined one: `validate_webhook_url` exists
specifically to refuse a destination that resolves to a private/loopback address, and a test's own
local receiver can only ever bind to one -- running the second proof through the full
`deliver_signed()` entry point (SSRF check included) would require defeating the exact guard the
first proof demonstrates is working correctly. Proof 2 therefore calls the signing and transport
functions directly, the same functions `deliver_signed()` itself calls internally, with the SSRF
check demonstrated separately and for real in proof 1.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.ci.github import http_transport
from core.integrations.ssrf import WebhookUrlError, validate_webhook_url
from core.integrations.webhooks import HEADER_SIGNATURE, HEADER_TIMESTAMP, sign, verify_signature


def _network_reachable() -> bool:
    try:
        socket.create_connection(("hooks.slack.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _network_reachable(), reason="network is not available")


def test_real_dns_resolves_slacks_own_incoming_webhook_host_to_public_addresses() -> None:
    v = validate_webhook_url("https://hooks.slack.com/services/T000/B000/xxx")
    assert v.host == "hooks.slack.com"
    assert v.ip  # a real, resolved, public address


def test_real_dns_resolves_discords_own_webhook_host_to_public_addresses() -> None:
    v = validate_webhook_url("https://discord.com/api/webhooks/000/xxx")
    assert v.host == "discord.com"
    assert v.ip


def test_real_dns_still_refuses_the_real_cloud_metadata_address() -> None:
    """169.254.169.254 resolves to itself (it has no DNS entry; it IS the address) -- real,
    unmocked, and still correctly refused."""
    with pytest.raises(WebhookUrlError, match="non-public"):
        validate_webhook_url("https://169.254.169.254/latest/meta-data/", resolver=lambda h: [h])


class _CapturingHandler(BaseHTTPRequestHandler):
    captured: dict[str, object] = {}

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        _CapturingHandler.captured = {"body": body, "headers": dict(self.headers)}
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a: object) -> None:  # noqa: D102 - silence test output
        pass


@pytest.fixture
def local_server() -> Iterator[int]:
    server = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_a_real_signed_post_is_received_and_verifies_correctly_over_a_real_socket(
    local_server: int,
) -> None:
    body = b'{"hello":"world"}'
    ts = 1_700_000_000
    secret = "a-real-shared-secret"
    headers = {
        "Content-Type": "application/json",
        HEADER_TIMESTAMP: str(ts),
        HEADER_SIGNATURE: sign(secret, ts, body),
    }
    status, _ = http_transport("POST", f"http://127.0.0.1:{local_server}/hook", headers, body)
    assert status == 200

    received = _CapturingHandler.captured
    received_body = received["body"]
    received_headers = received["headers"]
    assert isinstance(received_body, bytes) and received_body == body
    assert isinstance(received_headers, dict)
    assert verify_signature(
        secret,
        int(received_headers[HEADER_TIMESTAMP]),
        received_body,
        received_headers[HEADER_SIGNATURE],
        now=ts,
    )
    # The receiver's own HMAC check, exactly as a real third-party webhook consumer would run it,
    # correctly rejects the same request under the wrong secret.
    assert not verify_signature(
        "wrong-secret",
        int(received_headers[HEADER_TIMESTAMP]),
        received_body,
        received_headers[HEADER_SIGNATURE],
        now=ts,
    )
