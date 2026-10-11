"""Real sockets, a real local HTTP server, and a real external host through a real running instance
of `core.dast.proxy` -- not mocks (Week 49 task 2, plan §22.4). The unit tests in
tests/unit/test_dast_proxy.py cover parsing/allow-list logic in isolation; this file proves the
actual asyncio server really tunnels an allowed host's traffic and really refuses (and reports) a
disallowed one.

No Docker/Linux dependency -- `core.dast.proxy` is pure asyncio and runs on any platform, unlike
`core.dast.egress`'s nftables half (see tests/unit/test_dast_egress.py's docstring for that split).
"""

from __future__ import annotations

import http.client
import socket
import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.dast.proxy import BackgroundProxy


class _EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"hello from the allowed target")

    def log_message(
        self, format: str, *args: object
    ) -> None:  # noqa: A002 - stdlib's own signature
        pass  # keep test output quiet


@pytest.fixture
def local_target() -> Iterator[int]:
    server = HTTPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    thread.join(timeout=2)


class _Recorder:
    """A plain `on_blocked` callback that remembers what it was called with -- `BackgroundProxy`
    itself doesn't track blocked attempts, since a real campaign's own caller (the audit log) is
    what actually needs them, via whatever callback it passes in."""

    def __init__(self) -> None:
        self.blocked: list[tuple[str, int, bool]] = []

    def __call__(self, host: str, port: int, is_connect: bool) -> None:
        self.blocked.append((host, port, is_connect))


@pytest.fixture
def running_proxy() -> Iterator[tuple[BackgroundProxy, _Recorder]]:
    recorder = _Recorder()
    proxy = BackgroundProxy(frozenset({"127.0.0.1"}), on_blocked=recorder, bind_host="127.0.0.1")
    yield proxy, recorder
    proxy.close()


def test_an_allowed_plain_http_request_is_relayed_to_the_real_local_target(
    local_target: int, running_proxy: tuple[BackgroundProxy, _Recorder]
) -> None:
    proxy, recorder = running_proxy
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    conn.request("GET", f"http://127.0.0.1:{local_target}/")
    resp = conn.getresponse()
    body = resp.read()
    assert resp.status == 200
    assert body == b"hello from the allowed target"
    assert recorder.blocked == []


def test_a_disallowed_host_is_refused_with_403_and_reported(
    running_proxy: tuple[BackgroundProxy, _Recorder],
) -> None:
    proxy, recorder = running_proxy
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    conn.request("GET", "http://evil.example.net/")
    resp = conn.getresponse()
    assert resp.status == 403
    assert recorder.blocked == [("evil.example.net", 80, False)]


def test_a_real_connect_tunnel_to_a_real_external_allowed_host_succeeds() -> None:
    """A genuine CONNECT tunnel over the real network to example.com:443, through a real running
    proxy instance -- proves the tunnel relay (not just the allow/deny decision) works against a
    real TLS handshake, not a fake target."""
    recorder = _Recorder()
    proxy = BackgroundProxy(frozenset({"example.com"}), on_blocked=recorder, bind_host="127.0.0.1")
    try:
        sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
        sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        response = sock.recv(4096)
        assert b"200" in response.split(b"\r\n")[0]
        # Certificate validation is the real client's job, not this test's -- what's being proven
        # here is that the proxy relays raw bytes faithfully end to end, including a real TLS
        # handshake with a real server, not whether this sandbox's Python has a trust store wired up.
        ctx = ssl._create_unverified_context()
        tls_sock = ctx.wrap_socket(sock, server_hostname="example.com")
        tls_sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        body = b""
        while True:
            chunk = tls_sock.recv(65536)
            if not chunk:
                break
            body += chunk
        tls_sock.close()
        assert b"200" in body.split(b"\r\n")[0]
        assert recorder.blocked == []
    finally:
        proxy.close()


class _RecordingHandler(BaseHTTPRequestHandler):
    """An HTTP/1.1 target that keeps connections alive unless told otherwise, and remembers the
    request line and Host header of every request that reaches it."""

    protocol_version = "HTTP/1.1"
    seen: list[tuple[str, str]] = []

    def do_GET(self) -> None:
        type(self).seen.append((self.requestline, self.headers.get("Host", "")))
        body = f"you asked for {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


@pytest.fixture
def recording_target() -> Iterator[tuple[int, list[tuple[str, str]]]]:
    _RecordingHandler.seen = []
    server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1], _RecordingHandler.seen
    server.shutdown()
    thread.join(timeout=2)


def test_each_plain_request_reaches_the_target_in_origin_form_with_its_own_host(
    recording_target: tuple[int, list[tuple[str, str]]],
    running_proxy: tuple[BackgroundProxy, _Recorder],
) -> None:
    """A client that keeps its connection to the proxy alive. The proxy used to relay only the
    first request properly; the next went through raw, still `GET http://host/path`, which the
    target answered as a different page (Juice Shop: its app page, so Nuclei missed two findings).
    """
    port, seen = recording_target
    proxy, _ = running_proxy
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    bodies = []
    for path in ("/robots.txt", "/.well-known/security.txt"):
        conn.request("GET", f"http://127.0.0.1:{port}{path}")
        resp = conn.getresponse()
        assert resp.getheader("Connection") == "close"  # so the client opens a new connection
        bodies.append(resp.read())
    assert bodies == [b"you asked for /robots.txt", b"you asked for /.well-known/security.txt"]
    assert seen == [
        ("GET /robots.txt HTTP/1.1", f"127.0.0.1:{port}"),
        ("GET /.well-known/security.txt HTTP/1.1", f"127.0.0.1:{port}"),
    ]


def test_a_second_request_pipelined_on_one_connection_never_reaches_the_target(
    recording_target: tuple[int, list[tuple[str, str]]],
    running_proxy: tuple[BackgroundProxy, _Recorder],
) -> None:
    """Sent without waiting, the second request is not parsed or checked by the proxy; the target
    is told the first is the last on the connection, and acts on nothing after it."""
    port, seen = recording_target
    proxy, _ = running_proxy
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as sock:
        sock.sendall(
            f"GET http://127.0.0.1:{port}/first HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            f"GET http://evil.example.net/second HTTP/1.1\r\nHost: evil.example.net\r\n\r\n".encode()
        )
        received = b""
        while chunk := sock.recv(65536):
            received += chunk
    assert received.count(b"HTTP/1.1 200") == 1 and b"you asked for /first" in received
    assert seen == [("GET /first HTTP/1.1", f"127.0.0.1:{port}")]


def test_the_host_header_is_the_allowed_target_whatever_the_client_sends(
    recording_target: tuple[int, list[tuple[str, str]]],
    running_proxy: tuple[BackgroundProxy, _Recorder],
) -> None:
    """The connection goes to the allowed host either way, but a shared front end (a CDN, a
    virtual host) routes by Host header: one naming another site must not reach it."""
    port, seen = recording_target
    proxy, _ = running_proxy
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port, timeout=5)
    conn.putrequest("GET", f"http://127.0.0.1:{port}/x", skip_host=True)
    conn.putheader("Host", "evil.example.net")
    conn.endheaders()
    assert conn.getresponse().status == 200
    assert seen == [("GET /x HTTP/1.1", f"127.0.0.1:{port}")]
