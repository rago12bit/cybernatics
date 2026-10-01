"""Real sockets, a real local HTTP server, and a real external host through a real running instance
of `core.dast.proxy` -- not mocks (Week 49 task 2, plan §22.4). The unit tests in
tests/unit/test_dast_proxy.py cover parsing/allow-list logic in isolation; this file proves the
actual asyncio server really tunnels an allowed host's traffic and really refuses (and reports) a
disallowed one.

No Docker/Linux dependency -- `core.dast.proxy` is pure asyncio and runs on any platform, unlike
`core.dast.egress`'s nftables half (see tests/unit/test_dast_egress.py's docstring for that split).
"""

from __future__ import annotations

import asyncio
import http.client
import socket
import ssl
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core.dast.proxy import AllowListProxy


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


class _RunningProxy:
    """Runs a real `AllowListProxy` on its own event loop in a background thread. Shutdown waits on
    an `asyncio.Event` rather than cancelling `serve_forever()` -- cancellation is the documented way
    to stop it, but it means the coroutine driving `run_until_complete` ends via CancelledError,
    which surfaces as an unhandled-exception-in-thread warning on every single test unless the
    cancellation is caught in exactly the right place. Waiting on an event that `close()` sets lets
    `_start()` return normally instead."""

    def __init__(self, allowed_hosts: frozenset[str]) -> None:
        self.blocked: list[tuple[str, int, bool]] = []
        self._proxy = AllowListProxy(allowed_hosts, on_blocked=self._on_blocked)
        self._loop = asyncio.new_event_loop()
        self._server: asyncio.base_events.Server | None = None
        self._stop_event: asyncio.Event | None = None
        ready = threading.Event()

        def run_loop() -> None:
            asyncio.set_event_loop(self._loop)

            async def _start() -> None:
                self._stop_event = asyncio.Event()
                self._server = await asyncio.start_server(self._proxy.handle, "127.0.0.1", 0)
                ready.set()
                async with self._server:
                    await self._stop_event.wait()

            self._loop.run_until_complete(_start())

        self._thread = threading.Thread(target=run_loop, daemon=True)
        self._thread.start()
        ready.wait(timeout=5)

    def _on_blocked(self, host: str, port: int, is_connect: bool) -> None:
        self.blocked.append((host, port, is_connect))

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    def close(self) -> None:
        assert self._stop_event is not None
        self._loop.call_soon_threadsafe(self._stop_event.set)
        self._thread.join(timeout=5)


@pytest.fixture
def running_proxy() -> Iterator[_RunningProxy]:
    proxy = _RunningProxy(frozenset({"127.0.0.1"}))
    yield proxy
    proxy.close()


def test_an_allowed_plain_http_request_is_relayed_to_the_real_local_target(
    local_target: int, running_proxy: _RunningProxy
) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", running_proxy.port, timeout=5)
    conn.request("GET", f"http://127.0.0.1:{local_target}/")
    resp = conn.getresponse()
    body = resp.read()
    assert resp.status == 200
    assert body == b"hello from the allowed target"
    assert running_proxy.blocked == []


def test_a_disallowed_host_is_refused_with_403_and_reported(running_proxy: _RunningProxy) -> None:
    conn = http.client.HTTPConnection("127.0.0.1", running_proxy.port, timeout=5)
    conn.request("GET", "http://evil.example.net/")
    resp = conn.getresponse()
    assert resp.status == 403
    assert running_proxy.blocked == [("evil.example.net", 80, False)]


def test_a_real_connect_tunnel_to_a_real_external_allowed_host_succeeds() -> None:
    """A genuine CONNECT tunnel over the real network to example.com:443, through a real running
    proxy instance -- proves the tunnel relay (not just the allow/deny decision) works against a
    real TLS handshake, not a fake target."""
    proxy = _RunningProxy(frozenset({"example.com"}))
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
        assert proxy.blocked == []
    finally:
        proxy.close()
