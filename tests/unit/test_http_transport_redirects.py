"""core.ci.github.http_transport follows a redirect only within its own scheme, host and port
(2026-10-17 audit). urllib follows any redirect and keeps the Authorization header, so a Jira or
GitHub address that answered 302 to another host was sent the credentials, and one that answered
with an internal address was fetched from inside the network."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core.ci.github import http_transport

seen: list[tuple[int, str, str | None]] = []
REDIRECTS: dict[str, str] = {}  # path -> where it redirects


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server's name
        port = self.server.server_address[1]
        seen.append((port, self.path, self.headers.get("Authorization")))
        redirect = REDIRECTS.get(self.path)
        if redirect is not None:
            self.send_response(302)
            self.send_header("Location", redirect)
            self.end_headers()
            return
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def servers() -> Iterator[tuple[int, int]]:
    started = [ThreadingHTTPServer(("127.0.0.1", 0), _Handler) for _ in range(2)]
    for srv in started:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    seen.clear()
    REDIRECTS.clear()
    yield started[0].server_address[1], started[1].server_address[1]
    for srv in started:
        srv.shutdown()
        srv.server_close()


def test_a_redirect_on_the_same_host_is_followed(servers: tuple[int, int]) -> None:
    a, _ = servers
    REDIRECTS["/moved"] = "/landed"
    status, data = http_transport("GET", f"http://127.0.0.1:{a}/moved", {}, None)
    assert (status, data) == (200, {"path": "/landed"})


def test_a_redirect_to_another_host_is_refused_and_gets_no_credentials(
    servers: tuple[int, int],
) -> None:
    a, b = servers
    REDIRECTS["/moved"] = f"http://127.0.0.1:{b}/steal"
    status, data = http_transport(
        "GET", f"http://127.0.0.1:{a}/moved", {"Authorization": "Basic c2VjcmV0"}, None
    )
    assert status == 302 and data is None
    assert [port for port, _, _ in seen] == [a]  # the other server was never asked
