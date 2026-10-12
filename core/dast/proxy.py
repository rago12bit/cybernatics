"""The scope-enforcing egress proxy every DAST campaign runner's traffic goes through (plan §22.4,
Week 49 task 2). A DAST scanner (ZAP, Nuclei, ...) is a program whose entire job is to make requests
to arbitrary hosts and paths it discovers by following links and guessing -- exactly the capability
that must never extend past the one host a campaign is scoped to. This proxy is the enforcement
point: it allows a CONNECT tunnel or a plain HTTP request only to a host on its allow-list (normally
exactly one -- the campaign's ownership-verified Asset), and refuses, and reports, everything else.

This alone is not the whole control (`core.dast.egress` is the other half): a scanner could simply
ignore its configured proxy and connect directly. `core.dast.egress.build_dast_egress_nft_ruleset`
denies all direct outbound 80/443 in the runner's network namespace except to this proxy itself,
the same sidecar-container mechanism `core.fixagent.egress` already uses for fix-verification
(Week 46) -- so going around the proxy isn't a policy violation, it's a dropped packet.

Pure asyncio, no Linux-specific syscalls: unlike `core.fixagent.egress`'s nftables half, this part
runs and was verified for real on this (macOS) dev machine, not just reviewed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass

DEFAULT_CONNECT_TIMEOUT = 10.0
_MAX_HEADER_BYTES = 16 * 1024  # a request line this large is already not a sane DAST tool request
_MAX_HEAD_BYTES = 64 * 1024  # a whole request or response head
# Set by the proxy itself on a plain HTTP request, or hop-by-hop and so not the target's business.
_REQUEST_HEADERS_REPLACED = frozenset({
    b"host", b"connection", b"proxy-connection", b"keep-alive", b"proxy-authorization", b"te",
    b"upgrade",
})  # fmt: skip
_START_TIMEOUT = 5.0
# The header is not decoration. Nuclei's raw-request client (projectdiscovery/rawhttp 0.1.91) reads
# the status line and then waits for 5 more bytes, to skip a repeated status line some devices send.
# A bare "200 ...\r\n\r\n" leaves 2, and the target says nothing until the client speaks, so every
# raw template hung there with no deadline: Nuclei through this proxy stalled at ~93% for good.
_CONNECT_ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: bulwark\r\n\r\n"


class ProxyError(Exception):
    pass


@dataclass(frozen=True)
class ProxyConfig:
    """Where a scanner adapter should point its own upstream-proxy option. `host` is the address a
    scanner's own container can reach the proxy at -- not necessarily the address the proxy is bound
    to -- so a bind of 0.0.0.0 pairs with a `host` of "host.docker.internal" for a sibling Docker
    container (Week 49b, plan §22.4 follow-up)."""

    host: str
    port: int


@dataclass(frozen=True)
class ProxyTarget:
    host: str
    port: int
    is_connect: bool  # CONNECT (HTTPS tunnel) vs. plain absolute-form HTTP
    request_line: bytes  # the original request line, re-sent verbatim for plain HTTP


def parse_request_line(line: bytes) -> ProxyTarget | None:
    """`line` is the first line of an HTTP request, with the trailing CRLF already stripped.
    Returns None for anything that isn't a CONNECT or an absolute-form HTTP request -- origin-form
    requests ("GET /path HTTP/1.1") have no host in the request line at all and are refused by the
    caller, the same as an explicitly disallowed host: a proxy that guessed the target from the Host
    header alone would be trivially confusable about what it was actually enforcing."""
    try:
        text = line.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = text.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return None
    method, target = parts[0], parts[1]
    if method == "CONNECT":
        host, _, port = target.partition(":")
        if not host or not port.isdigit():
            return None
        return ProxyTarget(host=host.lower(), port=int(port), is_connect=True, request_line=line)
    if "://" in target:
        from urllib.parse import urlsplit

        parsed = urlsplit(target)
        if not parsed.hostname:
            return None
        resolved_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return ProxyTarget(
            host=parsed.hostname.lower(), port=resolved_port, is_connect=False, request_line=line
        )
    return None


class JsonLinesReporter:
    """The default `on_blocked` callback: one JSON object per line to stdout. A sidecar proxy
    container normally has no database credentials of its own (the point of running it isolated
    from the scanned target is that a compromised scanner shouldn't inherit app secrets) -- the
    worker that started a campaign tails this container's logs and writes each blocked attempt to
    the real audit log (`core.persistence.repo.append_audit_entry`) from its own, already-
    authenticated process instead. A caller with direct DB access (a test, or a future in-process
    runner) can pass any other `Callable[[str, int, bool], None]` instead of this."""

    def __call__(self, host: str, port: int, is_connect: bool) -> None:
        print(
            json.dumps(
                {
                    "event": "dast_egress_blocked",
                    "host": host,
                    "port": port,
                    "protocol": "https" if is_connect else "http",
                }
            ),
            flush=True,
        )


OnBlocked = Callable[[str, int, bool], None]


class AllowListProxy:
    """`allowed_hosts` is normally exactly one hostname -- the campaign's verified Asset. Matching
    is exact, never a suffix/subdomain match: a DAST campaign scoped to `example.com` must not be
    able to silently also reach `evil.example.com` just because it shares a suffix."""

    def __init__(self, allowed_hosts: frozenset[str], *, on_blocked: OnBlocked | None = None):
        self._allowed_hosts = frozenset(h.lower() for h in allowed_hosts)
        self._on_blocked = on_blocked or JsonLinesReporter()

    def is_allowed(self, host: str) -> bool:
        return host.lower() in self._allowed_hosts

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=DEFAULT_CONNECT_TIMEOUT)
        except (TimeoutError, asyncio.TimeoutError):
            writer.close()
            return
        if not line or len(line) > _MAX_HEADER_BYTES:
            writer.close()
            return
        target = parse_request_line(line.rstrip(b"\r\n"))
        if target is None:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        if not self.is_allowed(target.host):
            self._on_blocked(target.host, target.port, target.is_connect)
            status = b"403 Forbidden"
            writer.write(f"HTTP/1.1 {status.decode()}\r\n\r\n".encode())
            await writer.drain()
            writer.close()
            return
        if target.is_connect:
            await self._relay_connect(reader, writer, target)
        else:
            await self._relay_plain_http(reader, writer, target)

    async def _relay_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: ProxyTarget
    ) -> None:
        # Drain the rest of the CONNECT request's headers (clients normally send none of substance,
        # but a blank-line-terminated head is still part of the protocol) before tunneling.
        while True:
            header_line = await reader.readline()
            if header_line in (b"\r\n", b""):
                break
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout=DEFAULT_CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError, TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        writer.write(_CONNECT_ESTABLISHED)
        await writer.drain()
        await asyncio.gather(
            _pump(reader, upstream_writer), _pump(upstream_reader, writer), return_exceptions=True
        )

    async def _relay_plain_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, target: ProxyTarget
    ) -> None:
        """One request per connection. The request goes upstream in origin form, with the Host
        header set to the allowed target (whatever the client sent) and `Connection: close`; the
        response comes back marked `Connection: close` too, so a client sends its next request on
        a new connection, where it is parsed and checked like the first.

        Before, the connection became a raw pipe after the first request line: a client reusing it
        (HTTP keep-alive) had its next request reach the target unrewritten (`GET http://host/path`,
        which Juice Shop answered with its app page, so Nuclei missed two findings) and unchecked
        against the allow-list. The TCP connection was pinned to the allowed host either way, but a
        Host header naming another site can be routed to it by a shared front end (a CDN, a virtual
        host) -- a site ownership verification never covered."""
        from urllib.parse import urlsplit

        parsed = urlsplit(target.request_line.decode("ascii").split(" ")[1])
        origin_form_path = parsed.path or "/"
        if parsed.query:
            origin_form_path += f"?{parsed.query}"
        method = target.request_line.decode("ascii").split(" ")[0]
        head = [f"{method} {origin_form_path} HTTP/1.1\r\n".encode("ascii")]
        size = 0
        while True:
            header_line = await reader.readline()
            size += len(header_line)
            if size > _MAX_HEAD_BYTES:
                writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                await writer.drain()
                writer.close()
                return
            if header_line in (b"\r\n", b"\n", b""):
                break
            if header_line.split(b":", 1)[0].strip().lower() not in _REQUEST_HEADERS_REPLACED:
                head.append(header_line)
        host = f"[{target.host}]" if ":" in target.host else target.host
        default_port = 443 if parsed.scheme == "https" else 80
        authority = host if target.port == default_port else f"{host}:{target.port}"
        head.append(f"Host: {authority}\r\nConnection: close\r\n\r\n".encode("ascii"))
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(target.host, target.port), timeout=DEFAULT_CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError, TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        upstream_writer.write(b"".join(head))
        await upstream_writer.drain()
        # The rest of what the client sends is this request's body. A further request on the same
        # connection would ride along too, but the target must not act on anything after a request
        # marked `Connection: close` (RFC 9112 section 9.6).
        await asyncio.gather(
            _pump(reader, upstream_writer),
            _relay_response(upstream_reader, writer),
            return_exceptions=True,
        )


async def _relay_response(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """The response head with `Connection: close` in place of the target's own keep-alive headers,
    then the rest as it comes."""
    head: list[bytes] = []
    size = 0
    try:
        while True:
            line = await reader.readline()
            size += len(line)
            if not line or size > _MAX_HEAD_BYTES:
                writer.write(b"".join(head))
                break
            if line in (b"\r\n", b"\n"):
                writer.write(b"".join(head) + b"Connection: close\r\n" + line)
                break
            if head and line.split(b":", 1)[0].strip().lower() in (b"connection", b"keep-alive"):
                continue
            head.append(line)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        writer.close()
        return
    await _pump(reader, writer)


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        writer.close()


class BackgroundProxy:
    """Runs a real `AllowListProxy` on its own event loop in a background thread, for a synchronous
    caller (a DAST campaign job) that needs proxied traffic to flow while it makes blocking
    `subprocess.run` calls to launch scanner containers (Week 49b, plan §22.4 follow-up). Binds to
    `bind_host` (0.0.0.0 by default, so a sibling Docker container can reach it) on an OS-assigned
    port; use as a context manager so the server is always torn down, including when a scanner
    adapter raises.

    Shutdown waits on an `asyncio.Event` that `close()` sets, rather than cancelling
    `serve_forever()` -- the same choice `tests/integration/test_dast_proxy_live.py` made, for the
    same reason: cancellation makes the thread's driving coroutine end via `CancelledError`, which
    surfaces as an unhandled-exception-in-thread warning on every single campaign otherwise."""

    def __init__(
        self,
        allowed_hosts: frozenset[str],
        *,
        on_blocked: OnBlocked | None = None,
        bind_host: str = "0.0.0.0",
    ) -> None:
        self._proxy = AllowListProxy(allowed_hosts, on_blocked=on_blocked)
        self._loop = asyncio.new_event_loop()
        self._server: asyncio.base_events.Server | None = None
        self._stop_event: asyncio.Event | None = None
        ready = threading.Event()
        start_error: list[BaseException] = []

        def run_loop() -> None:
            asyncio.set_event_loop(self._loop)

            async def _start() -> None:
                self._stop_event = asyncio.Event()
                try:
                    self._server = await asyncio.start_server(self._proxy.handle, bind_host, 0)
                except OSError as exc:
                    start_error.append(exc)
                    return
                finally:
                    ready.set()
                try:
                    await self._stop_event.wait()
                finally:
                    # Stop accepting, but wait for the server to close only once the relays below
                    # are gone: from Python 3.12.1, `wait_closed()` (and so `async with server`)
                    # waits for every open connection, and a keep-alive relay never ends by itself.
                    self._server.close()
                # A scanner's own connection to the proxy and `close()` being called (once the
                # campaign's `subprocess.run` for that scanner returns) can land in the same
                # instant -- draining whatever relay tasks are still mid-flight here, instead of
                # letting the thread exit out from under them, is what turns an occasional "Task
                # was destroyed but it is pending" / "Event loop is closed" warning on an otherwise
                # passing campaign into a clean shutdown every time.
                pending = [
                    t for t in asyncio.all_tasks(self._loop) if t is not asyncio.current_task()
                ]
                if pending:
                    _, still = await asyncio.wait(pending, timeout=2.0)
                    # A relay a scanner kept open (HTTP keep-alive) never finishes by itself: cancel
                    # it and let it close its sockets now, while the loop can still run that.
                    for task in still:
                        task.cancel()
                    await asyncio.gather(*still, return_exceptions=True)
                await self._server.wait_closed()

            try:
                self._loop.run_until_complete(_start())
            finally:
                self._loop.close()

        self._thread = threading.Thread(target=run_loop, daemon=True)
        self._thread.start()
        if not ready.wait(timeout=_START_TIMEOUT) or start_error:
            self.close()
            detail = f": {start_error[0]}" if start_error else " (timed out)"
            raise ProxyError(f"background proxy failed to start{detail}")

    @property
    def port(self) -> int:
        assert self._server is not None
        return int(self._server.sockets[0].getsockname()[1])

    def __enter__(self) -> BackgroundProxy:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        if self._stop_event is not None:
            try:
                self._loop.call_soon_threadsafe(self._stop_event.set)
            except RuntimeError:
                pass  # the loop already stopped and closed itself (the failed-start path)
        self._thread.join(timeout=_START_TIMEOUT)


async def serve(allowed_hosts: frozenset[str], *, host: str = "0.0.0.0", port: int = 8080) -> None:
    proxy = AllowListProxy(allowed_hosts)
    server = await asyncio.start_server(proxy.handle, host, port)
    async with server:
        await server.serve_forever()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow", action="append", required=True, help="Allowed host (repeatable)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    try:
        asyncio.run(serve(frozenset(args.allow), host=args.host, port=args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":  # pragma: no cover - exercised via a real subprocess in tests, not here
    main(sys.argv[1:])
