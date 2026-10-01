"""core.dast.proxy's request parsing and allow-list enforcement (Week 49 task 2, plan §22.4).

Live, real-network/real-socket end-to-end proxying (a real CONNECT tunnel to a real allowed host, a
real blocked attempt reported) is in tests/integration/test_dast_proxy_live.py -- this file covers
what's mechanically checkable without starting a server: request-line parsing and the allow-list
decision itself.
"""

from __future__ import annotations

from core.dast.proxy import AllowListProxy, parse_request_line


def test_parses_a_connect_request() -> None:
    target = parse_request_line(b"CONNECT example.com:443 HTTP/1.1")
    assert target is not None
    assert (target.host, target.port, target.is_connect) == ("example.com", 443, True)


def test_connect_host_is_lowercased() -> None:
    target = parse_request_line(b"CONNECT Example.COM:443 HTTP/1.1")
    assert target is not None
    assert target.host == "example.com"


def test_parses_an_absolute_form_http_request() -> None:
    target = parse_request_line(b"GET http://example.com/path?x=1 HTTP/1.1")
    assert target is not None
    assert (target.host, target.port, target.is_connect) == ("example.com", 80, False)


def test_absolute_form_https_defaults_to_port_443() -> None:
    target = parse_request_line(b"GET https://example.com/ HTTP/1.1")
    assert target is not None
    assert target.port == 443


def test_rejects_origin_form_requests_with_no_host() -> None:
    """An origin-form request ("GET /path HTTP/1.1") carries no host at all in the request line --
    refusing it outright is deliberate: a proxy that fell back to a Host header to guess the target
    would be enforcing against a value an attacker-controlled client fully chooses, not the value it
    actually parsed and checked."""
    assert parse_request_line(b"GET /path HTTP/1.1") is None


def test_rejects_malformed_lines() -> None:
    assert parse_request_line(b"not a request line") is None
    assert parse_request_line(b"") is None
    assert parse_request_line(b"CONNECT missing-port HTTP/1.1") is None
    assert parse_request_line(b"CONNECT host:notaport HTTP/1.1") is None


def test_rejects_non_ascii_bytes() -> None:
    assert parse_request_line("CONNECT \xff\xfe:443 HTTP/1.1".encode("latin-1")) is None


def test_allow_list_proxy_matches_case_insensitively() -> None:
    proxy = AllowListProxy(frozenset({"Example.com"}))
    assert proxy.is_allowed("example.com") is True
    assert proxy.is_allowed("EXAMPLE.COM") is True


def test_allow_list_proxy_does_not_match_subdomains() -> None:
    proxy = AllowListProxy(frozenset({"example.com"}))
    assert proxy.is_allowed("evil.example.com") is False
    assert proxy.is_allowed("notexample.com") is False


def test_allow_list_proxy_calls_on_blocked_for_a_disallowed_host() -> None:
    calls = []
    proxy = AllowListProxy(
        frozenset({"example.com"}), on_blocked=lambda h, p, c: calls.append((h, p, c))
    )
    assert proxy.is_allowed("evil.com") is False
    # is_allowed alone never reports -- only the request-handling path does; verified in the live
    # integration test, which exercises handle() against a real socket.
    assert calls == []
