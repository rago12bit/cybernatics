"""Shared SSRF primitives (threat T5): resolve a hostname and reject anything that isn't globally
routable. Extracted out of `core/gitfetch.py` (Week 51 task 2, plan §23) so outbound webhook
delivery (`core/integrations/ssrf.py`) uses the literal same check git ingestion does, not a
parallel reimplementation that could quietly drift out of sync with it. `core/gitfetch.py` keeps
its own git-specific host allowlist and URL-path grammar; what's generic -- DNS resolution and the
public/private address check -- lives here, once.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable

Resolver = Callable[[str], list[str]]


def default_resolver(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return sorted({str(i[4][0]) for i in infos})


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%")[0])
    if isinstance(addr, ipaddress.IPv6Address):
        # Unwrap addresses that embed an IPv4 target, a classic SSRF filter bypass.
        embedded = addr.ipv4_mapped or addr.sixtofour or (addr.teredo[1] if addr.teredo else None)
        if embedded is not None:
            return is_public_ip(str(embedded))
        if addr in ipaddress.ip_network("64:ff9b::/96"):  # NAT64
            return False
    return addr.is_global and not addr.is_multicast
