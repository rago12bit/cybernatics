"""What every connector kind shares: the fetch contract, the page cap, and pagination that stays on
the configured host."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from core.connectors.http import ConnectorError, Transport, expect_ok, next_link
from core.models import Finding

MAX_PAGES = 100  # 10,000 alerts at 100 a page: beyond that a pull is refused, never truncated
PER_PAGE = 100


@dataclass
class Fetched:
    """One complete pull. `items` is how many records the source returned, which can differ from
    `len(findings)` (a record with no usable location is skipped and counted in `warnings`)."""

    findings: list[Finding]
    items: int
    warnings: list[str] = field(default_factory=list)
    requests: int = 0


def same_origin(base: str, url: str) -> bool:
    a, b = urlsplit(base), urlsplit(url)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def link_pages(
    transport: Transport, first_url: str, headers: dict[str, str], what: str
) -> Iterator[tuple[Any, int]]:
    """Every page of a Link-header-paginated list (GitHub), as `(body, request number)`. A next page
    on another host, or more than MAX_PAGES pages, fails the pull: a partial pull would look like
    "everything after page N was fixed" to the reimport that follows."""
    url: str | None = first_url
    n = 0
    while url:
        n += 1
        if n > MAX_PAGES:
            raise ConnectorError(
                f"{what}: more than {MAX_PAGES * PER_PAGE} records; refusing a partial pull"
            )
        if not same_origin(first_url, url):
            raise ConnectorError(f"{what}: pagination pointed at another host; refusing it")
        resp = transport("GET", url, headers, None)
        body = expect_ok(resp, what)
        if not isinstance(body, list):
            raise ConnectorError(f"{what}: expected a list, got {type(body).__name__}")
        yield body, n
        url = next_link(resp.headers)
