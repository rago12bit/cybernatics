"""The MCP server's only way to Bulwark's data: the REST API, as the token's holder (plan §50).

The server holds no database credentials and decides nothing about access itself. Every call
carries the token it was started with, so the API's own checks apply unchanged: the token's
scopes, its person's role project by project, the project scope a limited person runs under, and
Postgres row-level security behind all of it. What the token cannot see, the agent cannot see.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from core.mcp_server.untrusted import clean

# Path segments are ids the API issued; nothing else is put into a URL path.
_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")
TIMEOUT_S = 30.0


class ApiError(Exception):
    """A refusal or failure, worded for the person reading their agent's transcript."""


@dataclass(frozen=True)
class Identity:
    actor: str
    scopes: frozenset[str]
    org_role: str | None


def check_id(value: str, what: str) -> str:
    if not _ID.match(value or ""):
        raise ApiError(
            f"{what} must be an id from a previous result, like the ones list_issues returns"
        )
    return quote(value, safe="")


class BulwarkApi:
    def __init__(
        self, base_url: str, token: str, transport: httpx.AsyncBaseTransport | None = None
    ):
        parts = urlsplit(base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise ApiError(f"not an http(s) URL: {base_url!r}")
        if parts.scheme == "http" and parts.hostname not in ("localhost", "127.0.0.1", "::1"):
            # The token would cross the network in clear text.
            raise ApiError("use https for a Bulwark API that is not on this machine")
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}", "User-Agent": "bulwark-mcp"},
            timeout=TIMEOUT_S,
            follow_redirects=False,  # a redirect could carry the token somewhere else
            transport=transport,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(self, method: str, path: str, **kw: Any) -> Any:
        try:
            resp = await self._client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise ApiError(f"could not reach the Bulwark API ({type(exc).__name__})") from exc
        if resp.status_code < 300:
            return resp.json() if resp.content else None
        raise ApiError(_refusal(resp))

    async def call(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        """A request whose answer must be a JSON object, as every endpoint the tools use returns."""
        body = await self.request(method, path, **kw)
        if not isinstance(body, dict):
            raise ApiError("the Bulwark API gave an answer this server does not understand")
        return body

    async def whoami(self) -> Identity:
        me = await self.call("GET", "/v2/me")
        if me.get("scopes") is None:
            # The deployment-wide shared token is nobody in particular and can do everything; an
            # agent gets a token that stands for one person or one purpose, or nothing.
            raise ApiError(
                "this is the deployment's shared token; make a personal API token (My API tokens) "
                "and use that"
            )
        return Identity(str(me.get("actor", "")), frozenset(me["scopes"]), me.get("org_role"))


def _refusal(resp: httpx.Response) -> str:
    detail: Any = None
    try:
        detail = resp.json().get("detail")
    except (ValueError, AttributeError):
        pass
    if isinstance(detail, dict):
        detail = detail.get("message")
    # The API's own wording, but it can echo what was sent (a query), so it is cleaned and short.
    reason = f": {clean(detail, 300)}" if isinstance(detail, str) and detail else ""
    if resp.status_code == 401:
        return "the token was refused (expired, revoked, or its person was turned off)"
    if resp.status_code == 403:
        return f"this token is not allowed to do that{reason}"
    if resp.status_code == 404:
        return f"not found, or not visible to this token{reason}"
    if resp.status_code == 422:
        return f"the request was not valid{reason}"
    if resp.status_code == 429:
        return f"too many requests; try again later{reason}"
    return f"the Bulwark API answered HTTP {resp.status_code}{reason}"
