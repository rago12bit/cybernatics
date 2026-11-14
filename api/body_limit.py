"""A size limit on every request body, applied before the body is read.

FastAPI reads a route's body before it runs the route's dependencies, sign-in among them: a JSON
body is collected whole in memory, and a multipart upload is written whole to a temporary file,
whatever its size. uvicorn sets no limit of its own. So until this existed, anyone who could reach
the API -- signed in or not -- could post gigabytes at any route that takes a body and have the
server hold them, and the size checks the upload routes make themselves only ever saw a file that
had already arrived.

The limit depends on the route: an upload route may take what its own check allows (plus the
multipart framing around it), a webhook what its sender may send, and everything else -- JSON --
`JSON_MAX_BYTES`. A request that declares more (`Content-Length`) is answered 413 without being
read; one that declares nothing, or lies, is cut off at the limit as it streams.

Registered inside the CORS middleware (`api.main.create_app`), so a browser can read the 413.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from api.deps import WEBHOOK_MAX_BYTES
from core.config import Settings
from core.manual import attachments

#: The most a JSON (or any other non-upload) request body may be. The largest real ones -- a
#: threat model, a bulk change naming its Issues one by one -- are a few hundred kilobytes.
JSON_MAX_BYTES = 8 * 1024 * 1024
#: A SAML response: `core.identity.saml.finish` refuses more than a million characters of it.
SAML_MAX_BYTES = 2 * 1024 * 1024
#: Room for the multipart boundaries and the form's other fields around an uploaded file.
FORM_OVERHEAD_BYTES = 1024 * 1024

_ATTACHMENT = re.compile(r"^/v2/[a-z-]+/[^/]+/attachments$")
_UPLOADS = ("/scans/upload", "/v2/ingest")

LimitFor = Callable[[str, str], int]


def limits(settings: Settings) -> LimitFor:
    """The limit for a request, by method and path."""
    upload = settings.max_upload_bytes + FORM_OVERHEAD_BYTES
    attachment = attachments.MAX_BYTES + FORM_OVERHEAD_BYTES

    def limit_for(method: str, path: str) -> int:
        if method != "POST":
            return JSON_MAX_BYTES
        if path in _UPLOADS:
            return max(upload, JSON_MAX_BYTES)
        if path.startswith("/integrations/"):
            return WEBHOOK_MAX_BYTES
        if path.startswith("/auth/saml/"):
            return SAML_MAX_BYTES
        if _ATTACHMENT.match(path):
            return max(attachment, JSON_MAX_BYTES)
        return JSON_MAX_BYTES

    return limit_for


def too_large(limit: int) -> str:
    return f"request body over {limit} bytes"


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, limit_for: LimitFor) -> None:
        self.app = app
        self.limit_for = limit_for

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self.limit_for(scope["method"], scope["path"])
        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            # Not read at all. The connection is closed: the client may still be sending.
            refused = JSONResponse(
                {"detail": too_large(limit)}, status_code=413, headers={"Connection": "close"}
            )
            await refused(scope, receive, send)
            return
        seen = 0

        async def capped() -> Message:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    # Raised into whoever is reading the body (FastAPI's own body parsing lets an
                    # HTTPException through), so the request ends as an ordinary 413.
                    raise HTTPException(413, too_large(limit))
            return message

        await self.app(scope, capped, send)
