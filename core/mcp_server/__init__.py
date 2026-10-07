"""Bulwark's MCP server (plan §50): see `core.mcp_server.server` and docs/mcp.md."""

from __future__ import annotations

import sys

from core.mcp_server.api import ApiError, BulwarkApi
from core.mcp_server.server import build, offered_tools


async def serve(api_url: str, token: str, *, allow_scans: bool = False) -> None:
    """Check the token, then speak MCP over stdin/stdout until the client hangs up. Everything for
    a person goes to stderr: stdout carries the protocol and nothing else."""
    api = BulwarkApi(api_url, token)
    try:
        who = await api.whoami()
        names = offered_tools(who, allow_scans=allow_scans)
        print(f"bulwark mcp: acting as {who.actor}; tools: {', '.join(names)}", file=sys.stderr)
        if allow_scans and "run_scan" not in names:
            print("bulwark mcp: run_scan is off: this token cannot write scans", file=sys.stderr)
        await build(api, who, allow_scans=allow_scans).run_stdio_async()
    finally:
        await api.aclose()


__all__ = ["ApiError", "serve"]
