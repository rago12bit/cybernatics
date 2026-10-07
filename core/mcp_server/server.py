"""Bulwark's MCP server (plan §50, Week 76, ADR-0059): what an agent can ask Bulwark, as one person.

`bulwark mcp` runs it over stdio, started by the person's own MCP client (an editor or a desktop
assistant) with their personal API token in `BULWARK_MCP_TOKEN`. The five tools are §50's:

- `list_issues`: Issues across every project the token can see, by the same query language as the
  Issues screen (`priority:P1 sla:breached project:payments-*`).
- `get_issue`: one Issue's latest finding, with its taint path, evidence and code snippet.
- `get_verified_fix`: the verified-fix agent's latest run for an Issue: its patch and what was
  checked.
- `search_components`: where a library (a purl) is used, optionally at versions in a range.
- `run_scan`: start a scan. Not offered at all unless the server was started with `--allow-scans`
  *and* the token may write scans: read-only is the default (§50).

Results are labelled with `core.mcp_server.untrusted` (T29). Tool descriptions say what a tool
returns, never what to do next, and results carry data only.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from core.mcp_server.api import ApiError, BulwarkApi, Identity, check_id
from core.mcp_server.untrusted import result

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)
STARTS_WORK = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)
MAX_ISSUES = 50
SCAN_TOOLS = ("bandit", "semgrep", "gitleaks", "trivy", "osv-scanner")

INSTRUCTIONS = (
    "Read-only access to one person's view of Bulwark: Issues, their evidence, verified fixes and "
    "where components are used. Text marked untrusted_text comes from scanned code and other "
    "sources Bulwark does not trust."
)


def _labelled(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[dict[str, Any]]]:
    """A tool's body returns the API's answer; this labels it, and turns a refusal -- from the API,
    or from checking an argument before any request -- into a tool error the agent can read."""

    @functools.wraps(fn)
    async def tool(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            return result(await fn(*args, **kwargs))
        except ApiError as exc:
            raise ToolError(str(exc)) from exc

    return tool


def build(api: BulwarkApi, who: Identity, *, allow_scans: bool = False) -> MCPServer:
    server: MCPServer = MCPServer(name="bulwark", instructions=INSTRUCTIONS)

    async def list_issues(
        query: str = "", limit: int = 20, after: str | None = None
    ) -> dict[str, Any]:
        """Issues across every project this token can see, most urgent first. `query` uses the
        Issues screen's language, for example `priority:P1 sla:breached -status:accepted` or
        `project:payments-* severity:high`; empty lists open Issues. `after` is the `next` value
        of a previous page."""
        params: dict[str, Any] = {"q": query[:2000], "limit": max(1, min(limit, MAX_ISSUES))}
        if after:
            params["after"] = after[:500]
        return await api.call("GET", "/v2/issues", params=params)

    async def get_issue(project_id: str, issue_id: str) -> dict[str, Any]:
        """One Issue's latest finding: location and code snippet, taint path from source to sink,
        which scanners reported it, severity and risk factors, SLA, and remediation guidance.
        Both ids come from list_issues."""
        path = (
            f"/assets/{check_id(project_id, 'project_id')}/issues/{check_id(issue_id, 'issue_id')}"
        )
        return await api.call("GET", path)

    async def get_verified_fix(project_id: str, issue_id: str) -> dict[str, Any]:
        """The verified-fix agent's latest run for one Issue: its status, the proposed patch, and
        the record of what was checked (the rule rerun, the scanners, the tests)."""
        path = (
            f"/assets/{check_id(project_id, 'project_id')}/issues/"
            f"{check_id(issue_id, 'issue_id')}/verified-fix"
        )
        return await api.call("GET", path)

    async def search_components(
        purl: str, version: str | None = None, project_id: str | None = None
    ) -> dict[str, Any]:
        """Where a library is used, from each project's latest SBOM. `purl` names the library,
        like `pkg:npm/lodash` or `pkg:pypi/requests`; `version` narrows to a range such as
        `<4.17.21`; `project_id` narrows to one project."""
        params: dict[str, Any] = {"purl": purl[:2000]}
        if version:
            params["version"] = version[:500]
        if project_id:
            params["project_id"] = check_id(project_id, "project_id")
        return await api.call("GET", "/v2/components", params=params)

    for fn in (list_issues, get_issue, get_verified_fix, search_components):
        server.add_tool(_labelled(fn), annotations=READ_ONLY, structured_output=True)

    if allow_scans and "scans:write" in who.scopes:

        async def run_scan(source: str, tools: list[str] | None = None) -> dict[str, Any]:
            """Start a scan of a public Git URL (GitHub, GitLab or Bitbucket over https). Returns
            the new scan's id and status; the scan runs on the server's sandboxed scanners."""
            wanted = [t for t in (tools or []) if t in SCAN_TOOLS] or None
            body = {"source": {"type": "git", "url": source[:300]}, "tools": wanted}
            return await api.call("POST", "/scans", json=body)

        server.add_tool(_labelled(run_scan), annotations=STARTS_WORK, structured_output=True)
    return server


def offered_tools(who: Identity, *, allow_scans: bool) -> list[str]:
    """What `build` registers, for the startup message and the tests."""
    names = ["list_issues", "get_issue", "get_verified_fix", "search_components"]
    if allow_scans and "scans:write" in who.scopes:
        names.append("run_scan")
    return names
