"""The allowlisted tools a copilot turn may call (plan §21.5): query_issues, fetch_code_range,
get_call_path, list_routes, compare_scans. Mirrors core.fixagent.tools's shape (pure functions, one
path-containment chokepoint, JSON tool schemas) -- kept as its own copy rather than a cross-feature
import, the same reasoning core.hypotheses.service._safe_read already documents for itself: this
module's only filesystem access is read-only lookups, not worth coupling two independently-evolving
features over.

Every tool is read-only. Nothing here can write to the repository, run a scanner, or start a scan --
the copilot answers questions about what has already been scanned and indexed; it never triggers new
work on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from core.codeintel.models import CodeGraph
from core.persistence import repo

MAX_READ_BYTES = 40_000
MAX_ISSUES_RETURNED = 20


class ToolError(ValueError):
    """A tool call was rejected -- returned to the model as the tool's own result, never raised
    past the agent loop (same convention core.fixagent.tools.ToolError documents)."""


@dataclass(frozen=True)
class CopilotContext:
    """Everything one copilot conversation's tool calls need, built once when the conversation
    starts (session, asset, a fresh checkout + code-intelligence graph) -- not rebuilt per turn or
    per tool call."""

    session: Session
    org_id: str
    asset_id: str
    latest_scan_id: str
    checkout: Path
    graph: CodeGraph


def _safe_path(root: Path, rel: str) -> Path:
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        raise ToolError(f"path must be relative to the repository root: {rel!r}")
    candidate = (root / rel).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ToolError(f"path escapes the repository: {rel!r}")
    return candidate


def fetch_code_range(
    ctx: CopilotContext, path: str, *, start_line: int = 1, end_line: int | None = None
) -> str:
    """Lines start_line..end_line (1-based, inclusive), each prefixed with its number -- identical
    shape to core.fixagent.tools.read_file, so a citation built from this tool's output uses real
    line numbers a person can jump to."""
    p = _safe_path(ctx.checkout, path)
    if not p.is_file():
        raise ToolError(f"no such file: {path!r}")
    with p.open("rb") as fh:  # the first part only: never the whole of a very large file
        text = fh.read(MAX_READ_BYTES).decode("utf-8", errors="replace")
    lines = text.splitlines()
    lo = max(1, start_line)
    hi = len(lines) if end_line is None else min(len(lines), end_line)
    numbered = [f"{i:>5} | {lines[i - 1]}" for i in range(lo, hi + 1) if 1 <= i <= len(lines)]
    return "\n".join(numbered) if numbered else "(empty range)"


def get_call_path(ctx: CopilotContext, path: str, line: int) -> str:
    """The known callers of whatever function/method encloses path:line."""
    sym = next(
        (s for s in ctx.graph.all_symbols if s.path == path and s.start_line <= line <= s.end_line),
        None,
    )
    if sym is None:
        return f"no enclosing function found for {path}:{line}"
    caller_ids = ctx.graph.callers_of(sym.id)
    by_id = {s.id: s for s in ctx.graph.all_symbols}
    callers = [by_id[cid] for cid in caller_ids if cid in by_id]
    if not callers:
        return f"{sym.qualified_name} ({path}:{sym.start_line}-{sym.end_line}): no known callers"
    lines = [f"{sym.qualified_name} ({path}:{sym.start_line}-{sym.end_line}) is called by:"]
    lines += [f"  - {c.qualified_name} ({c.path}:{c.start_line})" for c in callers]
    return "\n".join(lines)


def list_routes(ctx: CopilotContext, *, method: str | None = None) -> str:
    """Every HTTP entrypoint core.codeintel found in this checkout, optionally filtered by method."""
    eps = ctx.graph.entrypoints
    if method:
        eps = [e for e in eps if e.method.upper() == method.upper()]
    if not eps:
        return "(no routes found)"
    return "\n".join(f"{e.method} {e.path} ({e.framework}) -- {e.symbol_id}" for e in eps)


def query_issues(
    ctx: CopilotContext,
    *,
    severity: list[str] | None = None,
    category: list[str] | None = None,
    cwe: str | None = None,
    path_contains: str | None = None,
) -> str:
    """The asset's currently-open issues, optionally filtered -- wraps
    core.persistence.repo.list_asset_issues (the same function the issues table API uses), plus a
    light in-memory filter for cwe/path_contains (not among that function's own filters)."""
    page = repo.list_asset_issues(
        ctx.session, ctx.asset_id, ctx.latest_scan_id, severities=severity, categories=category,
        sort="risk", limit=200,
    )  # fmt: skip
    items = page.items
    if cwe:
        items = [d for d in items if cwe.upper() in [c.upper() for c in d["taxonomy"]["cwe"]]]
    if path_contains:
        items = [d for d in items if path_contains in d["location"]["path"]]
    items = items[:MAX_ISSUES_RETURNED]
    if not items:
        return "(no matching issues)"
    lines = []
    for d in items:
        issue_id = d["issue"]["id"] if d.get("issue") else "?"
        risk = d["scoring"].get("risk_score")
        cwes = ",".join(d["taxonomy"]["cwe"]) or "none"
        lines.append(
            f"{issue_id} [{d['scoring']['normalized_severity']}] risk={risk} "
            f"{d['title']} ({d['location']['path']}:{d['location']['start_line']}) cwe={cwes}"
        )
    return "\n".join(lines)


def compare_scans_tool(ctx: CopilotContext, scan_id_a: str, scan_id_b: str) -> str:
    """New/fixed/reintroduced/unchanged issue ids between two scans of this asset -- wraps
    core.persistence.repo.compare_scans (the same function the scan-comparison screen uses)."""
    cmp = repo.compare_scans(ctx.session, scan_id_a, scan_id_b, org_id=ctx.org_id)
    if cmp is None:
        raise ToolError("these two scans do not belong to the same project")
    if cmp.earlier.asset_id != ctx.asset_id:
        # The ids come from the model, which reads the repository's text: a conversation about
        # one project does not answer for another, whatever it was told to ask.
        raise ToolError("these scans are not this project's")

    def fmt(items: list[dict[str, Any]]) -> str:
        return ", ".join(i["id"] for i in items) if items else "(none)"

    return (
        f"comparing {cmp.earlier.id} (earlier) to {cmp.later.id} (later):\n"
        f"new: {fmt(cmp.new)}\n"
        f"fixed: {fmt(cmp.fixed)}\n"
        f"reintroduced: {fmt(cmp.reintroduced)}\n"
        f"unchanged: {len(cmp.unchanged)} issue(s)"
    )


@dataclass(frozen=True)
class ToolSchema:
    name: str
    description: str
    input_schema: dict[str, Any]


TOOL_SCHEMAS: tuple[ToolSchema, ...] = (
    ToolSchema(
        "query_issues",
        "List the project's currently-open issues, optionally filtered.",
        {
            "type": "object",
            "properties": {
                "severity": {"type": "array", "items": {"type": "string"}},
                "category": {"type": "array", "items": {"type": "string"}},
                "cwe": {"type": "string", "description": "e.g. 'CWE-89'."},
                "path_contains": {"type": "string"},
            },
        },
    ),
    ToolSchema(
        "fetch_code_range",
        "Read a range of lines from a file in the repository, with line numbers.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "description": "Omit to read to the end."},
            },
            "required": ["path"],
        },
    ),
    ToolSchema(
        "get_call_path",
        "List the known callers of the function enclosing a given file:line.",
        {
            "type": "object",
            "properties": {"path": {"type": "string"}, "line": {"type": "integer"}},
            "required": ["path", "line"],
        },
    ),
    ToolSchema(
        "list_routes",
        "List every HTTP route this project's code intelligence found.",
        {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "e.g. 'GET'. Omit for all."}
            },
        },
    ),
    ToolSchema(
        "compare_scans",
        "Compare two scans of this project: new, fixed, reintroduced and unchanged issues.",
        {
            "type": "object",
            "properties": {"scan_id_a": {"type": "string"}, "scan_id_b": {"type": "string"}},
            "required": ["scan_id_a", "scan_id_b"],
        },
    ),
    ToolSchema(
        "give_answer",
        "End the turn with your answer. Call this once you have enough information; it ends the "
        "conversation. Every citation must come from a tool result you actually saw, never from "
        "memory or assumption.",
        {
            "type": "object",
            "properties": {
                "answer": {"type": "string"},
                "citations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {"type": "string", "enum": ["issue", "code"]},
                            "issue_id": {"type": "string"},
                            "path": {"type": "string"},
                            "line": {"type": "integer"},
                        },
                        "required": ["kind"],
                    },
                },
            },
            "required": ["answer", "citations"],
        },
    ),
)
