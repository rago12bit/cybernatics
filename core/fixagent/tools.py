"""The allowlisted tools an in-progress fix attempt's model turn may call (plan §21.2): `read_file`,
`search_code`, `get_call_path`, and the terminal `propose_patch`. No shell, no network, no writes
outside the one patch `propose_patch` ends the turn with.

`run_verification` (the fifth tool the plan names) is deliberately NOT exposed here as something the
model can call mid-turn -- see `docs/adr/0027-verified-fix-agent.md`. Verification means applying an
untrusted patch to a real checkout and running scanners/tests against it: a heavier, more
security-sensitive operation than reading text, and the workflow (not the model) decides when it
happens, deterministically, after a turn ends. Exposing it as a freely-callable tool would let the
model choose when to mutate and execute a sandboxed checkout mid-reasoning, a materially larger
trust boundary than choosing what to read.

Every tool here is a pure function of `root` (the checkout directory) plus its own arguments; none
of them can be pointed outside `root` -- `_safe_path` is the single chokepoint that enforces that,
and every tool routes every path argument through it before touching the filesystem.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from core.fixagent.context import FixContext

MAX_READ_BYTES = 40_000  # generous for one file's worth of context, small enough to bound a turn
MAX_SEARCH_RESULTS = 30
MAX_SEARCH_LINE_CHARS = 300


class ToolError(ValueError):
    """A tool call was rejected -- returned to the model as the tool's own result (so it can adjust
    its next call), never raised past the agent loop."""


def _safe_path(root: Path, rel: str) -> Path:
    """The one place path containment is enforced. Rejects absolute paths, `..` segments, and any
    resolved path that escapes `root` (covers symlink tricks too, since `resolve()` follows them).
    """
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        raise ToolError(f"path must be relative to the repository root: {rel!r}")
    candidate = (root / rel).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ToolError(f"path escapes the repository: {rel!r}")
    return candidate


def read_file(root: Path, path: str, *, start_line: int = 1, end_line: int | None = None) -> str:
    """Lines `start_line`..`end_line` (1-based, inclusive; `end_line=None` means to the end), each
    prefixed with its number -- the same `"NNNNN | code"` shape `core.llm.prompt` already uses, so
    the model sees a familiar format and any patch it proposes can be checked against real line
    numbers."""
    p = _safe_path(root, path)
    if not p.is_file():
        raise ToolError(f"no such file: {path!r}")
    with p.open("rb") as fh:  # the first part only: never the whole of a very large file
        text = fh.read(MAX_READ_BYTES).decode("utf-8", errors="replace")
    lines = text.splitlines()
    lo = max(1, start_line)
    hi = len(lines) if end_line is None else min(len(lines), end_line)
    numbered = [f"{i:>5} | {lines[i - 1]}" for i in range(lo, hi + 1) if 1 <= i <= len(lines)]
    return "\n".join(numbered) if numbered else "(empty range)"


def search_code(root: Path, query: str, *, glob: str = "**/*") -> str:
    """A plain, case-sensitive substring search over tracked-looking files (skips the usual
    dependency/build directories) -- not a regex engine, so a hostile or malformed query can't
    become a ReDoS or a filesystem traversal; `glob` narrows by extension/directory."""
    if not query or len(query) > 200:
        raise ToolError("query must be 1-200 characters")
    skip = {
        "node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build",
        ".next", "vendor", "site-packages",
    }  # fmt: skip
    hits: list[str] = []
    for p in sorted(root.glob(glob)):
        if not p.is_file() or any(part in skip for part in p.parts):
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if query in line:
                rel = p.relative_to(root)
                snippet = line.strip()[:MAX_SEARCH_LINE_CHARS]
                hits.append(f"{rel}:{i}: {snippet}")
                if len(hits) >= MAX_SEARCH_RESULTS:
                    return "\n".join(hits) + "\n(more results omitted)"
    return "\n".join(hits) if hits else "(no matches)"


def get_call_path(ctx: FixContext, path: str, line: int) -> str:
    """The known callers of whatever function/method encloses `path:line`, from the call graph
    already built for this attempt (`core.fixagent.context.gather_context`) -- no filesystem access
    of its own, so it needs no path-containment check beyond what building that graph already did.
    """
    from core.fixagent.context import enclosing_symbol

    sym = enclosing_symbol(ctx.graph, path, line)
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


@dataclass(frozen=True)
class ToolSchema:
    name: str
    description: str
    input_schema: dict[str, Any]


TOOL_SCHEMAS: tuple[ToolSchema, ...] = (
    ToolSchema(
        "read_file",
        "Read a range of lines from a file in the repository, with line numbers.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path relative to the repository root."},
                "start_line": {"type": "integer", "default": 1},
                "end_line": {"type": "integer", "description": "Omit to read to the end."},
            },
            "required": ["path"],
        },
    ),
    ToolSchema(
        "search_code",
        "Search for a plain substring across the repository's files.",
        {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "glob": {"type": "string", "description": "e.g. '**/*.py'. Default: every file."},
            },
            "required": ["query"],
        },
    ),
    ToolSchema(
        "get_call_path",
        "List the known callers of the function enclosing a given file:line, from the repository's "
        "own call graph.",
        {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "line": {"type": "integer"},
            },
            "required": ["path", "line"],
        },
    ),
    ToolSchema(
        "propose_patch",
        "End the turn with a fix: a unified diff for exactly the finding's file. Call this once "
        "you have enough context; it ends the conversation.",
        {
            "type": "object",
            "properties": {
                "explanation": {"type": "string"},
                "patch": {
                    "type": "string",
                    "description": "A unified diff, --- a/<path> / +++ b/<path>.",
                },
                "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            },
            "required": ["explanation", "patch", "confidence"],
        },
    ),
)
