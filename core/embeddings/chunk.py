"""Function-level chunking of a checkout for the security copilot's retrieval (plan §21.5:
"pgvector embeddings of function-level chunks"). Deterministic and model-free: chunk boundaries
come straight from `core.codeintel`'s real parsers (`CodeGraph.all_symbols`), never from a guess
at where a function starts or ends. Embedding the chunks is a separate step
(`core.embeddings.service`); this module only decides what a chunk is and reads its text.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.codeintel.models import CodeGraph, Symbol

# A vendored/minified/generated file can slip past core.codeintel's own per-file byte cap
# (MAX_FILE_BYTES) yet still parse into one absurd "function" spanning most of the file. Skipping
# it here -- rather than truncating -- keeps every stored chunk's text a complete, real function
# body: a truncated chunk would still cite a real file:line range but show incomplete code for it.
MAX_CHUNK_CHARS = 20_000


def _safe_read(root: Path, rel: str) -> str | None:
    """The same path-containment chokepoint `core.hypotheses.service._safe_read` and
    `core.fixagent.tools._safe_path` use, kept as its own small copy rather than a cross-feature
    import -- this module's only filesystem access is one read-only lookup, not worth coupling three
    independently-evolving features over."""
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        return None
    candidate = (root / rel).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        return None
    if not candidate.is_file():
        return None
    return candidate.read_text(errors="replace")


@dataclass(frozen=True)
class CodeChunk:
    id: str
    path: str
    symbol_name: str
    qualified_name: str
    kind: str
    language: str
    start_line: int
    end_line: int
    text: str


def _chunk_for(symbol: Symbol, source_lines: list[str]) -> CodeChunk | None:
    # start_line/end_line are 1-indexed and inclusive (core.codeintel's own convention, shared by
    # the Python/JS/Go extractors alike).
    if symbol.start_line < 1 or symbol.end_line < symbol.start_line:
        return None
    body = "\n".join(source_lines[symbol.start_line - 1 : symbol.end_line])
    if not body.strip() or len(body) > MAX_CHUNK_CHARS:
        return None
    return CodeChunk(
        id=symbol.id,
        path=symbol.path,
        symbol_name=symbol.name,
        qualified_name=symbol.qualified_name,
        kind=symbol.kind,
        language=symbol.language,
        start_line=symbol.start_line,
        end_line=symbol.end_line,
        text=body,
    )


def chunk_checkout(checkout: Path, graph: CodeGraph) -> list[CodeChunk]:
    """One chunk per real symbol `core.codeintel` found, reading each file at most once."""
    by_path: dict[str, list[Symbol]] = {}
    for symbol in graph.all_symbols:
        by_path.setdefault(symbol.path, []).append(symbol)
    out: list[CodeChunk] = []
    for path, symbols in by_path.items():
        source = _safe_read(checkout, path)
        if source is None:
            continue
        lines = source.splitlines()
        for symbol in symbols:
            chunk = _chunk_for(symbol, lines)
            if chunk is not None:
                out.append(chunk)
    return out
