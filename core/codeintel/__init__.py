"""Code intelligence (plan §20.2): tree-sitter/`ast`-based symbols, a call graph, and per-framework
entrypoint detection -- the foundation Week 38's taint engine walks outward from an entrypoint over.

`analyze()` never raises: a repository this can't usefully analyze (an unsupported language, a
truncated tree) yields a graph with no symbols for that file rather than failing the whole scan,
the same `analyze_or_none` contract `core/reachability` already uses.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from core.codeintel import go_lang, js_lang, python_lang
from core.codeintel.models import CodeGraph, Entrypoint, FileUnit, Symbol
from core.codeintel.resolve import resolve

log = logging.getLogger(__name__)

MAX_FILES = 20_000
MAX_FILE_BYTES = 2_000_000
SKIP_DIRS = frozenset(
    "node_modules .git .hg .svn .venv venv env __pycache__ site-packages dist build .tox "
    ".mypy_cache .next .nuxt coverage vendor third_party bower_components target".split()
)
_PY = {".py"}
_JS = {".js", ".jsx", ".mjs", ".cjs"}
_TS = {".ts", ".tsx", ".mts", ".cts"}
_GO = {".go"}


def _extract_one(rel: str, data: bytes) -> FileUnit | None:
    ext = Path(rel).suffix.lower()
    if ext in _PY:
        return python_lang.extract(rel, data.decode("utf-8", "replace"))
    if ext in _JS:
        return js_lang.extract(rel, data, typescript=False)
    if ext in _TS:
        return js_lang.extract(rel, data, typescript=True)
    if ext in _GO:
        return go_lang.extract(rel, data)
    return None


def analyze(root: Path) -> CodeGraph:
    units: list[FileUnit] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            path = Path(dirpath, fn)
            if path.is_symlink() or not path.is_file():
                continue
            seen += 1
            if seen > MAX_FILES:
                log.warning("code intelligence: too many files, stopping at %d", MAX_FILES)
                return resolve(units)
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            rel = path.relative_to(root).as_posix()
            unit = _extract_one(rel, data)
            if unit is not None:
                units.append(unit)
    return resolve(units)


def analyze_or_none(root: Path) -> CodeGraph | None:
    try:
        return analyze(root)
    except Exception:  # noqa: BLE001
        log.warning("code intelligence analysis failed", exc_info=True)
        return None


__all__ = ["CodeGraph", "Entrypoint", "Symbol", "analyze", "analyze_or_none"]
