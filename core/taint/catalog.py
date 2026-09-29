"""Per-language source/sink/sanitizer catalogs (plan §20.3): YAML, one file per language, loaded
once and cached.

"Source" here means exactly what the plan says -- "request parameters are sources" -- not a table
of individual attribute-access patterns (`request.args.get`, `req.body.x`, ...). Concretely, a
*bare name* is treated as carrying real external input wherever it appears inside a function
`core.codeintel`'s entrypoint detector (plan §20.2) already matched as an HTTP handler:

  - a `global_sources` entry (Flask's imported `request` object, referenced by that exact name
    anywhere in the function's scope) -- this also covers a Django view's `request` parameter for
    free, since to `ast`/tree-sitter a parameter and a global are both just a name reference; there
    is no need to know which one it is.
  - a `param_source_positions` entry (Express's `(req, res) => {}`, Go's `func(w, r) {}`) -- the
    entrypoint handler's own parameter at that position, whatever it happens to be named.

Sinks and sanitizers are matched the same way `core.codeintel`'s own call graph already extracts a
callee name: the last dotted/property component of a call (`cursor.execute` matches the pattern
`execute`), not the full qualified path -- so a sink pattern can also fire on an unrelated object
that merely has a same-named method. Documented, not hidden: the same shape-based trade-off
`core.codeintel`'s entrypoint matching already makes and names in its own ADR (0020).
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

_CATALOG_DIR = Path(__file__).parent / "catalogs"


@dataclass(frozen=True)
class SinkPattern:
    name: str  # matched against a call's callee name, e.g. "execute"
    category: str


@dataclass(frozen=True)
class Catalog:
    language: str
    global_sources: frozenset[str]
    param_source_positions: frozenset[int]
    sinks: tuple[SinkPattern, ...]
    sanitizers: frozenset[str]

    def sink_for(self, callee_name: str) -> SinkPattern | None:
        return next((s for s in self.sinks if s.name == callee_name), None)

    def is_sanitizer(self, callee_name: str) -> bool:
        return callee_name in self.sanitizers


@cache
def load_catalog(language: str) -> Catalog:
    path = _CATALOG_DIR / f"{language}.yaml"
    data = yaml.safe_load(path.read_text())
    return Catalog(
        language=language,
        global_sources=frozenset(data.get("global_sources", [])),
        param_source_positions=frozenset(data.get("param_source_positions", [])),
        sinks=tuple(SinkPattern(s["name"], s["category"]) for s in data.get("sinks", [])),
        sanitizers=frozenset(data.get("sanitizers", [])),
    )
