"""Go reachability (Week 69, plan §46.3): which packages the application's Go code imports, which
names it uses from each, and every method or field name it selects -- the evidence a VEX draft
for a Go vulnerability is built from, because Go's vulnerability database names the vulnerable
functions (`ecosystem_specific.imports[].symbols` in OSV).

Parsed with tree-sitter, never compiled or run. What is collected, per file that is not a test:
- each import (path, and the name it is bound to);
- `pkg.Name` where `pkg` is the file's name for an imported package (a call, a function value, a
  type or a variable): `refs[path]`;
- every other selector's name (`x.Next()`, `x.Field`, `pkg.Type.Method`): `selectors`, over the
  whole application, because a value of a package's type can be used in a file that does not
  import the package;
- in files that dot-import a package, the bare names called: `refs[path]` too.

An import without an explicit name is bound to the package's own name, which only the package's
source says. Candidates are derived from the path (`yaml.v3` -> `yaml`, `go-sqlite3` ->
`sqlite3`, `v2` -> the element before); Go rejects an unused import, so a file in which no
candidate is used marks that import's name unknown, and then nothing is claimed about its use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_NAMES = 20_000  # selectors kept over the whole application; past this, nothing is claimed

_VERSION = re.compile(r"^v\d+$")


def _parser() -> Any:
    from core.codeintel.go_lang import _parser as go_parser

    return go_parser()


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text else ""


def candidates(path: str) -> set[str]:
    """The names an import of `path` may be bound to when the import does not say."""
    parts = [p for p in path.split("/") if p]
    if not parts:
        return set()
    last = parts[-1]
    out = {parts[-2]} if _VERSION.match(last) and len(parts) > 1 else {last}
    for name in list(out):
        base = re.sub(r"\.v\d+$", "", name)
        out |= {base, base.removeprefix("go-"), base.removesuffix("-go"), base.removesuffix(".go")}
    out |= {n.replace("-", "_") for n in out} | {n.replace("-", "") for n in out}
    return {n for n in out if n.isidentifier()}


@dataclass
class GoFile:
    imports: dict[str, str] = field(default_factory=dict)  # path -> bound name ("." / "_" / "")
    refs: dict[str, dict[str, int]] = field(default_factory=dict)  # path -> name -> first line
    selectors: dict[str, int] = field(default_factory=dict)  # name -> first line
    unknown: set[str] = field(default_factory=set)  # imports whose bound name was not found
    parsed: bool = True


def scan_file(source: bytes) -> GoFile:
    out = GoFile()
    try:
        tree = _parser().parse(source)
    except Exception:  # noqa: BLE001 - a file we cannot parse is reported as such
        return GoFile(parsed=False)
    root = tree.root_node
    if root.has_error:
        out.parsed = False
    aliases: dict[str, set[str]] = {}  # bound name -> paths
    dotted: list[str] = []
    stack = [root]
    nodes: list[Any] = []
    while stack:
        n = stack.pop()
        if n.type == "import_spec":
            path = _text(n.child_by_field_name("path")).strip('"`')
            name_node = n.child_by_field_name("name")
            bound = _text(name_node) if name_node is not None else ""
            out.imports[path] = bound
            if bound == ".":
                dotted.append(path)
            elif bound and bound != "_":
                aliases.setdefault(bound, set()).add(path)
            elif not bound:
                for c in candidates(path):
                    aliases.setdefault(c, set()).add(path)
            continue
        if n.type in ("selector_expression", "qualified_type", "call_expression"):
            nodes.append(n)
        stack.extend(reversed(n.children))
    used_aliases: set[str] = set()
    for n in nodes:
        line = n.start_point[0] + 1
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if dotted and fn is not None and fn.type == "identifier":
                for path in dotted:
                    out.refs.setdefault(path, {}).setdefault(_text(fn), line)
            continue
        if n.type == "qualified_type":
            pkg, name = _text(n.child_by_field_name("package")), _text(
                n.child_by_field_name("name")
            )
        else:
            operand = n.child_by_field_name("operand")
            pkg = _text(operand) if operand is not None and operand.type == "identifier" else ""
            name = _text(n.child_by_field_name("field"))
        if not name:
            continue
        if pkg in aliases:
            used_aliases.add(pkg)
            for path in aliases[pkg]:
                out.refs.setdefault(path, {}).setdefault(name, line)
        else:
            out.selectors.setdefault(name, line)
    for path, bound in out.imports.items():
        if bound == "" and not (candidates(path) & used_aliases):
            out.unknown.add(path)
    return out


def read_go_mod(text: str) -> tuple[str, set[str], set[str]]:
    """(module path, direct requirements, indirect requirements)."""
    module = ""
    direct: set[str] = set()
    indirect: set[str] = set()
    block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("module "):
            module = line.split()[1].strip('"')
            continue
        if line.startswith("require ("):
            block = True
            continue
        if block and line.startswith(")"):
            block = False
            continue
        spec = (
            line.removeprefix("require ").strip() if (block or line.startswith("require ")) else ""
        )
        if not spec or spec.startswith("//"):
            continue
        parts = spec.split()
        if len(parts) >= 2:
            (indirect if "// indirect" in spec else direct).add(parts[0].strip('"'))
    return module, direct, indirect


@dataclass
class GoUsage:
    """The application's Go code, as stored per project (`code_usage.data["go"]`)."""

    module: str = ""
    direct: set[str] = field(default_factory=set)
    indirect: set[str] = field(default_factory=set)
    imports: dict[str, str] = field(default_factory=dict)  # path -> first file importing it
    test_imports: dict[str, str] = field(default_factory=dict)
    refs: dict[str, dict[str, str]] = field(default_factory=dict)  # path -> name -> "file:line"
    selectors: dict[str, str] = field(default_factory=dict)  # name -> "file:line"
    unknown: set[str] = field(default_factory=set)
    files: int = 0
    unparsed: int = 0
    truncated: bool = False

    def add(self, rel: str, f: GoFile, *, test: bool) -> None:
        self.files += 1
        self.unparsed += not f.parsed
        table = self.test_imports if test else self.imports
        for path in f.imports:
            table.setdefault(path, rel)
        if test:
            return
        self.unknown |= f.unknown
        for path, names in f.refs.items():
            mine = self.refs.setdefault(path, {})
            for name, line in names.items():
                mine.setdefault(name, f"{rel}:{line}")
        for name, line in f.selectors.items():
            if len(self.selectors) >= MAX_NAMES and name not in self.selectors:
                self.truncated = True
                break
            self.selectors.setdefault(name, f"{rel}:{line}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module, "direct": sorted(self.direct), "indirect": sorted(self.indirect),
            "imports": dict(sorted(self.imports.items())),
            "test_imports": dict(sorted(self.test_imports.items())),
            "refs": {p: dict(sorted(n.items())) for p, n in sorted(self.refs.items())},
            "selectors": dict(sorted(self.selectors.items())), "unknown": sorted(self.unknown),
            "files": self.files, "unparsed": self.unparsed, "truncated": self.truncated,
        }  # fmt: skip

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GoUsage:
        return cls(
            module=d.get("module", ""), direct=set(d.get("direct", [])),
            indirect=set(d.get("indirect", [])), imports=dict(d.get("imports", {})),
            test_imports=dict(d.get("test_imports", {})),
            refs={p: dict(n) for p, n in (d.get("refs") or {}).items()},
            selectors=dict(d.get("selectors", {})), unknown=set(d.get("unknown", [])),
            files=int(d.get("files", 0)), unparsed=int(d.get("unparsed", 0)),
            truncated=bool(d.get("truncated", False)),
        )  # fmt: skip

    def in_module(self, module: str, table: dict[str, str]) -> str | None:
        """The first file importing any package of `module`."""
        for path, rel in table.items():
            if path == module or path.startswith(module + "/"):
                return rel
        return None


@dataclass(frozen=True)
class SymbolUse:
    """Whether application code uses a vulnerable package's vulnerable symbols."""

    used: bool | None  # None: cannot tell
    where: str  # "file:line" of the first use, or why it cannot be told
    symbol: str = ""


def symbol_use(u: GoUsage, path: str, symbols: list[str]) -> SymbolUse:
    """`symbols` as Go's vulnerability database writes them: `Func` or `Type.Method`; empty means
    every symbol of the package."""
    if u.truncated:
        return SymbolUse(None, "the application has too many names to check")
    if path in u.unknown:
        return SymbolUse(None, f"the name {path} is imported as could not be determined")
    imported = path in u.imports
    if not symbols:
        if imported:
            return SymbolUse(True, u.imports[path], "(any)")
        return SymbolUse(False, "")
    refs = u.refs.get(path, {})
    for sym in symbols:
        typ, _, method = sym.rpartition(".")
        if not typ:
            if sym in refs:
                return SymbolUse(True, refs[sym], sym)
            continue
        # A method: called on a value, which any file can hold. By name, over the whole app.
        if method in u.selectors:
            return SymbolUse(True, u.selectors[method], sym)
        if method in refs:  # a local variable named like the package: counted as a use
            return SymbolUse(True, refs[method], sym)
    return SymbolUse(False, "")
