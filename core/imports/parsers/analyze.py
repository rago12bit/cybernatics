"""What a sample report looks like, for writing a mapping (plan §42.4 step 1).

Reads an uploaded sample and describes its *shape*: where the lists of records are, which fields
each record has, and a few example values of each. That description is what the mapping screen
shows and what the mapping assistant is given -- never the file itself -- so the model sees field
names and short examples, not a whole report, and can only propose paths that really exist.

Runs in the parser sandbox like every other read of an uploaded file (`worker.py --analyze`), with
the same limits; a sample is small, so this reads at most `MAX_SAMPLE_BYTES` of it.
"""

from __future__ import annotations

import io
import json
import re
from collections import Counter
from collections.abc import Callable
from typing import Any, BinaryIO

from core.imports.parsers.base import ParseAborted, ParseContext, ParseLimits
from core.imports.parsers.safe import iter_csv, iter_xml, json_events, stream_objects
from core.imports.parsers.universal import _local

MAX_SAMPLE_BYTES = 2 * 1024 * 1024
MAX_CANDIDATES = 5
RECORDS_READ = 50  # records per candidate whose fields are described
MAX_FIELDS = 120
EXAMPLES = 3
EXAMPLE_CHARS = 120
MAX_WALK_DEPTH = 8
_IDENT = re.compile(r"^[A-Za-z_@$][A-Za-z0-9_@$-]*$")


def sample_format(head: bytes) -> str:
    text = head[:4096].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
    if text.startswith(("{", "[")):
        return "json"
    if text.startswith("<"):
        return "xml"
    return "csv"


def analyze(stream: BinaryIO, limits: ParseLimits | None = None) -> dict[str, Any]:
    """`{"format", "candidates": [{"records", "count", "fields": [{"path", "examples", "filled"}]}],
    "error"}`. Never raises on bad input; an unreadable sample is an `error`."""
    limits = limits or ParseLimits(max_bytes=MAX_SAMPLE_BYTES, max_seconds=20.0)
    data = stream.read(limits.max_bytes + 1)
    if len(data) > limits.max_bytes:
        return {"format": None, "candidates": [], "error": "the sample is larger than 2 MB; "
                "upload the first part of the report"}  # fmt: skip
    fmt = sample_format(data)
    ctx = ParseContext(limits=limits)
    try:
        if fmt == "json":
            candidates = _json(data, ctx)
        elif fmt == "xml":
            candidates = _xml(data, ctx)
        else:
            candidates = _csv(data, ctx)
    except ParseAborted as exc:
        return {"format": fmt, "candidates": [], "error": str(exc)}
    except (ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
        return {"format": fmt, "candidates": [], "error": f"could not read the sample ({exc})"}
    if not candidates:
        return {"format": fmt, "candidates": [], "error": "found no list of records in the sample"}
    return {"format": fmt, "candidates": candidates, "error": None}


class _Fields:
    """Field paths in the order first seen, with a few distinct examples and a fill count."""

    def __init__(self) -> None:
        self.examples: dict[str, list[str]] = {}
        self.filled: Counter[str] = Counter()

    def add(self, path: str, value: Any) -> None:
        if path not in self.examples:
            if len(self.examples) >= MAX_FIELDS:
                return
            self.examples[path] = []
        text = _text(value)
        if not text:
            return
        self.filled[path] += 1
        seen = self.examples[path]
        if len(seen) < EXAMPLES and text not in seen:
            seen.append(text)

    def to_list(self) -> list[dict[str, Any]]:
        return [
            {"path": p, "examples": ex, "filled": self.filled[p]} for p, ex in self.examples.items()
        ]


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    s = " ".join(str(value).split())
    return s if len(s) <= EXAMPLE_CHARS else s[:EXAMPLE_CHARS] + "…"


# --- JSON ----------------------------------------------------------------------------------------


def _key(k: str) -> str:
    return f".{k}" if _IDENT.match(k) else "[" + json.dumps(k) + "]"


def _path_of_prefix(prefix: str) -> str | None:
    """ijson's `runs.item.results.item` -> `$.runs[*].results[*]`; None when a key holds a '.'
    (ijson's prefix would be ambiguous, and so would the records path)."""
    if prefix == "item":
        return "$[*]"
    parts = prefix.split(".")
    out = ["$"]
    for part in parts:
        out.append("[*]" if part == "item" else _key(part))
    return "".join(out)


def _json(data: bytes, ctx: ParseContext) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    for prefix, event, _ in json_events(io.BytesIO(data), ctx):
        if event == "start_map" and (prefix == "item" or prefix.endswith(".item")):
            counts[prefix] += 1
    out: list[dict[str, Any]] = []
    for prefix, count in counts.most_common():
        if len(out) >= MAX_CANDIDATES:
            break
        path = _path_of_prefix(prefix)
        if path is None:
            continue
        fields = _Fields()
        read = 0
        sub = ParseContext(limits=ctx.limits)
        for _, value in stream_objects(json_events(io.BytesIO(data), sub), _wanted(prefix)):
            if isinstance(value, dict):
                _walk(value, "$", fields, 0)
                read += 1
                if read >= RECORDS_READ:
                    break
        out.append({"records": path, "count": count, "fields": fields.to_list()})
    return out


def _wanted(prefix: str) -> Callable[[str], str | None]:
    return lambda p: "r" if p == prefix else None


def _walk(node: Any, path: str, fields: _Fields, depth: int) -> None:
    if depth > MAX_WALK_DEPTH:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            _walk(v, path + _key(str(k)), fields, depth + 1)
    elif isinstance(node, list):
        for item in node[:20]:
            _walk(item, path + "[*]", fields, depth + 1)
    else:
        fields.add(path, node)


# --- XML -----------------------------------------------------------------------------------------


def _xml(data: bytes, ctx: ParseContext) -> list[dict[str, Any]]:
    counts: Counter[tuple[str, ...]] = Counter()
    stack: list[str] = []
    for event, element in iter_xml(io.BytesIO(data), ctx):
        if event == "start":
            stack.append(_local(element.tag))
            if len(stack) > 1:
                counts[tuple(stack)] += 1
        else:
            stack.pop()
    # A record list is an element that repeats and has structure; the root never is one.
    ranked = [(chain, n) for chain, n in counts.most_common() if n >= 1][: MAX_CANDIDATES * 4]
    out: list[dict[str, Any]] = []
    for chain, count in ranked:
        if len(out) >= MAX_CANDIDATES:
            break
        fields = _Fields()
        read = 0
        stack = []
        sub = ParseContext(limits=ctx.limits)
        for event, element in iter_xml(io.BytesIO(data), sub):
            if event == "start":
                stack.append(_local(element.tag))
                continue
            if tuple(stack) == chain and read < RECORDS_READ:
                _walk_xml(element, "", fields, 0)
                read += 1
            stack.pop()
        listed = fields.to_list()
        if listed and any(f["path"] != "." for f in listed):
            out.append({"records": "/".join(chain[-2:]), "count": count, "fields": listed})
    return out


def _walk_xml(element: Any, path: str, fields: _Fields, depth: int) -> None:
    if depth > 3:
        return
    for k, v in element.attrib.items():
        fields.add(f"{path}@{_local(k)}" if path else f"@{_local(k)}", v)
    children = list(element)
    if not children and element.text and element.text.strip():
        fields.add(path.rstrip("/") or ".", element.text)
    for child in children:
        _walk_xml(child, f"{path}{_local(child.tag)}/", fields, depth + 1)


# --- CSV -----------------------------------------------------------------------------------------


def _csv(data: bytes, ctx: ParseContext) -> list[dict[str, Any]]:
    rows = iter_csv(io.BytesIO(data), ctx)
    header = next(rows, None)
    if not header or len(header) < 2:
        return []
    fields = _Fields()
    names = [h.strip() for h in header]
    for name in names:
        if name:
            fields.add(name, None)
    count = 0
    for row in rows:
        if not any(c.strip() for c in row):
            continue
        count += 1
        if count <= RECORDS_READ:
            for name, cell in zip(names, row, strict=False):  # short rows are allowed
                if name:
                    fields.add(name, cell)
    return [{"records": None, "count": count, "fields": fields.to_list()}]
