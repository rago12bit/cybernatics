"""Parsing untrusted files safely (plan §42.2): bounded reads, bounded nesting, bounded time, no XML
entity expansion, and regular expressions that cannot backtrack catastrophically.

Everything here exists because a report is attacker-controlled input. `ijson` and `defusedxml` are
the streaming readers; this module wraps them so limits are checked *while* reading, which is the
only point at which a hostile file can still be stopped cheaply.
"""

from __future__ import annotations

import codecs
import csv
import re as _stdlib_re
from collections.abc import Callable, Iterator
from typing import Any, BinaryIO

import ijson
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from ijson.common import ObjectBuilder

from core.imports.parsers.base import ParseAborted, ParseContext

try:  # RE2 guarantees linear-time matching; the stdlib engine does not.
    import re2 as _re2
except ImportError:  # pragma: no cover - google-re2 is a declared dependency
    _re2 = None

MAX_REGEX_INPUT = 20_000  # characters; free text beyond this is not searched for identifiers

_START = ("start_map", "start_array")
_END = ("end_map", "end_array")


class LimitedStream:
    """Counts bytes as they are read and stops at the limit, so an oversized upload is cut off
    mid-read rather than after being fully buffered."""

    def __init__(self, stream: BinaryIO, max_bytes: int) -> None:
        self._stream = stream
        self._left = max_bytes
        self._max = max_bytes

    def read(self, size: int = -1) -> bytes:
        data = self._stream.read(size)
        self._left -= len(data)
        if self._left < 0:
            raise ParseAborted(f"file exceeds the {self._max} byte limit")
        return data


def json_events(stream: BinaryIO, ctx: ParseContext) -> Iterator[tuple[str, str, Any]]:
    """`(prefix, event, value)` JSON events with the size, depth and time limits enforced."""
    limits = ctx.limits
    depth = 0
    count = 0
    try:
        for prefix, event, value in ijson.parse(
            LimitedStream(stream, limits.max_bytes), use_float=True
        ):
            if event in _START:
                depth += 1
                if depth > limits.max_depth:
                    raise ParseAborted(f"JSON nests deeper than {limits.max_depth} levels")
            elif event in _END:
                depth -= 1
            count += 1
            if count % 4096 == 0:
                ctx.check_time()
            yield prefix, event, value
    except ijson.IncompleteJSONError as exc:
        raise ParseAborted(
            "not valid JSON: the file ends unexpectedly (it may be cut off)"
        ) from exc
    except ijson.JSONError as exc:
        # The library's message is several lines with a caret pointing into the file; one line says
        # all a person can act on.
        first = (str(exc).strip().splitlines() or ["malformed"])[0]
        raise ParseAborted(f"not valid JSON ({first})") from exc


def stream_objects(
    events: Iterator[tuple[str, str, Any]],
    wanted: Callable[[str], str | None],
    markers: frozenset[str] = frozenset(),
) -> Iterator[tuple[str, Any]]:
    """Yield `(tag, value)` for every JSON value whose prefix `wanted` names, built whole -- and
    nothing else, so memory is bounded by the largest *record*, never by the file. A `markers`
    prefix yields `("marker:<prefix>", None)` each time a value starts there (e.g. "a new run
    began") without collecting it. Scalars at a wanted prefix are yielded directly."""
    builder: ObjectBuilder | None = None
    tag = ""
    depth = 0
    for prefix, event, value in events:
        if builder is None:
            if event in _START:
                if prefix in markers:
                    yield f"marker:{prefix}", None
                found = wanted(prefix)
                if found is not None:
                    builder, tag, depth = ObjectBuilder(), found, 1
                    builder.event(event, value)
            elif event not in _END and event != "map_key":
                found = wanted(prefix)
                if found is not None:
                    yield found, value
            continue
        builder.event(event, value)
        if event in _START:
            depth += 1
        elif event in _END:
            depth -= 1
            if depth == 0:
                yield tag, builder.value
                builder = None


class _Prefixed:
    """A stream with some already-read bytes put back in front of it."""

    def __init__(self, head: bytes, stream: BinaryIO) -> None:
        self._head, self._stream = head, stream

    def read(self, size: int = -1) -> bytes:
        if self._head:
            take = self._head if size < 0 else self._head[:size]
            self._head = self._head[len(take) :]
            return take
        return self._stream.read(size)


_EXTERNAL_DTD = _stdlib_re.compile(rb"<!DOCTYPE[^>\[]*\b(?:SYSTEM|PUBLIC)\b", _stdlib_re.IGNORECASE)


def iter_xml(
    stream: BinaryIO,
    ctx: ParseContext,
    events: tuple[str, ...] = ("start", "end"),
    *,
    allow_dtd: bool = False,
) -> Iterator[tuple[str, Any]]:
    """Streaming XML with DTDs, entities and external references all refused (`defusedxml`: XXE,
    billion laughs, quadratic blowup), plus the same size, depth and time limits as JSON.

    `allow_dtd` is for the one real-world case that needs it: Burp Suite writes an internal
    `<!DOCTYPE issues [<!ELEMENT ...>]>` declaration at the top of every report, so refusing every
    DTD would refuse every real Burp file. It admits *that* and nothing more: entity declarations
    (the whole of what XXE and entity expansion need) and external references stay forbidden, so a
    DOCTYPE that declares an entity or points at an external subset is still an error."""
    limits = ctx.limits
    depth = 0
    count = 0
    if allow_dtd:
        head = stream.read(4096)
        if _EXTERNAL_DTD.search(head):
            raise ParseAborted("XML points at an external DTD, which is refused")
        stream = _Prefixed(head, stream)  # type: ignore[assignment]
    try:
        for event, element in SafeET.iterparse(
            LimitedStream(stream, limits.max_bytes),
            events=events,
            forbid_dtd=not allow_dtd,
            forbid_entities=True,
            forbid_external=True,
        ):
            if event == "start":
                depth += 1
                if depth > limits.max_depth:
                    raise ParseAborted(f"XML nests deeper than {limits.max_depth} levels")
            elif event == "end":
                depth -= 1
            count += 1
            if count % 4096 == 0:
                ctx.check_time()
            yield event, element
    except DefusedXmlException as exc:
        raise ParseAborted(
            f"XML uses a DTD, entity or external reference, which is refused ({exc})"
        ) from exc
    except SafeET.ParseError as exc:
        raise ParseAborted(f"not valid XML ({exc})") from exc


def iter_csv(stream: BinaryIO, ctx: ParseContext) -> Iterator[list[str]]:
    """Rows of a CSV file (UTF-8, with or without a BOM), with the size, time and field-length
    limits enforced while reading, and an unterminated quoted field -- what a file cut off mid-row
    looks like -- an error. The delimiter is `;` or `,`, whichever the header line uses more.

    So is a file whose last row ends on a quoted field, or a delimiter just after one, with no line
    break after it. A cut there reads as a whole row: `..."text",` gains an empty last field, so the
    row is as wide as the header, and `..."text ""quoted` stops between the two quotes of an
    escaped `""`, which reads as a closing one. Exporters that quote fields end every row with a
    line break. An unquoted last row with no line break (`a,b,c`, as some real Tenable exports end)
    cannot be told apart from a cut one and is left alone. Parsers still check row widths."""
    limits = ctx.limits
    csv.field_size_limit(max(csv.field_size_limit(), 16 * 1024 * 1024))
    limited: Any = LimitedStream(stream, limits.max_bytes)  # read() is all the reader needs
    text = codecs.getreader("utf-8-sig")(limited, "replace")
    first = text.readline()
    delimiter = ";" if first.count(";") > first.count(",") else ","
    tail = first  # the last line the reader took: the end of the file once it stops

    def lines() -> Iterator[str]:
        nonlocal tail
        yield first
        for line in text:
            tail = line
            yield line

    reader = csv.reader(lines(), delimiter=delimiter, strict=True)
    try:
        for n, row in enumerate(reader):
            if n % 1024 == 0:
                ctx.check_time()
            yield row
    except csv.Error as exc:
        raise ParseAborted(f"not valid CSV ({exc}); the file may be cut off") from exc
    if tail.removesuffix(delimiter).endswith('"'):
        raise ParseAborted(
            "the last row ends on a quoted field with no line break after it; "
            "the file may be cut off"
        )


class SafePattern:
    """A compiled pattern that never backtracks catastrophically (RE2) and never scans unbounded
    text. Parsers extract identifiers (CWE-89, CVE-2024-1234) from free text in the file; that text
    is attacker-chosen, so the engine and the input length are both bounded."""

    def __init__(self, pattern: str, flags: int = 0) -> None:
        # RE2 takes flags inline ("(?i)"), not as a constant.
        self._re = (
            _re2.compile(("(?i)" if flags & _stdlib_re.IGNORECASE else "") + pattern)
            if _re2 is not None
            else _stdlib_re.compile(pattern, flags)
        )

    def findall(self, text: str) -> list[str]:
        return list(self._re.findall(text[:MAX_REGEX_INPUT]))

    def search(self, text: str) -> Any:
        return self._re.search(text[:MAX_REGEX_INPUT])
