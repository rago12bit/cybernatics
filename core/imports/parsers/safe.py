"""Parsing untrusted files safely (plan §42.2): bounded reads, bounded nesting, bounded time, no XML
entity expansion, and regular expressions that cannot backtrack catastrophically.

Everything here exists because a report is attacker-controlled input. `ijson` and `defusedxml` are
the streaming readers; this module wraps them so limits are checked *while* reading, which is the
only point at which a hostile file can still be stopped cheaply.
"""

from __future__ import annotations

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


def iter_xml(
    stream: BinaryIO, ctx: ParseContext, events: tuple[str, ...] = ("start", "end")
) -> Iterator[tuple[str, Any]]:
    """Streaming XML with DTDs, entities and external references all refused (`defusedxml`: XXE,
    billion laughs, quadratic blowup), plus the same size, depth and time limits as JSON."""
    limits = ctx.limits
    depth = 0
    count = 0
    try:
        for event, element in SafeET.iterparse(
            LimitedStream(stream, limits.max_bytes),
            events=events,
            forbid_dtd=True,
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
        raise ParseAborted(f"XML uses a DTD or entity, which is refused ({exc})") from exc
    except SafeET.ParseError as exc:
        raise ParseAborted(f"not valid XML ({exc})") from exc


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
