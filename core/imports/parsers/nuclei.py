"""Nuclei results import (plan §42.2 order of work #5, ported from DefectDojo's Nuclei parser).

Nuclei writes one JSON object per line (`-jsonl`, the default for `-o`) or, with `-json-export`, one
JSON array. Both are streamed a record at a time and both go through
`core.dast.mapping.nuclei_finding`, the function a native DAST campaign uses.

An *empty* file is the one input this parser will not let close anything. Nuclei writes an empty
file when it finds nothing, but an empty upload is also exactly what a failed export or a cut-off
transfer looks like, and reimport closes whatever a file no longer lists. So an empty file imports
nothing and closes nothing, and says so; an explicit empty array (`[]`) is unambiguous and does
close.

Derived in part from DefectDojo's `dojo/tools/nuclei/parser.py` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Iterator
from typing import Any, BinaryIO

from core.dast.mapping import nuclei_finding
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import LimitedStream, json_events, stream_objects
from core.models import Finding

_MARKERS = re.compile(r'"(?:template-id|templateID|template_id|matched-at|matcher-name)"')
_CHUNK = 1024 * 1024


def _records(line: bytes, ctx: ParseContext) -> Iterator[dict[str, Any]]:
    """The one JSON object on a line, read with the depth and time limits enforced."""
    found = False
    for _tag, value in stream_objects(
        json_events(io.BytesIO(line), ctx), lambda p: "rec" if p == "" else None
    ):
        found = True
        if isinstance(value, dict):
            yield value
    if not found:
        raise ParseAborted("a line is not a JSON object")


class NucleiParser(IngestParser):
    name = "nuclei"
    label = "Nuclei results"
    formats = frozenset({"jsonl", "json"})
    categories = frozenset({"dast"})
    ported_from = "dojo/tools/nuclei/parser.py"
    ported_into = ("core/dast/mapping.py",)

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith(("{", "[")) or '"info"' not in text:
            return 0.0
        if not _MARKERS.search(text):
            return 0.0
        return 0.95 if text.startswith("{") else 0.9

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        head = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        stream.seek(0)
        if not head:
            ctx.can_close_missing = False
            ctx.warn(
                "The file is empty. Nuclei writes an empty file when it finds nothing, but an "
                "empty upload also looks like a failed export, so nothing was imported and nothing "
                "will be closed. To record a clean run, export JSON (-json-export), which writes []"
            )
            return
        if head.startswith(b"["):
            yield from self._array(stream, ctx)
        else:
            yield from self._lines(stream, ctx)

    def _array(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        for _tag, value in stream_objects(
            json_events(stream, ctx), lambda p: "rec" if p == "item" else None
        ):
            if isinstance(value, dict):
                yield from self._one(value, json.dumps(value, sort_keys=True), ctx)

    def _lines(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        limited = LimitedStream(stream, ctx.limits.max_bytes)
        pending = b""
        while True:
            chunk = limited.read(_CHUNK)
            pending += chunk
            *lines, pending = pending.split(b"\n") if chunk else (*pending.split(b"\n"), b"")
            for line in lines:
                if line.strip():
                    for rec in _records(line, ctx):
                        yield from self._one(rec, line.decode("utf-8", "replace").strip(), ctx)
            ctx.check_time()
            if not chunk:
                return

    @staticmethod
    def _one(rec: dict[str, Any], raw: str, ctx: ParseContext) -> Iterator[Finding]:
        finding = nuclei_finding(rec, raw, on_unknown=ctx.unknown_severity)
        if finding is None:
            ctx.warn("a record without an `info` section was skipped; it is not a Nuclei result")
        else:
            yield finding
