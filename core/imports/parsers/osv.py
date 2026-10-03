"""OSV-Scanner results import (plan §42.2, order of work #3).

This is the JSON `osv-scanner` writes (`results[].packages[].vulnerabilities`), which names the
installed version of each affected package. A bare OSV *advisory* record (`{"id": ..., "affected":
[...]}`) is not a scan result: it says which versions are vulnerable, not which one anyone runs, so
it is not importable as findings (matching advisories to inventories is the advisory engine's job).

Each lockfile's result is mapped by `OsvScannerAdapter.result_findings`, the function a native scan
uses, so there is one reading of this format.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import BinaryIO

from core.adapters.osv_scanner import OsvScannerAdapter
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext
from core.imports.parsers.safe import json_events, stream_objects
from core.models import Finding

_ADAPTER = OsvScannerAdapter()


class OsvParser(IngestParser):
    name = "osv"
    label = "OSV-Scanner results"
    formats = frozenset({"json"})
    categories = frozenset({"sca"})

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith("{") or '"results"' not in text:
            return 0.0
        if '"source"' in text and '"packages"' in text:
            return 0.95
        if re.search(r'"results"\s*:\s*\[\s*\]', text):
            return 0.6  # an empty results list: plausible, but could be anything
        return 0.5 if '"source"' in text else 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        seen_results = False
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "result" if p == "results.item" else None,
            frozenset({"results"}),
        ):
            if tag == "marker:results":
                seen_results = True
            elif tag == "result":
                yield from _ADAPTER.result_findings(value)
        if not seen_results:
            raise ParseAborted("no `results` list found; not OSV-Scanner output")
