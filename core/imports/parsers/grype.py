"""Grype JSON import (plan §42.2 order of work #5, ported from DefectDojo's Anchore Grype parser).

Streams `matches[]`. Each match is read by `GrypeAdapter.to_finding`, the function a native scan
uses, so a Grype report uploaded and a Grype scan Bulwark ran cannot disagree about a match. Grype
reports one match per package location; the Issue's identity is package, version and vulnerability
(ADR-0004), so the same vulnerability in the same package found at two paths is one Issue, which is
also how DefectDojo folds them.

Derived in part from DefectDojo's `dojo/tools/anchore_grype/parser.py` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import BinaryIO

from core.adapters.grype import GrypeAdapter
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext
from core.imports.parsers.safe import json_events, stream_objects
from core.models import Finding

_ADAPTER = GrypeAdapter()


class GrypeParser(IngestParser):
    name = "grype"
    label = "Grype JSON report"
    formats = frozenset({"json"})
    categories = frozenset({"sca", "container"})
    ported_from = "dojo/tools/anchore_grype/parser.py"

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith("{") or '"matches"' not in text:
            return 0.0
        if re.search(r'"descriptor"\s*:\s*\{\s*"name"\s*:\s*"grype"', text):
            return 0.99
        return 0.95 if '"artifact"' in text and '"vulnerability"' in text else 0.5

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        seen = False
        skipped = 0
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "match" if p == "matches.item" else None,
            frozenset({"matches"}),
        ):
            if tag == "marker:matches":
                seen = True
            elif isinstance(value, dict):
                try:
                    finding = _ADAPTER.to_finding(value)
                except (KeyError, TypeError, ValueError, IndexError, AttributeError):
                    skipped += 1
                    continue
                if finding is not None:
                    yield finding
        if not seen:
            raise ParseAborted("no `matches` list found; not a Grype JSON report")
        if skipped:
            ctx.warn(f"{skipped} match(es) were malformed and skipped")
