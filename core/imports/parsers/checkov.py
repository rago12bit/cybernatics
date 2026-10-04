"""Checkov JSON import (plan §42.2 order of work #5, ported from DefectDojo's Checkov parser): the
`checkov -o json` report, one framework's object or the list Checkov writes when several ran
(`terraform`, `dockerfile`, ...).

Each failed check is read by `CheckovAdapter.to_finding`, the function a native scan uses. Passed
and skipped checks are not findings. A report with an empty `failed_checks` is a clean scan.

Derived in part from DefectDojo's `dojo/tools/checkov/parser.py` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import BinaryIO

from core.adapters.checkov import CheckovAdapter
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import json_events, stream_objects
from core.models import Finding

_ADAPTER = CheckovAdapter()


class CheckovParser(IngestParser):
    name = "checkov"
    label = "Checkov JSON report"
    formats = frozenset({"json"})
    categories = frozenset({"iac"})
    ported_from = "dojo/tools/checkov/parser.py"

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith(("{", "[")):
            return 0.0
        if '"check_type"' in text and '"results"' in text:
            return 0.99
        if '"failed_checks"' in text or ('"resourcecount"' in text and '"checkov_version"' in text):
            return 0.9
        return 0.0

    @staticmethod
    def _summary_only(stream: BinaryIO) -> bool:
        stream.seek(0)
        head = stream.read(2048).decode("utf-8", "ignore")
        return all(f'"{k}"' in head for k in ("passed", "failed", "resourcecount")) and (
            '"results"' not in head
        )

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        head = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        stream.seek(0)
        base = "item." if head.startswith(b"[") else ""
        results = f"{base}results"
        saw = False
        skipped = 0
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "check" if p == f"{results}.failed_checks.item" else None,
            frozenset({f"{results}.failed_checks"}),
        ):
            if tag.startswith("marker:"):
                saw = True
            elif isinstance(value, dict):
                try:
                    yield _ADAPTER.to_finding(value)
                except (KeyError, TypeError, ValueError, IndexError, AttributeError):
                    skipped += 1
        if not saw:
            if self._summary_only(stream):
                # Checkov 2 writes just its counters when it found nothing to scan.
                ctx.can_close_missing = False
                ctx.warn("The report holds only Checkov's counters (no resources were scanned)")
                return
            raise ParseAborted("no `results.failed_checks` list; not a Checkov JSON report")
        if skipped:
            ctx.warn(f"{skipped} failed check(s) were malformed and skipped")
