"""SARIF 2.1.0 import (plan §42.2, order of work #1: "already canonical, §3").

Streams `runs[].results[]` so memory is bounded by the largest result, not the report. It reads the
file twice -- rule metadata first, then results -- because SARIF does not say which a file lists
first, and a result needs its rule's tags, default level and help link. Uploads are seekable, so the
second pass costs time, not memory.

Normalisation is `core.sarif.result_to_finding`, the same function native scans use: an uploaded
Semgrep SARIF and a Semgrep scan Bulwark ran itself cannot disagree about what a result means.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, BinaryIO

from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import json_events, stream_objects
from core.models import Category, Finding
from core.sarif import result_to_finding
from core.scoring.severity import MATRIX

_RUN = "runs.item"
_SECRET_TOOLS = frozenset({"gitleaks", "trufflehog", "detect-secrets"})
_MARKERS = frozenset({_RUN})


def _tool_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-")[:40] or "sarif"


class SarifParser(IngestParser):
    name = "sarif"
    label = "SARIF 2.1.0"
    formats = frozenset({"json"})
    categories = frozenset({"sast", "secrets"})

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith("{") or '"runs"' not in text:
            return 0.0
        if re.search(r'"\$schema"\s*:\s*"[^"]*sarif', text, re.IGNORECASE):
            return 0.99
        if re.search(r'"version"\s*:\s*"2\.1\.0"', text):
            return 0.95
        return 0.5  # has "runs" but nothing says it is SARIF

    def _read_metadata(
        self, stream: BinaryIO, ctx: ParseContext
    ) -> tuple[list[dict[str, dict[str, Any]]], list[list[dict[str, Any]]], list[str]]:
        """Per run: rules by id, rules in file order (a result may refer to one by index), and the
        tool's name."""
        by_id: list[dict[str, dict[str, Any]]] = []
        ordered: list[list[dict[str, Any]]] = []
        names: list[str] = []

        def wanted(prefix: str) -> str | None:
            if prefix == f"{_RUN}.tool.driver.rules.item":
                return "rule"
            if prefix == f"{_RUN}.tool.driver.name":
                return "name"
            return None

        for tag, value in stream_objects(json_events(stream, ctx), wanted, _MARKERS):
            if tag == f"marker:{_RUN}":
                by_id.append({})
                ordered.append([])
                names.append("")
            elif tag == "rule" and isinstance(value, dict):
                ordered[-1].append(value)
                if "id" in value:
                    by_id[-1][str(value["id"])] = value
            elif tag == "name":
                names[-1] = str(value)
        if not by_id:
            raise ParseAborted("no SARIF runs found")
        return by_id, ordered, names

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        by_id, ordered, names = self._read_metadata(stream, ctx)
        stream.seek(0)

        run = -1
        total = skipped = 0
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "result" if p == f"{_RUN}.results.item" else None,
            _MARKERS,
        ):
            if tag == f"marker:{_RUN}":
                run += 1
                continue
            if not isinstance(value, dict):
                continue
            total += 1
            rules = by_id[run]
            if "ruleId" not in value and "rule" not in value:
                # A result may name its rule only by position in the driver's rule list.
                idx = value.get("ruleIndex")
                if isinstance(idx, int) and 0 <= idx < len(ordered[run]):
                    value["ruleId"] = ordered[run][idx].get("id")
            tool = _tool_slug(names[run])
            category = Category.SECRETS if tool in _SECRET_TOOLS else Category.SAST
            finding = result_to_finding(
                value,
                rules,
                tool,
                category,
                severity_tool=tool if tool in MATRIX else "sarif",
                use_security_severity=True,
            )
            if finding is None:
                skipped += 1
                continue
            yield finding
        if skipped:
            ctx.warn(f"{skipped} of {total} results had no usable rule or file and were skipped")
