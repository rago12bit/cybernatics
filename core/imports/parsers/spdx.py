"""SPDX import, JSON (plan §42.2, order of work #2).

SPDX is an inventory format: it lists packages, files and relationships, and says nothing about
vulnerabilities. So an SPDX file yields **no findings and cannot close any** -- importing one must
never read as "these packages are clean." It is still recognised and validated, and the import says
what it found, so that picking the wrong format or uploading the wrong file is visible rather than
a silent empty import. Turning the package list into a searchable inventory is the component
inventory work (plan Week 67); until then this is deliberately all it does.

Only SPDX 2.x JSON is read. Tag-value, RDF/XML, YAML and SPDX 3.0 JSON-LD are not.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import BinaryIO

from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext
from core.imports.parsers.safe import json_events, stream_objects
from core.models import Finding


class SpdxParser(IngestParser):
    name = "spdx"
    label = "SPDX 2.x (JSON)"
    formats = frozenset({"json"})
    categories = frozenset({"sca"})

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if text.startswith("{") and re.search(r'"spdxVersion"\s*:\s*"SPDX-2', text):
            return 0.99
        return 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        version = ""
        packages = 0
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "version" if p == "spdxVersion" else None,
            frozenset({"packages.item"}),
        ):
            if tag == "version":
                version = str(value)
            elif tag == "marker:packages.item":
                packages += 1
        if not version.startswith("SPDX-"):
            raise ParseAborted("no spdxVersion found; not an SPDX document")
        ctx.can_close_missing = False
        ctx.warn(
            f"{version} file with {packages} packages and no vulnerability data: nothing to import "
            "as findings, and it cannot close any (a package list does not say the packages are "
            "free of vulnerabilities)"
        )
        return
        yield  # pragma: no cover - makes this a generator that yields nothing
