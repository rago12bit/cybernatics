"""SPDX import, JSON (plan §42.2, order of work #2).

SPDX is an inventory format: it lists packages, files and relationships, and says nothing about
vulnerabilities. So an SPDX file yields **no findings and cannot close any** -- importing one must
never read as "these packages are clean." It is still recognised and validated, and the import says
what it found, so that picking the wrong format or uploading the wrong file is visible rather than
a silent empty import. Each package with a purl (an `externalRefs` entry of type `purl`) goes to the
component inventory (plan §46.1), where "where do we use this?" finds it.

Only SPDX 2.x JSON is read. Tag-value, RDF/XML, YAML and SPDX 3.0 JSON-LD are not.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, BinaryIO

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
            lambda p: {"spdxVersion": "version", "packages.item": "package"}.get(p),
        ):
            if tag == "version":
                version = str(value)
            elif tag == "package":
                packages += 1
                if isinstance(value, dict):
                    _inventory(ctx, value)
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


def _inventory(ctx: ParseContext, package: dict[str, Any]) -> None:
    for ref in package.get("externalRefs") or []:
        if isinstance(ref, dict) and str(ref.get("referenceType", "")).lower() == "purl":
            locator, version = ref.get("referenceLocator"), package.get("versionInfo")
            ctx.component(str(locator or ""), str(version or ""))
            return
