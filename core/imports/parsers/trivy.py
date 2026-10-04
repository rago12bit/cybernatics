"""Trivy JSON import (plan §42.2 order of work #5, ported from DefectDojo's Trivy parser): image,
filesystem and repository reports (`Results[]`), Kubernetes reports (`Resources[].Results[]`) and
the old top-level-list layout.

Each result block is read by `TrivyAdapter.result_findings`, the function a native scan uses:
vulnerabilities (SCA), misconfigurations (IaC, or Dockerfile -> container) and secrets. Licence
findings are not imported (a licence is not a vulnerability); the report says how many it left out.

A report with no `Results` at all is a clean scan if it carries Trivy's own header (`SchemaVersion`
or `ArtifactName`), and an error if it does not. The bare `null` that old Trivy wrote for a scan
with nothing to report is read as that clean scan.

Derived in part from DefectDojo's `dojo/tools/trivy/parser.py` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import BinaryIO

from core.adapters.trivy import TrivyAdapter
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import json_events, stream_objects
from core.models import Finding

_ADAPTER = TrivyAdapter()
_HEADER = frozenset({"SchemaVersion", "ArtifactName", "ArtifactType", "ClusterName"})


class TrivyParser(IngestParser):
    name = "trivy"
    label = "Trivy JSON report"
    formats = frozenset({"json"})
    categories = frozenset({"sca", "iac", "container", "secrets"})
    default_dedup = "package"
    ported_from = "dojo/tools/trivy/parser.py"

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if text.startswith("{"):
            if '"SchemaVersion"' in text and ('"ArtifactName"' in text or '"Results"' in text):
                return 0.99
            if '"ClusterName"' in text:
                return 0.95
            return 0.0
        if (
            text.startswith("[")
            and '"Target"' in text
            and ('"Vulnerabilities"' in text or '"Misconfigurations"' in text)
        ):
            return 0.9  # the old layout: a bare list of result blocks
        return 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        head = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        stream.seek(0)
        as_list = head.startswith(b"[")
        if head.strip() == b"null":
            return  # what old Trivy wrote for a scan with nothing to report
        # `Results` (image, filesystem, repository); `Resources[].Results` (kubernetes, newer);
        # `Vulnerabilities[].Results` and `Misconfigurations[].Results` (kubernetes, older).
        nested = ("Resources", "Vulnerabilities", "Misconfigurations")
        blocks = (
            ("item",) if as_list else ("Results.item", *(f"{n}.item.Results.item" for n in nested))
        )
        markers = frozenset(
            {""} if as_list else {"Results", *(f"{n}.item.Results" for n in nested)}
        )

        def wanted(prefix: str) -> str | None:
            if prefix in blocks:
                return "res"
            if not as_list and prefix in _HEADER:
                return "header"
            return None

        seen_misconfigs: set[tuple[str, str, int, int, str]] = set()
        saw = as_list
        licences = skipped = 0
        for tag, value in stream_objects(json_events(stream, ctx), wanted, markers):
            if tag.startswith("marker:") or tag == "header":
                saw = True
                continue
            if not isinstance(value, dict):
                continue
            licences += len(value.get("Licenses") or [])
            try:
                yield from _ADAPTER.result_findings(value, seen_misconfigs)
            except (KeyError, TypeError, AttributeError, ValueError):
                skipped += 1
        if not saw:
            raise ParseAborted("no Trivy header or `Results`; not a Trivy JSON report")
        if skipped:
            ctx.warn(f"{skipped} result block(s) were malformed and skipped")
        if licences:
            ctx.warn(f"{licences} licence finding(s) were not imported (not a vulnerability)")
