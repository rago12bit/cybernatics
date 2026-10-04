"""OWASP ZAP report import (plan §42.2 order of work #5, ported from DefectDojo's ZAP parser).

Reads both report shapes ZAP writes: the XML report (`OWASPZAPReport`, including the "XML plus
requests and responses" variant) and the JSON report (`-J`, what `zap-baseline.py` produces and
what Bulwark's own DAST campaigns read). Both name the same fields, and both go through
`core.dast.mapping.zap_alert_findings`, the function a native scan uses -- one reading of an alert.

Each `<alertitem>` is handled and released as it ends, so memory is bounded by the largest alert,
not by the report. Unlike DefectDojo's parser (which loads the whole tree), a report cut off
mid-file is an error and never a shorter report: reimport closes whatever a file no longer lists.

Derived in part from DefectDojo's `dojo/tools/zap/parser.py` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any, BinaryIO

from core.dast.mapping import zap_alert_findings
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import iter_xml, json_events, stream_objects
from core.models import Finding

_SITE = "site.item"


def _alert_dict(el: Any) -> dict[str, Any]:
    alert: dict[str, Any] = {}
    for child in el:
        if child.tag == "instances":
            alert["instances"] = [
                {c.tag: c.text or "" for c in inst} for inst in child.findall("instance")
            ]
        else:
            alert[child.tag] = child.text or ""
    return alert


class ZapParser(IngestParser):
    name = "zap"
    label = "OWASP ZAP report"
    formats = frozenset({"xml", "json"})
    categories = frozenset({"dast"})
    ported_from = "dojo/tools/zap/parser.py"
    ported_into = ("core/dast/mapping.py",)

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if text.startswith("<"):
            if "<OWASPZAPReport" in text:
                return 0.99
            return 0.8 if "<alertitem" in text else 0.0
        if text.startswith("{"):
            if re.search(r'"@programName"\s*:\s*"ZAP"', text):
                return 0.99
            # A GitLab DAST report opens with the same `@generated` header (it is ZAP's, merged),
            # but has `vulnerabilities` where ZAP has `site`.
            if '"@generated"' in text and '"site"' in text and '"vulnerabilities"' not in text:
                return 0.7
            return 0.0
        return 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        head = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        stream.seek(0)
        if head.startswith(b"<"):
            yield from self._parse_xml(stream, ctx)
        else:
            yield from self._parse_json(stream, ctx)

    def _parse_xml(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        site = ""
        saw_report = False
        for event, el in iter_xml(stream, ctx):
            if event == "start":
                if el.tag == "OWASPZAPReport":
                    saw_report = True
                elif el.tag == "site":
                    site = el.get("name") or el.get("host") or ""
                continue
            if el.tag == "alertitem":
                yield from zap_alert_findings(_alert_dict(el), site, "zap", ctx.unknown_severity)
                el.clear()
        if not saw_report:
            raise ParseAborted("no <OWASPZAPReport> element; not a ZAP XML report")

    def _parse_json(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        site = ""
        saw_sites = False

        def wanted(prefix: str) -> str | None:
            if prefix == f"{_SITE}.alerts.item":
                return "alert"
            if prefix == f"{_SITE}.@name":
                return "name"
            return None

        for tag, value in stream_objects(json_events(stream, ctx), wanted, frozenset({_SITE})):
            if tag == f"marker:{_SITE}":
                saw_sites, site = True, ""
            elif tag == "name":
                site = str(value)
            elif tag == "alert" and isinstance(value, dict):
                yield from zap_alert_findings(value, site, "zap", ctx.unknown_severity)
        if not saw_sites:
            raise ParseAborted("no `site` list found; not a ZAP JSON report")
