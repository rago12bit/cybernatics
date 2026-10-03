"""OpenVAS / Greenbone report import (plan §42.2 order of work #5, ported from DefectDojo's OpenVAS
parser, version 2): the GMP XML report and the CSV export.

A finding is one NVT (vulnerability test) on one host and port. Where DefectDojo folds results with
the same location, title, NVT and severity, here each result is its own place and ones sharing a
place share an Issue (the fingerprint says so; see `core.dast.mapping`).

What a report says about its own completeness decides whether it may close anything:

* a scan that did not finish (`scan_run_status` other than `Done`: Stopped, Interrupted, ...) has
  only part of its results, so it closes nothing;
* a report with no results and no hosts scanned nothing, so it closes nothing;
* a report exported with a severity filter (`levels=hm`) is missing the levels it hides, which would
  read as "fixed"; it is imported, but says so.

Derived in part from DefectDojo's `dojo/tools/openvas/parser_v2/` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any, BinaryIO

from core.dast.mapping import (
    clip,
    cwe_ids,
    dast_finding,
    network_target,
    severity_of,
)
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import SafePattern, iter_csv, iter_xml
from core.models import Finding

_LEVELS = SafePattern(r"levels=([a-z]+)")
_MAX_REFS = 30


def _float(value: str | None) -> float | None:
    try:
        return float(value) if value else None
    except ValueError:
        return None


def _tags(text: str) -> dict[str, str]:
    """`summary=...|impact=...|cvss_base_vector=...` -> dict (the NVT's `tags` field)."""
    tags: dict[str, str] = {}
    for part in (text or "").strip().split("|"):
        key, sep, value = part.partition("=")
        if sep and value:
            tags[key] = value
    return tags


def _clean(text: str) -> str:
    return (text or "").replace("\n  ", " ").strip()


def _result(
    ctx: ParseContext,
    *,
    oid: str,
    title: str,
    host: str,
    port: str,
    protocol: str,
    threat: str,
    summary: str = "",
    impact: str = "",
    result: str = "",
    qod: str = "",
    solution: str = "",
    cves: list[str] | None = None,
    references: list[str] | None = None,
    cwe: str = "",
    score: float | None = None,
    cvss3: bool = False,
    epss: float | None = None,
) -> Finding:
    place_host, route = network_target(host, port if port.isdigit() else "", protocol or "tcp")
    parts = [
        f"Summary: {clip(_clean(summary), 1_500)}" if summary else "",
        f"Impact: {clip(_clean(impact), 1_500)}" if impact else "",
        f"QoD: {qod}%" if qod else "",
        f"Result:\n{clip(_clean(result), 2_000)}" if result else "",
    ]
    return dast_finding(
        "openvas",
        rule=oid or hashlib.sha256(title.encode()).hexdigest()[:10],
        title=title,
        host=place_host,
        route=route,
        severity=severity_of("openvas", threat or "Info", ctx.unknown_severity),
        native=threat or "Info",
        description="\n\n".join(p for p in parts if p),
        cwe=cwe_ids(cwe),
        cve=[c.strip().upper() for c in (cves or []) if c.strip()],
        summary=_clean(solution),
        references=(references or [])[:_MAX_REFS],
        cvss=score if cvss3 else None,
        epss=epss,
        digest_of=f"{oid}|{place_host}|{route}|{hashlib.sha256(result.encode()).hexdigest()[:8]}",
    )


# --- XML ------------------------------------------------------------------------------------------


def _text(el: Any, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _xml_result(ctx: ParseContext, el: Any) -> Finding:
    nvt = el.find("nvt")
    oid = (nvt.get("oid") or "") if nvt is not None else ""
    title = (_text(nvt, "name") if nvt is not None else "") or _text(el, "name") or oid or "OpenVAS"
    host_el = el.find("host")
    hostname = _text(host_el, "hostname") if host_el is not None else ""
    ip = (host_el.text or "").strip() if host_el is not None and host_el.text else ""
    port_text = _text(el, "port")
    port, _, protocol = port_text.partition("/")
    tags = _tags(_text(nvt, "tags")) if nvt is not None else {}
    refs = nvt.findall("refs/ref") if nvt is not None else []
    vector = tags.get("cvss_base_vector", "")
    return _result(
        ctx,
        oid=oid,
        title=title,
        host=hostname or ip,
        port=port,
        protocol=protocol,
        threat=_text(el, "threat"),
        summary=tags.get("summary", ""),
        impact=tags.get("impact", ""),
        result=_text(el, "description"),
        qod=_text(el.find("qod"), "value") if el.find("qod") is not None else "",
        solution=_text(nvt, "solution") if nvt is not None else "",
        cves=[r.get("id") or "" for r in refs if r.get("type") == "cve"],
        references=[r.get("id") or "" for r in refs if r.get("type") != "cve" and r.get("id")],
        score=_float(_text(el, "severity")),
        cvss3=vector.startswith("CVSS:3"),
    )


# --- CSV ------------------------------------------------------------------------------------------


class OpenVasParser(IngestParser):
    name = "openvas"
    label = "OpenVAS / Greenbone report"
    formats = frozenset({"xml", "csv"})
    categories = frozenset({"dast", "network"})
    ported_from = "dojo/tools/openvas/parser_v2/"
    ported_into = ("core/dast/mapping.py",)

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if text.startswith("<"):
            if "<report" in text and ("<gmp>" in text or "<scan_run_status>" in text):
                return 0.99
            return 0.0
        first = text.splitlines()[0].lower() if text else ""
        return 0.99 if "nvt name" in first and "nvt oid" in first else 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        head = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        stream.seek(0)
        if head.startswith(b"<"):
            yield from self._xml(stream, ctx)
        else:
            yield from self._csv(stream, ctx)

    def _xml(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stack: list[str] = []
        saw_report = False
        results = 0
        status = ""
        hosts: int | None = None
        levels = ""
        for event, el in iter_xml(stream, ctx):
            if event == "start":
                stack.append(el.tag)
                saw_report = saw_report or el.tag == "report"
                continue
            stack.pop()
            parent = stack[-1] if stack else ""
            if el.tag == "result" and parent == "results":
                results += 1
                yield _xml_result(ctx, el)
                el.clear()
            elif el.tag == "scan_run_status":
                status = (el.text or "").strip()
            elif el.tag == "count" and parent == "hosts":
                hosts = int(el.text) if (el.text or "").strip().isdigit() else hosts
            elif el.tag == "term" and parent == "filters":
                match = _LEVELS.search(el.text or "")
                levels = match.group(1) if match else levels
        if not saw_report:
            raise ParseAborted("no <report> element; not a Greenbone/OpenVAS XML report")
        if status and status != "Done":
            self._no_close(
                ctx, f"the scan's status is {status!r}, not Done, so its results are partial"
            )
        elif results == 0 and not hosts:
            self._no_close(ctx, "has no results and scanned no hosts")
        if levels and not set("hml") <= set(levels):
            ctx.warn(
                f"The report was exported with a severity filter (levels={levels}); findings at "
                "the levels it hides are not in the file and will read as fixed"
            )

    def _csv(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        rows = iter_csv(stream, ctx)
        header = next((r for r in rows if any(c.strip() for c in r)), None)
        if header is None:
            raise ParseAborted("the file is empty")
        names = [c.strip().lower() for c in header]
        if "nvt name" not in names:
            raise ParseAborted("no `NVT Name` column; not an OpenVAS CSV export")
        seen = 0
        for number, row in enumerate(rows, start=2):
            if not any(c.strip() for c in row):
                continue
            if len(row) < len(names):
                raise ParseAborted(
                    f"row {number} has {len(row)} fields and the header has {len(names)}; "
                    "the file may be cut off"
                )
            cell = {n: row[i].strip() for i, n in enumerate(names) if n}
            seen += 1
            yield _result(
                ctx,
                oid=cell.get("nvt oid", ""),
                title=cell.get("nvt name", ""),
                host=cell.get("hostname") or cell.get("ip", ""),
                port=cell.get("port", ""),
                protocol=cell.get("port protocol", ""),
                threat=cell.get("severity", ""),
                summary=cell.get("summary", ""),
                impact=cell.get("vulnerability insight", "") or cell.get("impact", ""),
                result=cell.get("specific result", ""),
                qod=cell.get("qod", ""),
                solution=cell.get("solution", ""),
                cves=[c for c in cell.get("cves", "").split(",") if c],
                references=[c for c in cell.get("other references", "").split(",") if c],
                cwe=cell.get("cweid", ""),
                epss=_float(cell.get("max severity epss score")),
            )
        if seen == 0:
            self._no_close(ctx, "has a header and no rows")

    @staticmethod
    def _no_close(ctx: ParseContext, why: str) -> None:
        ctx.can_close_missing = False
        ctx.warn(f"The report {why}; it will not close any Issue")
