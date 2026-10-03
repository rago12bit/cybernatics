"""Nessus / Tenable report import (plan §42.2 order of work #5, ported from DefectDojo's Tenable
parser): the `.nessus` XML export (`NessusClientData_v2`) and the CSV exports (Nessus Pro's and
Tenable.io's, whose columns differ but name the same things).

A finding is one plugin on one host and port: its place is `host` + `port/protocol` (see
`core.dast.mapping.network_target`). DefectDojo folds a plugin that fired on fifty hosts into one
finding; here each host is its own Issue, so a plugin fixed on one host closes that host's Issue and
no other.

XML is streamed one `<ReportItem>` at a time. CSV is streamed row by row, and a row with fewer
fields than the header -- what a file cut off mid-line looks like -- is an error, because reimport
closes whatever a file no longer lists.

A report that lists no hosts at all, or a CSV with no rows, scanned nothing; it says nothing about
what was fixed, so it closes nothing.

Derived in part from DefectDojo's `dojo/tools/tenable/` parsers (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from typing import Any, BinaryIO

from core.dast.mapping import (
    clip,
    cwe_ids,
    dast_finding,
    network_target,
    plain_text,
    severity_of,
    target_of,
)
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import SafePattern, iter_csv, iter_xml
from core.models import Finding
from core.scoring.severity import from_cvss

_CVE = SafePattern(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_LEVELS = {"0": "None", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
_NO_SOLUTION = {"n/a", "na", "none", ""}
_MAX_XREFS = 20


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _finding(
    ctx: ParseContext,
    *,
    plugin: str,
    title: str,
    host: str,
    port: str,
    protocol: str,
    label: str,
    synopsis: str,
    description: str,
    output: str,
    solution: str,
    references: list[str],
    cves: list[str],
    cwe: str = "",
    cvss3: float | None = None,
    epss: float | None = None,
    band_severity: bool = False,
) -> Finding:
    severity = severity_of("nessus", label, ctx.unknown_severity)
    if cvss3 is not None and not 0 <= cvss3 <= 10:
        ctx.warn(f"ignored a CVSS v3 base score of {cvss3:g}, which is not between 0 and 10")
        cvss3 = None
    if band_severity and cvss3 is not None:
        severity = from_cvss(cvss3)  # DefectDojo's XML parser lets a v3 score override Nessus's 0-4
    if "://" in host:
        host, route = target_of(host)  # a URL names its own place
    else:
        host, route = network_target(host, port, protocol)
    parts = [
        synopsis,
        f"Description: {clip(description, 2_000)}" if description else "",
        f"Plugin output:\n{clip(output, 2_000)}" if output else "",
    ]
    return dast_finding(
        "nessus",
        rule=plugin or hashlib.sha256(title.encode()).hexdigest()[:10],
        title=title,
        host=host,
        route=route,
        severity=severity,
        native=label,
        description="\n\n".join(p for p in parts if p),
        cwe=cwe_ids(cwe),
        cve=cves,
        summary="" if solution.strip().lower() in _NO_SOLUTION else solution,
        references=references,
        cvss=cvss3,
        epss=epss,
        digest_of=f"{host}|{route}|{plugin}",
    )


# --- XML (.nessus) --------------------------------------------------------------------------------


def _child(item: Any, tag: str) -> str:
    el = item.find(tag)
    return (el.text or "").strip() if el is not None and el.text else ""


def _xml_item(ctx: ParseContext, host: str, item: Any) -> Finding:
    refs: list[str] = []
    for see in item.iter("see_also"):
        refs += (see.text or "").split()
    refs += [clip((x.text or "").strip(), 200) for x in item.iter("xref")][:_MAX_XREFS]
    cves = [(c.text or "").strip().upper() for c in item.iter("cve") if (c.text or "").strip()]
    return _finding(
        ctx,
        plugin=item.get("pluginID") or "",
        title=item.get("pluginName") or item.get("pluginID") or "Nessus finding",
        host=host,
        port=item.get("port") or "",
        protocol=item.get("protocol") or "tcp",
        label=_LEVELS.get(item.get("severity") or "0", item.get("severity") or "0"),
        synopsis=_child(item, "synopsis"),
        description=plain_text(_child(item, "description")),
        output=_child(item, "plugin_output"),
        solution=_child(item, "solution"),
        references=refs,
        cves=cves,
        cwe=_child(item, "cwe"),
        cvss3=_float(_child(item, "cvss3_base_score")),
        band_severity=True,
    )


# --- CSV ------------------------------------------------------------------------------------------

# Nessus Pro and Tenable.io name the same columns differently; each tuple is one field, in the order
# DefectDojo prefers them. Lower-case, because exports differ in case too.
_COLUMNS = {
    "title": ("name", "plugin name", "definition.name", "asset.name"),
    "plugin": ("plugin id", "plugin", "definition.id"),
    "severity": ("risk", "severity"),
    "host": ("host", "asset.host_name", "dns name", "ip address"),
    "port": ("port", "asset.port"),
    "protocol": ("protocol",),
    "synopsis": ("synopsis", "definition.synopsis"),
    "description": ("description", "definition.description"),
    "solution": ("solution", "definition.solution", "steps to remediate"),
    "see_also": ("see also", "definition.see_also"),
    "output": ("plugin output", "output", "plugin text"),
    "cve": ("cve", "definition.cve"),
    "cvss3": (
        "cvssv3",
        "definition.cvss3.base_score",
        "cvss v3.0 base score",
        "cvss v3 base score",
    ),
    "epss": ("epss score",),
}


class _Row:
    def __init__(self, header: list[str], row: list[str]) -> None:
        index = {name.strip().lower(): i for i, name in enumerate(header)}
        self._cells = {name: row[i].strip() for name, i in index.items() if i < len(row)}

    def get(self, field: str) -> str:
        for name in _COLUMNS[field]:
            if self._cells.get(name):
                return self._cells[name]
        return ""


def _epss(raw: str) -> float | None:
    # Some exports write 0.1234 as "1234" (DefectDojo reads it the same way).
    return _float(raw if "0." in raw else "0." + raw) if raw else None


class NessusParser(IngestParser):
    name = "nessus"
    label = "Nessus / Tenable report"
    formats = frozenset({"xml", "csv"})
    categories = frozenset({"dast", "network"})
    ported_from = "dojo/tools/tenable/"
    ported_into = ("core/dast/mapping.py",)

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if text.startswith("<"):
            return 0.99 if "<NessusClientData_v2" in text else 0.0
        first = text.splitlines()[0].lower() if text else ""
        names = {n.strip(' "') for n in first.replace(";", ",").split(",")}
        if {"definition.id", "definition.name"} <= names:
            return 0.95  # a Tenable.io export
        has_plugin = bool(names & {"plugin id", "plugin", "plugin name"})
        has_host = bool(names & {"host", "ip address", "asset.host_name", "asset.name"})
        if {"plugin id", "host", "risk"} <= names or {
            "plugin",
            "plugin name",
            "ip address",
        } <= names:
            return 0.99
        return (
            0.9 if has_plugin and has_host and ("name" in names or "plugin name" in names) else 0.0
        )

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        head = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        stream.seek(0)
        if head.startswith(b"<"):
            yield from self._xml(stream, ctx)
        else:
            yield from self._csv(stream, ctx)

    def _xml(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        saw_root = False
        host = ""
        hosts = 0
        for event, el in iter_xml(stream, ctx):
            if event == "start":
                if el.tag == "NessusClientData_v2":
                    saw_root = True
                elif el.tag == "ReportHost":
                    host, hosts = (el.get("name") or "").strip(), hosts + 1
                continue
            if el.tag == "ReportItem":
                if host:
                    yield _xml_item(ctx, host, el)
                el.clear()
            elif el.tag == "ReportHost":
                el.clear()
        if not saw_root:
            raise ParseAborted(
                "not a NessusClientData_v2 document; other Nessus export versions are not supported"
            )
        if hosts == 0:
            self._scanned_nothing(ctx, "lists no hosts")

    def _csv(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        rows = iter_csv(stream, ctx)
        header = next((r for r in rows if any(c.strip() for c in r)), None)
        if header is None:
            raise ParseAborted("the file is empty")
        names = {c.strip().lower() for c in header}
        if not names & (set(_COLUMNS["title"]) | set(_COLUMNS["plugin"])):
            raise ParseAborted("no `Name` or `Plugin Name` column; not a Nessus or Tenable CSV")
        seen = 0
        for number, row in enumerate(rows, start=2):
            if not any(c.strip() for c in row):
                continue
            if len(row) < len(header):
                raise ParseAborted(
                    f"row {number} has {len(row)} fields and the header has {len(header)}; "
                    "the file may be cut off"
                )
            r = _Row(header, row)
            title = r.get("title")
            if not title:
                continue
            seen += 1
            cve_text = r.get("cve")
            yield _finding(
                ctx,
                plugin=r.get("plugin"),
                title=title,
                host=r.get("host") or "localhost",
                port=r.get("port"),
                protocol=r.get("protocol") or "tcp",
                label=_LEVELS.get(r.get("severity"), r.get("severity") or "None"),
                synopsis=r.get("synopsis"),
                description=r.get("description"),
                output=r.get("output"),
                solution=r.get("solution"),
                references=[*r.get("see_also").split()],
                cves=list(dict.fromkeys(c.upper() for c in _CVE.findall(cve_text))),
                cvss3=_float(r.get("cvss3")),
                epss=_epss(r.get("epss")),
            )
        if seen == 0:
            self._scanned_nothing(ctx, "has a header and no rows")

    @staticmethod
    def _scanned_nothing(ctx: ParseContext, why: str) -> None:
        ctx.can_close_missing = False
        ctx.warn(
            f"The report {why}, so it scanned nothing: that says nothing about what was fixed, and "
            "it will not close any Issue"
        )
