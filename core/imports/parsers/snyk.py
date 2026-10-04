"""Snyk JSON import (plan §42.2 order of work #5, ported from DefectDojo's Snyk parser): the output
of `snyk test --json` for Open Source and Container projects, one project or a list of them
(`--all-projects`).

Snyk writes a project's own details (`displayTargetFile`, `projectName`, `packageManager`) *after*
its vulnerabilities, so the file is read twice, as SARIF is: project details first, then the
vulnerabilities, one at a time. Severity follows the CVSS score when there is one (the FIRST bands,
as DefectDojo does) and Snyk's own word when there is not (licence issues carry no score).

Snyk Code produces SARIF; upload that with the `sarif` parser.

Derived in part from DefectDojo's `dojo/tools/snyk/parser.py` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, BinaryIO

from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import json_events, stream_objects
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Package,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)
from core.scoring.severity import from_cvss, normalize

_ECOSYSTEM = {
    "gomodules": "go", "golangdep": "go", "govendor": "go", "cocoapods": "cocoapods",
    "hex": "hex", "pub": "pub", "sbt": "maven", "paket": "nuget",
}  # fmt: skip
_META = ("displayTargetFile", "projectName", "packageManager", "path")


def _strings(v: Any) -> list[str]:
    return [str(x) for x in v] if isinstance(v, list) else ([str(v)] if v else [])


def vulnerability_finding(
    vuln: dict[str, Any], project: dict[str, str], ctx: ParseContext
) -> Finding:
    vid, name, version = str(vuln["id"]), str(vuln["packageName"]), str(vuln["version"])
    word = str(vuln.get("severity") or "")
    score = vuln.get("cvssScore")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        severity = from_cvss(float(score))
    else:
        severity = normalize("snyk", word, Severity.INFO)
        if word.strip().upper() not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            ctx.unknown_severity(word)
    raw_ids = vuln.get("identifiers")
    identifiers: dict[str, Any] = raw_ids if isinstance(raw_ids, dict) else {}
    cves = [c.upper() for c in _strings(identifiers.get("CVE"))]
    ghsa = _strings(identifiers.get("GHSA"))
    cwes = tuple(
        c if c.upper().startswith("CWE-") else f"CWE-{c}" for c in _strings(identifiers.get("CWE"))
    )
    manager = project.get("packageManager", "")
    eco = _ECOSYSTEM.get(manager.lower()) or Package.normalize_ecosystem(manager or "unknown")
    path = project.get("displayTargetFile") or project.get("projectName") or "unknown"
    chain = " > ".join(_strings(vuln.get("from")))
    upgrade = [u for u in _strings(vuln.get("upgradePath")) if u and u != "false"]
    fixed = _strings(vuln.get("fixedIn"))
    summary = (
        f"Upgrade to {upgrade[-1]}." if upgrade
        else f"Fixed in {', '.join(fixed)}." if fixed else ""
    )  # fmt: skip
    epss = (
        (vuln.get("epssDetails") or {}).get("probability")
        if isinstance(vuln.get("epssDetails"), dict)
        else None
    )
    detail = [
        f"Vulnerable path: {chain}" if chain else "",
        str(vuln.get("description") or "")[:4000],
    ]
    snippet = f"{name}@{version}"
    return Finding(
        id=f"snyk:{vid}:{path}:{snippet}",
        title=f"{name} {version}: {vuln.get('title') or vid}"[:300],
        description="\n\n".join(d for d in detail if d) or vid,
        location=Location(path, 1, 1, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(
            Category.SCA,
            cwe=cwes,
            cve=tuple(cves),
            aliases=tuple(dict.fromkeys([vid, *cves, *ghsa])),
        ),
        scoring=Scoring(
            native_severity={"snyk": word.upper()},
            normalized_severity=severity,
            cvss_v3_1=(
                float(score)
                if isinstance(score, (int, float))
                and not isinstance(score, bool)
                and vuln.get("CVSSv3")
                else None
            ),
            epss_score=float(epss) if isinstance(epss, (int, float)) else None,
            confidence=0.9,
        ),
        evidence=Evidence(reported_by=["snyk"], rule_ids={"snyk": [vid]}),
        remediation=Remediation(summary=summary, references=[]),
        package=Package(name, version, eco),
    )


class SnykParser(IngestParser):
    name = "snyk"
    label = "Snyk JSON report"
    formats = frozenset({"json"})
    categories = frozenset({"sca", "container"})
    default_dedup = "package"
    ported_from = "dojo/tools/snyk/parser.py"

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith(("{", "[")):
            return 0.0
        if '"vulnerabilities"' in text and '"packageName"' in text:
            return 0.95
        if (
            '"vulnerabilities"' in text
            and ('"dependencyCount"' in text or '"packageManager"' in text)
            and ('"ok"' in text)
        ):
            return 0.9
        return 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        head = stream.read(4096).lstrip(b"\xef\xbb\xbf \t\r\n")
        stream.seek(0)
        base = "item" if head.startswith(b"[") else ""
        dot = f"{base}." if base else ""
        project_marker = frozenset({base})

        def meta_wanted(prefix: str) -> str | None:
            return (
                f"meta:{prefix[len(dot):]}"
                if prefix.startswith(dot) and prefix[len(dot) :] in _META
                else None
            )

        projects: list[dict[str, str]] = []
        for tag, value in stream_objects(json_events(stream, ctx), meta_wanted, project_marker):
            if tag.startswith("marker:"):
                projects.append({})
            elif tag.startswith("meta:") and projects:
                projects[-1][tag[5:]] = str(value)
        if not projects:
            raise ParseAborted("no Snyk project found; not a `snyk test --json` report")
        stream.seek(0)

        index = -1
        seen_vulns = False
        skipped = 0
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "vuln" if p == f"{dot}vulnerabilities.item" else None,
            project_marker,
        ):
            if tag.startswith("marker:"):
                index += 1
            elif isinstance(value, dict):
                seen_vulns = True
                try:
                    yield vulnerability_finding(value, projects[max(index, 0)], ctx)
                except (KeyError, TypeError, ValueError):
                    skipped += 1
        if skipped:
            ctx.warn(f"{skipped} vulnerability record(s) were malformed and skipped")
        if not seen_vulns and not any(
            "packageManager" in p or "displayTargetFile" in p for p in projects
        ):
            raise ParseAborted("no `vulnerabilities` list; not a `snyk test --json` report")
