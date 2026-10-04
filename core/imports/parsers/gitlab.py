"""GitLab security report import (plan §42.2 order of work #5, ported from DefectDojo's GitLab SAST,
dependency scanning, container scanning, secret detection and DAST parsers).

GitLab's reports share one schema (`vulnerabilities[]`), and what a record *is* shows in its
location: a `dependency` is a package (SCA, or a container image's package), a `hostname` is a web
target (DAST, API fuzzing), a commit or `raw_source_code_extract` is a secret, a `file` with
lines is code (SAST). That is what is read, not a declared report type, because v15 reports leave
`category` and `scan` out. Coverage-fuzzing crashes have no place in code or on the web and are
skipped (and counted in the warnings).

GitLab's `id` is not used as identity (it is a hash GitLab recomputes); a finding is where it is and
what rule it broke. A severity of Unknown or Undefined is Info, and the title says so, as DefectDojo
does. `scan.type` and `dependency_files` come after the vulnerabilities in the file, so it is read
twice.

Derived in part from DefectDojo's `dojo/tools/gitlab_*` parsers (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any, BinaryIO

from core.dast.mapping import clip, cwe_ids, dast_finding, plain_text, severity_of, target_of
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.safe import SafePattern, json_events, stream_objects
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Package,
    Remediation,
    Scoring,
    Taxonomy,
)

_BY_MANAGER = {
    "bundler": "rubygems",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "pip": "pypi",
    "pipenv": "pypi",
    "poetry": "pypi",
    "setuptools": "pypi",
    "maven": "maven",
    "gradle": "maven",
    "sbt": "maven",
    "go": "go",
    "composer": "packagist",
    "nuget": "nuget",
    "cargo": "cargo",
    "conan": "conan",
    "conda": "conda",
    "pub": "pub",
    "swift": "swift",
    "cocoapods": "cocoapods",
}
_BY_FILE = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "gemfile.lock": "rubygems",
    "pipfile.lock": "pypi",
    "poetry.lock": "pypi",
    "requirements.txt": "pypi",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "go.sum": "go",
    "go.mod": "go",
    "composer.lock": "packagist",
    "packages.lock.json": "nuget",
    "cargo.lock": "cargo",
}
_IDENTIFIER_LIST = SafePattern(r'"identifiers"\s*:\s*\[')
_META = {"scan.type": "type", "scan.scanner.name": "scanner", "dependency_files.item": "file"}
_NOT_A_RULE = {"cwe", "cve", "owasp", "wasc", "ghsa", "osvdb", "usn", "rhsa", "elsa", "dsa", "cert"}
_UNSET = {"", "undefined", "unknown"}


def _strings(v: Any) -> list[str]:
    return [str(x) for x in v] if isinstance(v, list) else ([str(v)] if v else [])


def _identifiers(vuln: dict[str, Any]) -> list[dict[str, Any]]:
    return [i for i in vuln.get("identifiers") or [] if isinstance(i, dict)]


def _rule(vuln: dict[str, Any], title: str) -> str:
    ids = _identifiers(vuln)
    for i in ids:
        if str(i.get("type", "")).lower() not in _NOT_A_RULE and i.get("value"):
            return str(i["value"])
    return title


def _ecosystem(path: str, managers: dict[str, str]) -> str:
    manager = managers.get(path, "")
    return (
        _BY_MANAGER.get(manager.lower())
        or _BY_FILE.get(PurePosixPath(path).name.lower())
        or Package.normalize_ecosystem(manager or "unknown")
    )


def vulnerability_finding(
    vuln: dict[str, Any], scan: dict[str, str], managers: dict[str, str], ctx: ParseContext
) -> Finding | None:
    raw_loc = vuln.get("location")
    loc: dict[str, Any] = raw_loc if isinstance(raw_loc, dict) else {}
    ids = _identifiers(vuln)
    raw_id = str(vuln.get("id") or vuln.get("cve") or "")
    ids0 = _identifiers(vuln)
    first_cve = next(
        (
            str(i["value"])
            for i in ids0
            if str(i.get("type", "")).lower() == "cve" and i.get("value")
        ),
        "",
    )
    raw_dep0 = loc.get("dependency")
    dep0: dict[str, Any] = raw_dep0 if isinstance(raw_dep0, dict) else {}
    pkg0 = dep0.get("package")
    if loc.get("image") and isinstance(pkg0, dict) and pkg0.get("name"):
        # A container finding is named by what GitLab calls it, else by what is wrong where.
        title = str(
            vuln.get("message")
            or vuln.get("name")
            or f"{first_cve or raw_id} in {pkg0['name']}-{dep0.get('version', '')}"
        )
    elif loc.get("hostname") and not (vuln.get("name") or vuln.get("message")):
        # A DAST record has no name; its first identifier names the check ("PII Disclosure").
        title = str(
            next((i["name"] for i in ids0 if i.get("name")), "")
            or vuln.get("description")
            or raw_id
        )
    else:
        title = str(vuln.get("name") or vuln.get("message") or vuln.get("description") or raw_id)
    word = str(vuln.get("severity") or "")
    unset = word.strip().lower() in _UNSET
    severity = severity_of("gitlab", word or "Unknown", ctx.unknown_severity)
    if unset:  # GitLab's own "I don't know": Info, and the title keeps what it said
        title = f"[{word or 'Unknown'} severity] {title}"
    cves = [
        str(i["value"]).upper()
        for i in ids
        if str(i.get("type", "")).lower() == "cve" and i.get("value")
    ]
    cwes = cwe_ids([i.get("value") for i in ids if str(i.get("type", "")).lower() == "cwe"])
    others = [str(i["value"]) for i in ids if i.get("value")]
    description = (
        "\n\n".join(
            p for p in (plain_text(vuln.get("message")), plain_text(vuln.get("description"))) if p
        )
        or title
    )
    solution = str(vuln.get("solution") or "")
    links = [
        str(link.get("url"))
        for link in vuln.get("links") or []
        if isinstance(link, dict) and link.get("url")
    ]
    scanner = scan.get("scanner", "")
    native = {"gitlab": word.upper()}
    evidence = Evidence(reported_by=[scanner or "gitlab"], rule_ids={})

    raw_dep = loc.get("dependency")
    dep: dict[str, Any] = raw_dep if isinstance(raw_dep, dict) else {}
    raw_pkg = dep.get("package")
    pkg = raw_pkg.get("name") if isinstance(raw_pkg, dict) else None
    if pkg:  # a package: SCA, or an image's package
        version = str(dep.get("version") or "")
        image = str(loc.get("image") or "")
        path = image or str(loc.get("file") or "unknown")
        os_name = str(loc.get("operating_system") or "").replace(":", " ").split(" ")[0].lower()
        eco = os_name if image and os_name else _ecosystem(str(loc.get("file") or ""), managers)
        rule = cves[0] if cves else _rule(vuln, title)
        snippet = f"{pkg}@{version}"
        evidence.rule_ids = {evidence.reported_by[0]: [rule]}
        return Finding(
            id=f"gitlab:{rule}:{path}:{snippet}",
            title=(f"{cves[0]}: {title}" if cves and not image else title)[:300],
            description=description,
            location=Location(path, 1, 1, snippet, Location.hash_snippet(snippet)),
            taxonomy=Taxonomy(
                Category.SCA,
                cwe=cwes,
                cve=tuple(dict.fromkeys(cves)),
                aliases=tuple(dict.fromkeys(others)),
            ),
            scoring=Scoring(native_severity=native, normalized_severity=severity, confidence=0.9),
            evidence=evidence,
            remediation=Remediation(summary=solution, references=links),
            package=Package(str(pkg), version, eco),
        )

    if loc.get("hostname"):  # a web target: DAST or API fuzzing
        host = target_of(str(loc["hostname"]))[0]
        route = str(loc.get("path") or "/")
        return dast_finding(
            "gitlab",
            rule=_rule(vuln, title),
            title=title,
            host=host,
            route=route.split("?")[0] or "/",
            severity=severity,
            native=word.upper(),
            description=description,
            cwe=cwes,
            cve=cves,
            summary=solution,
            references=links,
            digest_of=f"{raw_id}|{loc.get('param')}|{loc.get('method')}",
            reported_by=scanner,
        )

    path = str(loc.get("file") or "")
    if not path:
        return None  # a coverage-fuzzing crash, or a record with no place at all
    start = max(int(loc.get("start_line") or 1), 1)
    end = max(int(loc.get("end_line") or start), start)
    secret = (
        scan.get("type") == "secret_detection"
        or "raw_source_code_extract" in vuln
        or bool(loc.get("commit"))
    )
    snippet = clip(vuln.get("raw_source_code_extract") or "", 500) if secret else ""
    rule = _rule(vuln, title)
    evidence.rule_ids = {evidence.reported_by[0]: [rule]}
    return Finding(
        id=f"gitlab:{rule}:{path}:{start}",
        title=title[:300],
        description=description,
        location=Location(path, start, end, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(
            Category.SECRETS if secret else Category.SAST,
            cwe=cwes,
            cve=tuple(cves),
            aliases=tuple(dict.fromkeys(others)),
        ),
        scoring=Scoring(native_severity=native, normalized_severity=severity, confidence=0.6),
        evidence=evidence,
        remediation=Remediation(summary=solution, references=links),
    )


class GitlabParser(IngestParser):
    name = "gitlab"
    label = "GitLab security report"
    formats = frozenset({"json"})
    categories = frozenset({"sast", "sca", "container", "secrets", "dast"})
    # One parser for five of DefectDojo's (sast, dep_scan, container_scan, secret_detection, dast).
    ported_from = "dojo/tools/gitlab_sast/parser.py"
    ported_into = ("core/dast/mapping.py",)

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith("{") or '"vulnerabilities"' not in text:
            return 0.0
        # GitLab's `identifiers` is a list of {type, name, value}; Snyk's is an object of lists.
        if _IDENTIFIER_LIST.search(text) or '"remediations"' in text:
            return 0.97
        return 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)

        def meta(prefix: str) -> str | None:
            return _META.get(prefix)

        scan: dict[str, str] = {}
        managers: dict[str, str] = {}
        for tag, value in stream_objects(json_events(stream, ctx), meta):
            if tag == "file" and isinstance(value, dict):
                managers[str(value.get("path", ""))] = str(value.get("package_manager", ""))
            elif tag in ("type", "scanner"):
                scan[tag] = str(value)
        stream.seek(0)

        saw = False
        skipped = unplaced = 0
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "vuln" if p == "vulnerabilities.item" else None,
            frozenset({"vulnerabilities"}),
        ):
            if tag.startswith("marker:"):
                saw = True
            elif isinstance(value, dict):
                try:
                    finding = vulnerability_finding(value, scan, managers, ctx)
                except (KeyError, TypeError, ValueError, AttributeError):
                    skipped += 1
                    continue
                if finding is None:
                    unplaced += 1
                else:
                    yield finding
        if not saw:
            raise ParseAborted("no `vulnerabilities` list; not a GitLab security report")
        if skipped:
            ctx.warn(f"{skipped} record(s) were malformed and skipped")
        if unplaced:
            ctx.warn(
                f"{unplaced} record(s) have no file, package or URL (coverage-fuzzing crashes) "
                "and were skipped"
            )
