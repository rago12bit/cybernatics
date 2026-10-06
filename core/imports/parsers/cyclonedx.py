"""CycloneDX import, JSON and XML (plan §42.2, order of work #2).

A CycloneDX document is mostly an inventory (`components`); it only makes claims about
vulnerabilities when it has a `vulnerabilities` section (a VEX, or the output of a scanner such as
Grype that adds one). So:

- Findings come from `vulnerabilities[]`, each resolved against the component it `affects`.
- A file with no `vulnerabilities` section is an inventory: it yields no findings *and* cannot close
  anything (`ctx.can_close_missing = False`) -- it never said those packages are clean.

A rating's `method` matters: CVSS scores are severities, but the same list also carries things like
the EPSS exploit probability (`method: "other"`, no severity), which is not one and must not be read
as one.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from typing import Any, BinaryIO

from core.adapters.base import TARGET_PREFIX
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext, seekable
from core.imports.parsers.purl import parse_purl
from core.imports.parsers.safe import SafePattern, iter_xml, json_events, stream_objects
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
from core.scoring.severity import MATRIX, from_cvss

_CVE = SafePattern(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CVSS_V3 = ("CVSSV3", "CVSSV31", "CVSSV3.1", "CVSSV30")
_COMPONENT_FIELDS = ("bom-ref", "name", "version", "purl", "group", "type")


def _tool_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-")[:40] or "cyclonedx"


def _component_path(raw: dict[str, Any]) -> str:
    """Where a component was found, when the file says (Syft writes `syft:location:N:path`;
    CycloneDX 1.5+ has `evidence.occurrences[].location`). The location is part of the finding's
    identity (a manifest file), so use it when present; "sbom" otherwise."""
    for occ in (raw.get("evidence") or {}).get("occurrences") or []:
        if isinstance(occ, dict) and occ.get("location"):
            return _relative(str(occ["location"]))
    for prop in raw.get("properties") or []:
        if isinstance(prop, dict) and re.fullmatch(
            r"syft:location:\d+:path", str(prop.get("name"))
        ):
            return _relative(str(prop.get("value", "")))
    return "sbom"


def _relative(path: str) -> str:
    """A path as native scans write it: relative to the scanned root, no leading slash."""
    return path.removeprefix(TARGET_PREFIX).lstrip("/") or "sbom"


def _flatten(raw: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """A component and every component nested inside it, reduced to the fields used."""
    yield {k: raw.get(k) for k in _COMPONENT_FIELDS} | {"path": _component_path(raw)}
    for child in raw.get("components") or []:
        if isinstance(child, dict):
            yield from _flatten(child)


def _package(component: dict[str, Any] | None, ref: str) -> tuple[Package, str] | None:
    """The Package an `affects` entry points at, and the file it was found in."""
    purl = str((component or {}).get("purl") or "")
    parsed = parse_purl(purl) or parse_purl(ref)
    if parsed is not None and parsed[2]:
        eco, name, version = parsed
        return Package(name=name, version=version, ecosystem=eco), str(
            (component or {}).get("path") or "sbom"
        )
    if component and component.get("name") and component.get("version"):
        name = str(component["name"])
        if component.get("group"):
            name = f"{component['group']}/{name}"
        return (
            Package(name=name, version=str(component["version"]), ecosystem="unknown"),
            str(component.get("path") or "sbom"),
        )
    return None


def _severity(ratings: list[Any], ctx: ParseContext) -> tuple[Severity, str, float | None] | None:
    """(normalized severity, the native label, CVSS v3 score) from a vulnerability's ratings, or
    None when it has nothing usable. A CVSS score wins (it is the most specific); otherwise the
    highest qualitative label the format defines."""
    table = MATRIX["cyclonedx"]
    best_score: tuple[float, str] | None = None
    labels: list[str] = []
    for r in ratings:
        if not isinstance(r, dict):
            continue
        method = str(r.get("method") or "").upper()
        score = r.get("score")
        if method.startswith("CVSS") and isinstance(score, (int, float)):
            if best_score is None or score > best_score[0]:
                best_score = (float(score), method)
        elif r.get("severity"):
            labels.append(str(r["severity"]))
    if best_score is not None:
        score, method = best_score
        return from_cvss(score), f"{method} {score:g}", (score if method in _CVSS_V3 else None)
    known = [(table[label.upper()], label) for label in labels if label.upper() in table]
    if known:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        sev, label = min(known, key=lambda sl: order.index(sl[0]))
        return sev, label.upper(), None
    for label in labels:
        ctx.unknown_severity(label)
    return None


def _advisory_urls(v: dict[str, Any]) -> list[str]:
    urls = [
        str(a["url"]) for a in v.get("advisories") or [] if isinstance(a, dict) and a.get("url")
    ]
    src = v.get("source")
    if isinstance(src, dict) and src.get("url"):
        urls.append(str(src["url"]))
    return list(dict.fromkeys(urls))


def vulnerability_findings(
    v: dict[str, Any],
    components: dict[str, dict[str, Any]],
    tool: str,
    ctx: ParseContext,
    skipped: Counter[str],
) -> Iterator[Finding]:
    """One Finding per (vulnerability, affected component). Counters in `skipped` explain, in one
    warning at the end, anything that could not be turned into a finding."""
    vid = str(v.get("id") or v.get("bom-ref") or "")
    if not vid:
        skipped["has no id"] += 1
        return
    rated = _severity(v.get("ratings") or [], ctx)
    if rated is None:
        severity, native, cvss = Severity.INFO, "", None
        skipped["has no usable severity rating (imported as Info)"] += 1
    else:
        severity, native, cvss = rated
    refs = [r for r in v.get("affects") or [] if isinstance(r, dict) and r.get("ref")]
    if not refs:
        skipped["affects nothing that can be identified"] += 1
        return
    urls = _advisory_urls(v)
    cves = sorted(
        {c.upper() for c in _CVE.findall(" ".join([vid, *urls]))}
        | {
            str(r["id"]).upper()
            for r in v.get("references") or []
            if isinstance(r, dict) and str(r.get("id", "")).upper().startswith("CVE-")
        }
    )
    aliases = sorted(
        {
            vid,
            *cves,
            *(
                str(r["id"])
                for r in v.get("references") or []
                if isinstance(r, dict) and r.get("id")
            ),
        }
    )
    cwes = tuple(f"CWE-{int(c)}" for c in v.get("cwes") or [] if str(c).isdigit())
    description = str(v.get("description") or v.get("detail") or vid)
    summary = description.split(". ")[0][:200]
    for ref in refs:
        found = _package(components.get(str(ref["ref"])), str(ref["ref"]))
        if found is None:
            skipped["affects a component that is not described in the file"] += 1
            continue
        package, path = found
        text = f"{package.name}@{package.version}"
        yield Finding(
            id=f"{tool}:{vid}:{path}:{text}",
            title=f"{package.name} {package.version}: {summary}"[:300],
            description=description,
            location=Location(path, 1, 1, text, Location.hash_snippet(text)),
            taxonomy=Taxonomy(Category.SCA, cwe=cwes, cve=tuple(cves), aliases=tuple(aliases)),
            scoring=Scoring(
                native_severity={tool: native} if native else {},
                normalized_severity=severity,
                cvss_v3_1=cvss,
            ),
            evidence=Evidence(reported_by=[tool], rule_ids={tool: [vid]}),
            remediation=Remediation(summary=str(v.get("recommendation") or ""), references=urls),
            package=package,
        )


class CycloneDxParser(IngestParser):
    name = "cyclonedx"
    label = "CycloneDX"
    formats = frozenset({"json", "xml"})
    categories = frozenset({"sca"})

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if text.startswith("{") and re.search(r'"bomFormat"\s*:\s*"CycloneDX"', text):
            return 0.99
        if text.startswith("<") and "<bom" in text and "cyclonedx.org/schema/bom" in text:
            return 0.99
        return 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        stream = seekable(stream, ctx.limits)
        first = stream.read(1024).lstrip(b"\xef\xbb\xbf \t\r\n")[:1]
        stream.seek(0)
        skipped: Counter[str] = Counter()
        if first == b"<":
            yield from self._parse_xml(stream, ctx, skipped)
        else:
            yield from self._parse_json(stream, ctx, skipped)
        for reason, n in skipped.items():
            ctx.warn(f"{n} vulnerabilit{'y' if n == 1 else 'ies'}: {reason}")

    # --- JSON -------------------------------------------------------------------------------

    def _parse_json(
        self, stream: BinaryIO, ctx: ParseContext, skipped: Counter[str]
    ) -> Iterator[Finding]:
        components: dict[str, dict[str, Any]] = {}
        tool = "cyclonedx"
        has_section = False
        n_components = 0

        def wanted(prefix: str) -> str | None:
            return {
                "bomFormat": "format",
                "components.item": "component",
                "metadata.tools.components.item.name": "tool",  # CycloneDX 1.5+
                "metadata.tools.item.name": "tool",  # CycloneDX 1.4 and earlier
            }.get(prefix)

        for tag, value in stream_objects(
            json_events(stream, ctx), wanted, frozenset({"vulnerabilities"})
        ):
            if tag == "format" and value != "CycloneDX":
                raise ParseAborted("bomFormat is not CycloneDX")
            elif tag == "marker:vulnerabilities":
                has_section = True
            elif tag == "tool" and tool == "cyclonedx" and isinstance(value, str):
                tool = _tool_slug(value)
            elif tag == "component" and isinstance(value, dict):
                for comp in _flatten(value):
                    n_components += 1
                    _inventory(ctx, comp)
                    if comp.get("bom-ref"):
                        components[str(comp["bom-ref"])] = comp
        if not has_section and n_components == 0:
            raise ParseAborted("no components or vulnerabilities found; not a CycloneDX document")
        stream.seek(0)
        for tag, value in stream_objects(
            json_events(stream, ctx),
            lambda p: "vuln" if p == "vulnerabilities.item" else None,
        ):
            if tag == "vuln" and isinstance(value, dict):
                yield from vulnerability_findings(value, components, tool, ctx, skipped)
        self._finish(ctx, has_section, n_components)

    # --- XML --------------------------------------------------------------------------------

    def _parse_xml(
        self, stream: BinaryIO, ctx: ParseContext, skipped: Counter[str]
    ) -> Iterator[Finding]:
        components: dict[str, dict[str, Any]] = {}
        tool = "cyclonedx"
        has_section = False
        n_components = 0
        stack: list[str] = []
        for event, el in iter_xml(stream, ctx):
            local = _local(el.tag)
            if event == "start":
                stack.append(local)
                if local == "vulnerabilities":
                    has_section = True
                continue
            stack.pop()
            if local == "component":
                if "tools" in stack:
                    if tool == "cyclonedx":
                        tool = _tool_slug(_text(el, "name"))
                elif stack and stack[-1] == "metadata":
                    el.clear()  # the document's own subject (the scanned directory), not a package
                else:
                    n_components += 1
                    comp = next(_flatten(_xml_component(el)))
                    _inventory(ctx, comp)
                    if comp.get("bom-ref"):
                        components[str(comp["bom-ref"])] = comp
                    el.clear()
            elif local == "tool" and "tools" in stack and tool == "cyclonedx":
                tool = _tool_slug(_text(el, "name"))
            elif local == "vulnerability":
                yield from vulnerability_findings(
                    _xml_vulnerability(el), components, tool, ctx, skipped
                )
                el.clear()
        if not has_section and n_components == 0:
            raise ParseAborted("no components or vulnerabilities found; not a CycloneDX document")
        self._finish(ctx, has_section, n_components)

    @staticmethod
    def _finish(ctx: ParseContext, has_section: bool, n_components: int) -> None:
        if not has_section:
            ctx.can_close_missing = False
            ctx.warn(
                f"This file lists {n_components} components and no vulnerabilities section, so it "
                "has no findings to import and cannot close any (a package list does not say the "
                "packages are free of vulnerabilities)"
            )


def _inventory(ctx: ParseContext, comp: dict[str, Any]) -> None:
    """Every component, for the component inventory (plan §46.1) -- not a finding."""
    ctx.component(
        str(comp.get("purl") or ""), str(comp.get("version") or ""), str(comp.get("path") or "")
    )


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(el: Any, child: str) -> str:
    for c in el:
        if _local(c.tag) == child:
            return (c.text or "").strip()
    return ""


def _xml_component(el: Any) -> dict[str, Any]:
    props = []
    for p in el.iter():
        if _local(p.tag) == "property" and p.get("name"):
            props.append({"name": p.get("name"), "value": (p.text or "").strip()})
    occ = [
        {"location": (o.text or "").strip()}
        for o in el.iter()
        if _local(o.tag) == "location" and (o.text or "").strip()
    ]
    return {
        "bom-ref": el.get("bom-ref"),
        "type": el.get("type"),
        "name": _text(el, "name"),
        "version": _text(el, "version"),
        "group": _text(el, "group"),
        "purl": _text(el, "purl"),
        "properties": props,
        "evidence": {"occurrences": occ},
        "components": [],
    }


def _xml_vulnerability(el: Any) -> dict[str, Any]:
    def children(parent: str, item: str) -> list[Any]:
        for c in el:
            if _local(c.tag) == parent:
                return [i for i in c if _local(i.tag) == item]
        return []

    source = next((c for c in el if _local(c.tag) == "source"), None)
    return {
        "id": _text(el, "id"),
        "bom-ref": el.get("bom-ref"),
        "source": {"name": _text(source, "name"), "url": _text(source, "url")} if source else None,
        "description": _text(el, "description"),
        "recommendation": _text(el, "recommendation"),
        "ratings": [
            {
                "score": _float(_text(r, "score")),
                "severity": _text(r, "severity"),
                "method": _text(r, "method"),
            }
            for r in children("ratings", "rating")
        ],
        "advisories": [{"url": _text(a, "url")} for a in children("advisories", "advisory")],
        "affects": [{"ref": _text(t, "ref")} for t in children("affects", "target")],
        "cwes": [(c.text or "").strip() for c in children("cwes", "cwe")],
        "references": [{"id": _text(r, "id")} for r in children("references", "reference")],
    }


def _float(text: str) -> float | None:
    try:
        return float(text)
    except ValueError:
        return None
