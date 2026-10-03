"""Burp Suite XML issue export import (plan §42.2 order of work #5, ported from DefectDojo's Burp
parser).

Burp's export is `<issues><issue>...</issue></issues>`; each `<issue>` is already one issue at one
place (host, path, parameter), so each becomes one finding. Issues are handled and released as
they end, so memory is bounded by the largest issue (the base64 request/response pairs are the
bulk of a real export), not by the file.

Burp writes an internal `<!DOCTYPE issues [<!ELEMENT ...>]>` at the top of every export, so this is
the one parser that admits a DTD -- but only that: an entity declaration or an external DTD is still
refused (`safe.iter_xml(allow_dtd=True)`).

Derived in part from DefectDojo's `dojo/tools/burp/parser.py` (BSD-3-Clause, Copyright (c)
2015-2023 DefectDojo, Inc.); the notice and licence are in THIRD_PARTY_LICENSES.md. Not affiliated
with or endorsed by DefectDojo.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Iterator
from typing import Any, BinaryIO
from urllib.parse import urlsplit

from core.dast.mapping import (
    MAX_EVIDENCE,
    clip,
    cwe_ids,
    dast_finding,
    plain_text,
    severity_of,
    target_of,
)
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext
from core.imports.parsers.safe import SafePattern, iter_xml
from core.models import Finding

_CONFIDENCE = {"certain": 0.9, "firm": 0.6, "tentative": 0.3}
_BRACKET = SafePattern(r"\[([^\]]*)\]")
_CWE = SafePattern(r"CWE-(\d+)", 0)
_HREF = SafePattern(r'href="([^"]+)"')
# Every issue an extension raises shares this type id, so on its own it would make unrelated
# extension findings one rule (DefectDojo keys on type *and* title for the same reason).
_EXTENSION_TYPE = "134217728"
_MAX_COLLABORATOR_EVENTS = 5


def _text(el: Any, tag: str) -> str:
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def _first_line(b64: str) -> str:
    """The request line or status line of a base64-encoded HTTP message, decoded from a bounded
    prefix: a Burp export carries whole bodies, and a finding needs one line of them."""
    prefix = (b64 or "").strip()[:512]
    prefix = prefix[: len(prefix) - len(prefix) % 4]
    try:
        raw = base64.b64decode(prefix, validate=False)
    except (binascii.Error, ValueError):
        return ""
    return raw.decode("utf-8", "replace").splitlines()[0][:200] if raw else ""


def _collaborator(el: Any) -> list[str]:
    out = []
    for event in el.findall("collaboratorEvent")[:_MAX_COLLABORATOR_EVENTS]:
        kind, origin, when = (_text(event, t) for t in ("interactionType", "originIp", "time"))
        extra = (
            f" for {_text(event, 'lookupHost')}"
            if kind == "DNS" and _text(event, "lookupHost")
            else ""
        )
        out.append(f"Collaborator {kind} interaction{extra} from {origin} at {when}")
    return out


def issue_finding(el: Any, ctx: ParseContext) -> Finding:
    name = _text(el, "name") or "Burp issue"
    rule = _text(el, "type") or "0"
    if rule == _EXTENSION_TYPE:
        rule = f"{rule}:{name[:80]}"
    host, _ = target_of(_text(el, "host"))
    path = _text(el, "path")
    route = urlsplit(path).path or "/"
    label = _text(el, "severity") or "Information"
    severity = severity_of("burp", label, ctx.unknown_severity)

    param = ""
    match = _BRACKET.search(_text(el, "location"))
    if match:
        param = match.group(1)
    pairs = el.findall("requestresponse")
    facts = []
    if param:
        facts.append(f"Parameter: {clip(param, 200)}")
    if pairs:
        request = _first_line(_text(pairs[0], "request"))
        response = _first_line(_text(pairs[0], "response"))
        facts += [f"Request: {request}"] if request else []
        facts += [f"Response: {response}"] if response else []
    facts += _collaborator(el)

    detail = plain_text(_text(el, "issueDetail"))
    background = plain_text(_text(el, "issueBackground"))
    description = "\n\n".join(
        p
        for p in (
            f"URL: {host}{path}",
            detail,
            "\n".join(facts),
            f"Background: {clip(background, 2_000)}" if background else "",
        )
        if p
    )
    fix = "\n\n".join(
        p
        for p in (
            plain_text(_text(el, "remediationDetail")),
            plain_text(_text(el, "remediationBackground")),
        )
        if p
    )
    classifications = _text(el, "vulnerabilityClassifications")
    return dast_finding(
        "burp",
        rule=rule,
        title=name,
        host=host,
        route=route,
        severity=severity,
        native=label,
        description=description[: MAX_EVIDENCE * 20],
        cwe=cwe_ids(_CWE.findall(classifications)),
        summary=fix,
        references=_HREF.findall(_text(el, "references")),
        confidence=_CONFIDENCE.get(_text(el, "confidence").lower(), 0.5),
        digest_of=f"{_text(el, 'serialNumber')}|{param}",
    )


class BurpParser(IngestParser):
    name = "burp"
    label = "Burp Suite XML report"
    formats = frozenset({"xml"})
    categories = frozenset({"dast"})
    ported_from = "dojo/tools/burp/parser.py"
    ported_into = ("core/dast/mapping.py",)

    def sniff(self, head: bytes) -> float:
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        if not text.startswith("<"):
            return 0.0
        if "<issues" in text and "burpVersion" in text:
            return 0.99
        if "<issue>" in text and "<serialNumber>" in text and "<issues" in text:
            return 0.9
        return 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        saw_root = False
        depth = 0
        for event, el in iter_xml(stream, ctx, allow_dtd=True):
            if event == "start":
                depth += 1
                if depth == 1:
                    saw_root = el.tag == "issues"
                continue
            depth -= 1
            if el.tag == "issue" and depth == 1:
                yield issue_finding(el, ctx)
                el.clear()
        if not saw_root:
            raise ParseAborted("the root element is not <issues>; not a Burp Suite XML export")
