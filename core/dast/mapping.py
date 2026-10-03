"""One reading of what a DAST or network tool's record means (plan §22.4, §42.2).

The campaign adapters (`core.dast.adapters`) read a tool's output while Bulwark runs it; the import
parsers (`core.imports.parsers`) read the same tools' reports when someone uploads them. Both call
the functions here, for the same reason SARIF has `core.sarif`: a ZAP alert imported from a file and
the same alert from a scan Bulwark ran must be the same Finding, or they become two Issues.

Imports only `core.models` and `core.scoring`, because the sandboxed parser image copies exactly
those (docker/ingest-parser/Dockerfile).

Where a finding is -- its identity (see `core.correlation.fingerprint`) -- is `Location.host` plus
`Location.route`. For a web finding that is the origin and the URL path; for a network finding
(Nessus, OpenVAS) it is the host and `port/protocol`, there being no URL.

The ZAP and Nuclei readings are derived in part from DefectDojo's `dojo/tools/zap/parser.py` and
`dojo/tools/nuclei/parser.py` (BSD-3-Clause, Copyright (c) 2015-2023 DefectDojo, Inc.); the notice
and licence are in THIRD_PARTY_LICENSES.md. Not affiliated with or endorsed by DefectDojo.
"""

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Remediation,
    Scoring,
    Severity,
    Taxonomy,
)
from core.scoring.severity import MATRIX

try:  # RE2 guarantees linear-time matching; the stdlib engine does not.
    import re2 as _re
except ImportError:  # pragma: no cover - google-re2 is a declared dependency
    import re as _re

UnknownSeverity = Callable[[str], None]

# Free text in a report is attacker-chosen; nothing here reads more of it than a person would.
MAX_TEXT = 20_000
MAX_EVIDENCE = 1_000

_DEFAULT_PORTS = {"http": 80, "https": 443}
_CWE = re.compile(r"^\s*(?:cwe[-_ ]?)?(\d{1,6})\s*$", re.IGNORECASE)
_BLOCK_TAG = _re.compile(
    r"(?i)</?(?:p|div|br|li|ul|ol|tr|table|h[1-6]|pre|blockquote|hr|dd|dt|dl|section)\b[^>]*>"
)
_TAG = _re.compile(r"<[^>]*>")


def target_of(url: str) -> tuple[str, str]:
    """`(host, route)` for a URL or a bare `host[:port]`: `("https://example.com", "/a/b")`.

    The origin is lower-cased and a scheme's default port is dropped, so `https://Example.com:443`
    and `https://example.com` are one place; query and fragment are dropped from the route because a
    scanner generates them on the fly (ZAP's own parser does the same, "it produces a lot of fake
    locations"). Unparseable input is no target at all rather than an error.
    """
    url = (url or "").strip()
    if not url:
        return "", "/"
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        hostname = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return "", "/"
    if not hostname:
        return "", "/"
    if ":" in hostname:
        hostname = f"[{hostname}]"  # IPv6
    route = parts.path or "/"
    scheme = parts.scheme.lower()
    if scheme:
        shown = f":{port}" if port and port != _DEFAULT_PORTS.get(scheme) else ""
        return f"{scheme}://{hostname}{shown}", route
    return (f"{hostname}:{port}" if port else hostname), route


def network_target(host: str, port: str | int | None, protocol: str = "tcp") -> tuple[str, str]:
    """`(host, route)` for a finding with no URL: a host, and `port/protocol` ("443/tcp") as the
    route. Port 0 or none means the whole host (a finding about the machine, not a service)."""
    host = (host or "").strip().lower()
    number = str(port or "").strip()
    if not number or number == "0":
        return host, "host"
    return host, f"{number}/{(protocol or 'tcp').strip().lower()}"


def plain_text(markup: str | None, limit: int = MAX_TEXT) -> str:
    """A report's HTML-ish text (ZAP writes `<p>` into every description) as plain text.

    Tags are removed with linear-time regular expressions (RE2), after cutting the input to `limit`
    characters: the stdlib HTML parser is quadratic on pathological markup (twenty thousand
    characters of `<a <a <a ...` took over two seconds), and a report is attacker-chosen input.
    """
    if not markup:
        return ""
    text = str(markup)[:limit]
    if "<" in text:
        text = _TAG.sub("", _BLOCK_TAG.sub("\n", text))
    text = html.unescape(text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" ?\n ?", "\n", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def cwe_ids(values: Iterable[object] | object) -> tuple[str, ...]:
    """`CWE-79` for each of "79", 79, "cwe-79", "CWE_79"; anything that is not a CWE number
    ("nvd-cve-other", "-1", "0") is dropped, because a made-up weakness id is worse than none."""
    if values is None:
        return ()
    items = values if isinstance(values, (list, tuple, set)) else [values]
    out: list[str] = []
    for v in items:
        m = _CWE.match(str(v))
        if m and int(m.group(1)) > 0:
            out.append(f"CWE-{int(m.group(1))}")
    return tuple(dict.fromkeys(out))


def clip(text: object, limit: int = MAX_EVIDENCE) -> str:
    s = str(text or "").strip()
    return s if len(s) <= limit else s[:limit] + "…"


def severity_of(tool: str, label: str, on_unknown: UnknownSeverity | None = None) -> Severity:
    """Normalise a tool's own severity word. A word the tool does not define is Info and is reported
    through `on_unknown` -- never guessed up or down."""
    table = MATRIX.get(tool, {})
    key = str(label or "").strip().upper()
    if key in table:
        return table[key]
    if on_unknown is not None:
        on_unknown(str(label or ""))
    return Severity.INFO


def dast_finding(
    tool: str,
    *,
    rule: str,
    title: str,
    host: str,
    route: str,
    severity: Severity,
    native: str,
    description: str = "",
    cwe: Iterable[str] = (),
    cve: Iterable[str] = (),
    aliases: Iterable[str] = (),
    summary: str = "",
    references: Iterable[str | None] = (),
    cvss: float | None = None,
    confidence: float = 0.5,
    epss: float | None = None,
    digest_of: str = "",
    reported_by: str = "",
) -> Finding:
    """The canonical Finding for one DAST or network record. `digest_of` is whatever makes this
    record distinct from another that shares tool, rule and place (a parameter, a whole raw line);
    it only affects the id, never the identity -- see `core.correlation.fingerprint`."""
    digest = hashlib.sha256(f"{host}|{route}|{digest_of}".encode()).hexdigest()[:12]
    tool_name = reported_by or tool
    return Finding(
        id=f"{tool}-{rule}-{digest}",
        title=(title or rule)[:300],
        description=description or title or rule,
        location=Location(path="", start_line=0, end_line=0, route=route, host=host),
        taxonomy=Taxonomy(
            category=Category.DAST,
            cwe=tuple(dict.fromkeys(cwe)),
            cve=tuple(dict.fromkeys(cve)),
            aliases=tuple(dict.fromkeys(aliases)),
        ),
        scoring=Scoring(
            native_severity={tool: native},
            normalized_severity=severity,
            cvss_v3_1=cvss,
            epss_score=epss,
            confidence=confidence,
        ),
        evidence=Evidence(reported_by=[tool_name], rule_ids={tool_name: [rule]}),
        remediation=Remediation(
            summary=summary,
            references=[r for r in dict.fromkeys(references) if r],
            generated_by="static",
        ),
    )


# --- ZAP ---------------------------------------------------------------------------------------

ZAP_RISK = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
_ZAP_CONFIDENCE = {"1": 0.3, "2": 0.6, "3": 0.9, "4": 0.99}  # low .. user-confirmed


def _text(v: object) -> str:
    return "" if v is None else str(v).strip()


def zap_alert_findings(
    alert: dict[str, Any],
    site: str,
    tool: str = "zap",
    on_unknown: UnknownSeverity | None = None,
    *,
    reported_by: str = "",
) -> list[Finding]:
    """One Finding per instance (URL) of a ZAP alert, from an alert as a dict -- the XML report's
    `alertitem` children or the JSON report's alert object, which name the same fields.

    An alert hit at fifty URLs is fifty findings, so each is its own place to fix and the same alert
    fixed on one URL closes that Issue and no other. (DefectDojo folds them into one finding with
    fifty endpoints; the comparison harness regroups ours to match, see tests/golden/ingest.)
    """
    title = _text(alert.get("alert")) or _text(alert.get("name")) or "ZAP finding"
    plugin = _text(alert.get("pluginid")) or "0"
    risk = _text(alert.get("riskcode"))
    label = ZAP_RISK.get(risk)
    if label is None:
        if on_unknown is not None:
            on_unknown(f"riskcode {risk or '(none)'}")
        severity = Severity.INFO
    else:
        severity = severity_of(tool, label, on_unknown)
    native = _text(alert.get("riskdesc")) or label or risk
    confidence = _ZAP_CONFIDENCE.get(_text(alert.get("confidence")), 0.5)
    base = plain_text(alert.get("desc"))
    solution = plain_text(alert.get("solution"))
    references = [ln.strip() for ln in plain_text(alert.get("reference")).splitlines()]
    cwe = cwe_ids(alert.get("cweid"))
    instances = alert.get("instances") or [{"uri": site}]

    findings: list[Finding] = []
    for inst in instances:
        if not isinstance(inst, dict):
            continue
        uri = _text(inst.get("uri")) or site
        host, route = target_of(uri)
        if not host:
            host = target_of(site)[0]
        facts = [
            f"{k}: {clip(_text(inst.get(key)))}"
            for k, key in (
                ("Method", "method"),
                ("Parameter", "param"),
                ("Attack", "attack"),
                ("Evidence", "evidence"),
            )
            if _text(inst.get(key))
        ]
        status = _text(inst.get("responseheader")).splitlines()[:1]
        if status:
            facts.append(f"Response: {clip(status[0], 200)}")
        other = plain_text(inst.get("otherinfo"), 2_000)
        if other:
            facts.append(f"Other info: {clip(other, 1_000)}")
        description = "\n\n".join(p for p in (base, "\n".join(facts)) if p)
        findings.append(dast_finding(
            tool,
            rule=plugin,
            title=title,
            host=host,
            route=route,
            severity=severity,
            native=native,
            description=description,
            cwe=cwe,
            summary=solution,
            references=references,
            confidence=confidence,
            digest_of="|".join(
                (
                    title,
                    uri,
                    _text(inst.get("method")),
                    _text(inst.get("param")),
                    _text(inst.get("attack")),
                )
                ),  # fmt: skip
                reported_by=reported_by,
            ),
        )
    return findings


# --- Nuclei ------------------------------------------------------------------------------------


def _as_list(v: object) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x is not None]
    return [x.strip(" -") for x in str(v).splitlines() if x.strip(" -")] or [str(v)]


def nuclei_finding(
    rec: dict[str, Any],
    raw: str,
    tool: str = "nuclei",
    on_unknown: UnknownSeverity | None = None,
) -> Finding | None:
    """The Finding for one Nuclei result (a line of `-jsonl`, or one element of a `-json-export`
    array). Both spellings of the keys DefectDojo handles are read: `template-id` / `templateID`,
    `matched-at` / `matched`. Nuclei reports one record per matcher that fired, so the matcher is
    part of the rule id: `tech-detect` matching `nginx` and `php` at one URL is two detections.

    Returns None for a record that is not a Nuclei result at all (no `info`).
    """
    info = rec.get("info")
    if not isinstance(info, dict):
        return None
    template = _text(rec.get("template-id") or rec.get("templateID") or rec.get("template_id"))
    template = template or "unknown"
    matcher = _text(rec.get("matcher-name") or rec.get("matcher_name"))
    rule = f"{template}:{matcher}" if matcher else template
    label = _text(info.get("severity")) or "info"
    severity = severity_of(tool, label, on_unknown)

    raw_cls = info.get("classification")
    cls: dict[str, Any] = raw_cls if isinstance(raw_cls, dict) else {}
    cvss: float | None = None
    metrics = _text(cls.get("cvss-metrics"))
    score = cls.get("cvss-score")
    if (
        isinstance(score, (int, float))
        and not isinstance(score, bool)
        and not metrics.startswith(("CVSS:4", "CVSS:2"))
    ):
        cvss = float(score)

    matched = _text(
        rec.get("matched-at") or rec.get("matched") or rec.get("url") or rec.get("host")
    )
    host, route = target_of(matched)
    if not host:
        host, route = target_of(_text(rec.get("host")))

    parts = [_text(info.get("description"))]
    extracted = _as_list(rec.get("extracted-results"))
    if extracted:
        parts.append("Results:\n" + "\n".join(clip(x, 500) for x in extracted[:20]))
    cve = [c.upper() for c in _as_list(cls.get("cve-id"))]
    return dast_finding(
        tool,
        rule=rule,
        title=_text(info.get("name")) or template,
        host=host,
        route=route,
        severity=severity,
        native=label,
        description="\n\n".join(p for p in parts if p),
        cwe=cwe_ids(cls.get("cwe-id")),
        cve=cve,
        summary=_text(info.get("remediation")),
        references=_as_list(info.get("reference")),
        cvss=cvss,
        digest_of=hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest(),
    )
