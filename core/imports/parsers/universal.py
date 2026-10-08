"""The universal mapper's parser (plan §42.4, ADR-0043): a saved mapping *is* a parser.

For a JSON, CSV or XML report Bulwark has no parser for, a person (helped by a model, see
`core.imports.mapper`) writes down where each field lives -- "the title is `$.name`, the severity is
`$.risk`" -- and that mapping is all this module needs. It is deterministic: the same mapping and
the same file always give the same findings, and no model is anywhere in the import path. The
model helped write the mapping; it never reads a file being imported.

The path language is deliberately small, smaller than JSONPath:

- JSON: `$` (the record), `.key`, `["key with spaces"]`, `[0]`, `[*]` (every element). No filters,
  no recursive descent, no slices, no scripts -- nothing whose cost depends on the data, so a
  mapping cannot be made expensive by a hostile file, and nothing a person cannot read at a glance.
- XML: `child/grandchild`, `@attribute`, `child/@attribute`, and `.` for the record's own text,
  matched on local names (namespaces ignored), because that is how people read XML reports.
- CSV: a column name from the header row, matched ignoring case and surrounding spaces.

Lives in the parser package because the sandboxed parser image copies exactly that directory: an
uploaded file is parsed by a saved mapping inside the same container as every other parser.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from core.dast.mapping import clip, cwe_ids, dast_finding, plain_text, target_of
from core.imports.parsers.base import IngestParser, ParseAborted, ParseContext
from core.imports.parsers.safe import SafePattern, iter_csv, iter_xml, json_events, stream_objects
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
from core.scoring.severity import from_cvss

FORMATS = ("json", "csv", "xml")
# Every field a mapping can fill, and whether it can hold several values.
FIELDS: dict[str, bool] = {
    "title": False,
    "severity": False,
    "description": False,
    "path": False,
    "line": False,
    "rule": False,  # the tool's own id for the check: what `tool_id` deduplication matches on
    "cwe": True,
    "cve": True,
    "url": False,  # a web finding: becomes host + route, the way every DAST parser does
    "package": False,
    "version": False,
    "ecosystem": False,
    "recommendation": False,
    "references": True,
}
REQUIRED = ("title",)
SEVERITY_WORDS: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "information": Severity.INFO,
    "note": Severity.INFO,
    "none": Severity.INFO,
}
MAX_PATH = 200
MAX_SEGMENTS = 16
MAX_FAN_OUT = 1000  # values one `[*]` path may collect from one record
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,39}$")
_CVE = SafePattern(r"(?i)\bCVE-\d{4}-\d{4,7}\b")
_CWE_IN_TEXT = SafePattern(r"(?i)\bCWE[-_ ]?(\d{1,6})\b")
_JSON_SEGMENT = re.compile(
    r"""\.(?P<key>[A-Za-z_@$][A-Za-z0-9_@$-]*)"""
    r"""|\[(?:(?P<index>\d{1,6})|(?P<star>\*)|"(?P<qkey>(?:[^"\\]|\\.){1,200})")\]"""
)
_XML_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,100}$")


class MappingError(ValueError):
    """A mapping that cannot be a parser: what is wrong, said so a person can fix it."""


# --- the path language --------------------------------------------------------------------------


@dataclass(frozen=True)
class JsonPath:
    """A parsed JSON path: each step is a key (str), an index (int) or `None` for `[*]`."""

    text: str
    steps: tuple[str | int | None, ...]

    @property
    def fans_out(self) -> bool:
        return any(s is None for s in self.steps)

    def values(self, record: Any) -> list[Any]:
        """Every value the path reaches in `record`, in document order (scalars only: an object or
        array at the end of a path is not a value a finding can hold)."""
        current = [record]
        for step in self.steps:
            following: list[Any] = []
            for node in current:
                if step is None:
                    if isinstance(node, list):
                        following.extend(node[:MAX_FAN_OUT])
                elif isinstance(step, int):
                    if isinstance(node, list) and step < len(node):
                        following.append(node[step])
                elif isinstance(node, dict) and step in node:
                    following.append(node[step])
            current = following[:MAX_FAN_OUT]
            if not current:
                return []
        return [v for v in current if v is not None and not isinstance(v, (dict, list))]


def parse_json_path(text: str, *, record_path: bool = False) -> JsonPath:
    """`$.a.b[0]["c d"][*]`. A records path (where the findings are) may only use keys and `[*]`,
    and must end in `[*]`: it becomes a streaming prefix, so the file is never loaded whole."""
    text = text.strip()
    if not text.startswith("$"):
        raise MappingError(f"a JSON path starts with `$`: {text!r}")
    if len(text) > MAX_PATH:
        raise MappingError(f"path is longer than {MAX_PATH} characters")
    steps: list[str | int | None] = []
    pos = 1
    while pos < len(text):
        m = _JSON_SEGMENT.match(text, pos)
        if not m:
            raise MappingError(f"cannot read the path {text!r} at {text[pos:pos + 12]!r}")
        if m.group("key") is not None:
            steps.append(m.group("key"))
        elif m.group("qkey") is not None:
            steps.append(json.loads(f'"{m.group("qkey")}"'))
        elif m.group("index") is not None:
            steps.append(int(m.group("index")))
        else:
            steps.append(None)
        pos = m.end()
    if len(steps) > MAX_SEGMENTS:
        raise MappingError(f"path has more than {MAX_SEGMENTS} steps")
    if record_path:
        if not steps or steps[-1] is not None:
            raise MappingError("the records path must end in `[*]` (each element is one finding)")
        for s in steps:
            if isinstance(s, int):
                raise MappingError("the records path cannot use an index; use keys and `[*]`")
            if isinstance(s, str) and "." in s:
                raise MappingError(f"the records path cannot use a key containing '.': {s!r}")
    return JsonPath(text, tuple(steps))


def json_prefix(path: JsonPath) -> str:
    """The `ijson` prefix of a records path: `$.runs[*].results[*]` -> `runs.item.results.item`."""
    return ".".join("item" if s is None else str(s) for s in path.steps)


@dataclass(frozen=True)
class XmlPath:
    text: str
    elements: tuple[str, ...]  # child element local names, in order
    attribute: str | None  # read this attribute of the last element, or its text when None

    def values(self, record: Any) -> list[str]:
        nodes = [record]
        for name in self.elements:
            nodes = [c for n in nodes for c in n if _local(c.tag) == name][:MAX_FAN_OUT]
            if not nodes:
                return []
        out = []
        for n in nodes:
            if self.attribute is not None:
                value = next((v for k, v in n.attrib.items() if _local(k) == self.attribute), None)
            else:
                value = "".join(n.itertext())
            if value is not None and value.strip():
                out.append(value.strip())
        return out


def _local(tag: Any) -> str:
    text = str(tag)
    return text.rsplit("}", 1)[-1] if text.startswith("{") else text


def parse_xml_path(text: str) -> XmlPath:
    text = text.strip()
    if not text or len(text) > MAX_PATH:
        raise MappingError(f"an XML path is 1-{MAX_PATH} characters")
    if text == ".":
        return XmlPath(text, (), None)
    parts = text.split("/")
    attribute = None
    if parts[-1].startswith("@"):
        attribute = parts.pop()[1:]
        if not _XML_NAME.match(attribute):
            raise MappingError(f"not an attribute name: {attribute!r}")
    if len(parts) > MAX_SEGMENTS:
        raise MappingError(f"path has more than {MAX_SEGMENTS} steps")
    for p in parts:
        if not _XML_NAME.match(p):
            raise MappingError(f"not an element name: {p!r} (in {text!r})")
    return XmlPath(text, tuple(parts), attribute)


def parse_record_xml_path(text: str) -> tuple[str, ...]:
    """Where each finding's element is: `report/issues/issue`, matched against the end of the
    element chain, so the root's name does not have to be known (`issues/issue` works too)."""
    path = parse_xml_path(text)
    if path.attribute is not None or not path.elements:
        raise MappingError("the records path is a chain of element names, like `report/issue`")
    return path.elements


# --- the mapping ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class MappingSpec:
    """What a saved mapping says. Plain data: stored as JSON, shipped into the sandbox as JSON."""

    format: str
    source: str  # the tool's name: what "reported by" says, and the deduplication source
    fields: dict[str, str]
    records: str | None = None  # JSON: `$.results[*]`; XML: `report/issue`; CSV: none
    category: str = "sast"
    severity_map: dict[str, str] = field(default_factory=dict)  # the tool's word -> ours
    default_ecosystem: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "source": self.source,
            "records": self.records,
            "category": self.category,
            "fields": dict(self.fields),
            "severity_map": dict(self.severity_map),
            "default_ecosystem": self.default_ecosystem,
        }

    @staticmethod
    def from_dict(d: Any) -> MappingSpec:
        """Validated: a spec that comes back from here can be compiled into a parser."""
        if not isinstance(d, dict):
            raise MappingError("a mapping is a JSON object")
        spec = MappingSpec(
            format=str(d.get("format") or "").lower(),
            source=str(d.get("source") or "").strip().lower(),
            fields={str(k): str(v) for k, v in (d.get("fields") or {}).items() if str(v).strip()},
            records=(str(d["records"]).strip() or None) if d.get("records") is not None else None,
            category=str(d.get("category") or "sast").lower(),
            severity_map={
                str(k).strip().lower(): str(v).strip().upper()
                for k, v in (d.get("severity_map") or {}).items()
            },
            default_ecosystem=str(d.get("default_ecosystem") or "").strip().lower(),
        )
        compile_spec(spec)  # raises MappingError for anything that cannot run
        return spec


@dataclass(frozen=True)
class _Compiled:
    spec: MappingSpec
    records: Any  # JsonPath | tuple[str, ...] | None
    fields: dict[str, Any]  # name -> JsonPath | XmlPath | str (a CSV column)
    severity_map: dict[str, Severity]


def compile_spec(spec: MappingSpec) -> _Compiled:
    if spec.format not in FORMATS:
        raise MappingError(f"format must be one of {', '.join(FORMATS)}")
    if not SOURCE_RE.match(spec.source):
        raise MappingError(
            "the source name is 2-40 lower-case letters, digits, '.', '_' or '-' (it is what "
            "'reported by' shows, and what deduplication settings are chosen for)"
        )
    try:
        category = Category(spec.category)
    except ValueError:
        raise MappingError(
            f"category must be one of {', '.join(c.value for c in Category)}"
        ) from None
    unknown = sorted(set(spec.fields) - set(FIELDS))
    if unknown:
        raise MappingError(f"unknown field(s): {', '.join(unknown)}")
    for name in REQUIRED:
        if name not in spec.fields:
            raise MappingError(f"the {name} field must be mapped")
    if category is Category.SCA and "package" not in spec.fields:
        raise MappingError("a dependency (sca) mapping must map the package field")
    if category is Category.DAST and "url" not in spec.fields:
        raise MappingError("a web (dast) mapping must map the url field")
    sev_map: dict[str, Severity] = {}
    for word, value in spec.severity_map.items():
        try:
            sev_map[word] = Severity(value)
        except ValueError:
            raise MappingError(
                f"severity_map: {value!r} is not one of {', '.join(s.value for s in Severity)}"
            ) from None
    if len(sev_map) > 100:
        raise MappingError("severity_map has more than 100 entries")

    records: Any = None
    compiled: dict[str, Any] = {}
    if spec.format == "json":
        if not spec.records:
            raise MappingError("a JSON mapping needs a records path, like `$.findings[*]`")
        records = parse_json_path(spec.records, record_path=True)
        compiled = {k: parse_json_path(v) for k, v in spec.fields.items()}
    elif spec.format == "xml":
        if not spec.records:
            raise MappingError("an XML mapping needs a records path, like `report/issue`")
        records = parse_record_xml_path(spec.records)
        compiled = {k: parse_xml_path(v) for k, v in spec.fields.items()}
    else:
        if spec.records:
            raise MappingError("a CSV mapping has no records path: every row is one finding")
        for k, v in spec.fields.items():
            if len(v) > MAX_PATH:
                raise MappingError(f"the column name for {k} is too long")
        compiled = {k: v.strip().lower() for k, v in spec.fields.items()}
    return _Compiled(spec, records, compiled, sev_map)


# --- the parser ----------------------------------------------------------------------------------


class UniversalParser(IngestParser):
    """A saved mapping, as a parser. `name` is `universal:<mapping id>`, which is what an import
    records, so every import says exactly which mapping version read it."""

    formats = frozenset(FORMATS)
    categories = frozenset(c.value for c in Category)

    def __init__(self, spec: MappingSpec, name: str = "universal", label: str = "") -> None:
        self._c = compile_spec(spec)
        self.spec = spec
        self.name = name
        self.label = label or f"Mapped report ({spec.source})"
        self.formats = frozenset({spec.format})
        self.categories = frozenset({spec.category})
        self.default_dedup = (
            "package" if spec.category in ("sca", "container") else
            "tool_id" if "rule" in spec.fields else "fingerprint_v2"
        )  # fmt: skip

    def sniff(self, head: bytes) -> float:
        """How sure this mapping fits a file: only ever asked about saved mappings, and only used to
        *suggest* one -- a mapped import still names its parser."""
        text = head[:65536].decode("utf-8", errors="ignore").lstrip("﻿ \t\r\n")
        spec = self.spec
        if spec.format == "json":
            if not text.startswith(("{", "[")):
                return 0.0
            keys = [s for s in self._c.records.steps if isinstance(s, str)]
            leaves = [
                next((s for s in reversed(p.steps) if isinstance(s, str)), None)
                for p in self._c.fields.values()
            ]
            wanted = [*keys, *[k for k in leaves if k]]
            hits = sum(1 for k in wanted if json.dumps(k) in text)
            return round(0.95 * hits / len(wanted), 2) if wanted else 0.0
        if spec.format == "xml":
            if not text.startswith("<"):
                return 0.0
            names = self._c.records
            hits = sum(1 for n in names if re.search(rf"<(?:\w+:)?{re.escape(n)}[\s>/]", text))
            return round(0.95 * hits / len(names), 2)
        header = text.splitlines()[0] if text else ""
        cells = {c.strip().strip('"').strip().lower() for c in re.split(r"[;,]", header)}
        columns = set(self._c.fields.values())
        return round(0.95 * len(columns & cells) / len(columns), 2) if columns else 0.0

    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        skipped = 0
        records = 0
        for get in self._records(stream, ctx):
            records += 1
            finding = self._finding(get, ctx)
            if finding is None:
                skipped += 1
            else:
                yield finding
        if skipped:
            ctx.warn(f"{skipped} record(s) had no title and were skipped")
        if records == 0 and self.spec.format != "csv":
            ctx.warn(f"no records were found at {self.spec.records}")
        # A mapping that yields nothing cannot be told from a mapping that no longer fits the file
        # (a renamed key, a records path into the wrong list, a wrong title column): reimport would
        # read either as "everything was fixed". A known format's empty report says that; a
        # mapping's says only that the mapping found nothing, so it closes nothing.
        if records == skipped:
            ctx.can_close_missing = False
            ctx.warn(
                "the mapping found no findings in this file, so nothing will be closed; if the "
                "tool really reported nothing, close the Issues by hand"
            )

    # Each record is handed over as a `get(field) -> list[str]` function, so the finding builder
    # does not care which format it came from.
    def _records(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Any]:
        c = self._c
        if self.spec.format == "json":
            prefix = json_prefix(c.records)
            for _, value in stream_objects(
                json_events(stream, ctx), lambda p: "r" if p == prefix else None
            ):
                yield lambda name, rec=value: _strings(c.fields[name].values(rec))
        elif self.spec.format == "xml":
            want = c.records
            stack: list[str] = []
            for event, element in iter_xml(stream, ctx):
                if event == "start":
                    stack.append(_local(element.tag))
                    continue
                if len(stack) >= len(want) and tuple(stack[-len(want) :]) == want:
                    values = {k: p.values(element) for k, p in c.fields.items()}
                    yield lambda name, vals=values: vals[name]
                    element.clear()
                stack.pop()
        else:
            rows = iter_csv(stream, ctx)
            header = next(rows, None)
            if header is None:
                raise ParseAborted("the file is empty")
            index = {h.strip().lower(): i for i, h in enumerate(header)}
            missing = sorted(col for col in c.fields.values() if col not in index)
            if missing:
                raise ParseAborted(f"the CSV has no column(s) named {', '.join(missing)}")
            cols = {k: index[v] for k, v in c.fields.items()}
            last: list[str] = header
            for row in rows:
                if not any(cell.strip() for cell in row):
                    continue
                last = row
                yield lambda name, r=row: (
                    [r[cols[name]].strip()] if cols[name] < len(r) and r[cols[name]].strip() else []
                )
            # A short row mid-file is tolerated (some writers drop empty trailing fields); a short
            # last row is what a file cut off mid-line looks like, and reimport closes whatever a
            # file no longer lists.
            if len(last) < len(header):
                raise ParseAborted(
                    f"the last row has {len(last)} fields and the header has {len(header)}; "
                    "the file may be cut off"
                )

    def _finding(self, get: Any, ctx: ParseContext) -> Finding | None:
        spec = self.spec
        mapped = self._c.fields

        def one(name: str) -> str:
            if name not in mapped:
                return ""
            values = get(name)
            return values[0] if values else ""

        def many(name: str) -> list[str]:
            return get(name) if name in mapped else []

        title = " ".join(one("title").split())[:300]
        if not title:
            return None
        raw_severity = one("severity")
        severity = self._severity(raw_severity, ctx)
        description = plain_text(one("description")) or title
        cwes = _cwes(many("cwe"))
        cves = tuple(dict.fromkeys(c.upper() for c in _CVE.findall(" ".join(many("cve")))))
        rule = clip(one("rule"), 200)
        references = [
            r for r in _split(many("references")) if r.startswith(("https://", "http://"))
        ]
        remediation = Remediation(summary=plain_text(one("recommendation")), references=references)
        native = {spec.source: raw_severity.upper()} if raw_severity else {}
        category = Category(spec.category)

        if category is Category.DAST:
            host, route = target_of(one("url"))
            if not host:
                return None
            return dast_finding(
                spec.source,
                rule=rule or title,
                title=title,
                host=host,
                route=route,
                severity=severity,
                native=raw_severity.upper(),
                description=description,
                cwe=cwes,
                cve=list(cves),
                summary=remediation.summary,
                references=references,
                digest_of=f"{title}|{one('path')}",
                reported_by=spec.source,
            )

        evidence = Evidence(
            reported_by=[spec.source], rule_ids={spec.source: [rule]} if rule else {}
        )
        package_name = one("package")
        if category in (Category.SCA, Category.CONTAINER) and package_name:
            version = one("version")
            eco = Package.normalize_ecosystem(
                one("ecosystem") or spec.default_ecosystem or "unknown"
            )
            snippet = f"{package_name}@{version}"
            path = one("path") or "unknown"
            key = cves[0] if cves else (rule or title)
            return Finding(
                id=f"{spec.source}:{key}:{path}:{snippet}"[:300],
                title=(f"{cves[0]}: {title}" if cves and cves[0] not in title else title)[:300],
                description=description,
                location=Location(path, 1, 1, snippet, Location.hash_snippet(snippet)),
                taxonomy=Taxonomy(category, cwe=cwes, cve=cves, aliases=cves),
                scoring=Scoring(native_severity=native, normalized_severity=severity),
                evidence=evidence,
                remediation=remediation,
                package=Package(package_name, version, eco),
            )

        path = one("path") or "unknown"
        line = _line(one("line"))
        digest = hashlib.sha256(f"{title}|{path}|{line}|{rule}".encode()).hexdigest()[:12]
        return Finding(
            id=f"{spec.source}:{rule or digest}:{path}:{line}"[:300],
            title=title,
            description=description,
            location=Location(path, line, line),
            taxonomy=Taxonomy(category, cwe=cwes, cve=cves),
            scoring=Scoring(native_severity=native, normalized_severity=severity),
            evidence=evidence,
            remediation=remediation,
        )

    def _severity(self, raw: str, ctx: ParseContext) -> Severity:
        """The mapping's own words first, then the common ones, then a CVSS-like number; anything
        else is Info and said so -- never guessed up or down."""
        if "severity" not in self._c.fields:
            return Severity.INFO
        word = raw.strip().lower()
        if word in self._c.severity_map:
            return self._c.severity_map[word]
        if word in SEVERITY_WORDS:
            return SEVERITY_WORDS[word]
        try:
            score = float(word)
        except ValueError:
            ctx.unknown_severity(raw)
            return Severity.INFO
        if 0.0 <= score <= 10.0:
            return from_cvss(score)
        ctx.unknown_severity(raw)
        return Severity.INFO


def _strings(values: list[Any]) -> list[str]:
    out = []
    for v in values:
        if isinstance(v, bool):
            out.append("true" if v else "false")
        elif isinstance(v, float) and v.is_integer():
            out.append(str(int(v)))
        else:
            s = str(v).strip()
            if s:
                out.append(s)
    return out


def _cwes(values: list[str]) -> tuple[str, ...]:
    """`CWE-79` from "CWE-79: Cross-site scripting", "cwe 79", "79" or "79, 89"; a value that names
    no weakness gives none rather than a guess."""
    found: list[str] = []
    for v in values:
        named = _CWE_IN_TEXT.findall(v)
        found.extend(named if named else [p for p in _split([v]) if p.isdigit()])
    return cwe_ids(found)


def _split(values: list[str]) -> list[str]:
    """`["CWE-79, CWE-89"]` -> `["CWE-79", "CWE-89"]`: a CSV cell often lists several."""
    return [p for v in values for p in re.split(r"[,;\s|]+", v) if p]


def _line(value: str) -> int:
    m = re.match(r"\s*(\d{1,9})", value or "")
    return max(int(m.group(1)), 1) if m else 1


__all__ = [
    "FIELDS",
    "FORMATS",
    "MappingError",
    "MappingSpec",
    "UniversalParser",
    "compile_spec",
    "parse_json_path",
    "parse_xml_path",
]
