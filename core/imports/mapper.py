"""The universal mapper outside the sandbox (plan §42.4, ADR-0043): saving mappings, resolving a
saved one into a parser, and drafting one from a sample's description.

    1. Upload a sample. Its *shape* is described in the sandbox (`parsers.analyze`).
    2. A draft mapping is proposed from that description: by the model when one is configured
       (`propose_with_model`), otherwise -- or when the model's draft does not hold up -- by name
       matching (`propose_heuristic`). Either way it is a draft.
    3. A person edits it against a live preview, then saves it. The saved mapping is a
       deterministic parser (`parsers.universal`); the model is never in the import path.

The model is shown the description, never the file, and its answer is checked against it: a path it
names that the sample does not have is dropped, not trusted (`sanitize`).
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.imports.parsers.base import IngestParser
from core.imports.parsers.registry import PARSERS, get_parser
from core.imports.parsers.universal import (
    FIELDS,
    SEVERITY_WORDS,
    MappingError,
    MappingSpec,
    UniversalParser,
)
from core.llm.client import LLMClient
from core.llm.prompt import load_prompt
from core.llm.scrub import injection_signals, scrub_secrets
from core.models import Severity
from core.persistence.models import IngestMapping

log = logging.getLogger(__name__)

PREFIX = "universal:"
SYSTEM = load_prompt("mapper", "v1")
MAX_DESCRIPTION_CHARS = 12_000
NAME_RE = re.compile(r"^[^\x00-\x1f]{1,200}$")

# The words a field is commonly called, best first. Matched on the last key of a path, lower-cased
# with everything but letters and digits removed ("Check ID" and "check_id" are both "checkid").
SYNONYMS: dict[str, tuple[str, ...]] = {
    "title": ("title", "name", "summary", "issuename", "vulnerabilityname", "checkname",
              "rulename", "alert", "alertname", "issue", "vulnerability", "finding", "message"),
    "severity": ("severity", "risk", "risklevel", "level", "priority", "criticality", "sev",
                 "impact", "rating", "cvssscore", "cvss", "score"),
    "description": ("description", "details", "detail", "desc", "longdescription", "message",
                    "explanation"),
    "path": ("file", "filename", "filepath", "path", "sourcefile", "location", "manifest",
             "manifestpath", "target"),
    "line": ("line", "linenumber", "lineno", "startline", "beginline", "row"),
    "rule": ("ruleid", "checkid", "rule", "check", "pluginid", "testid", "vulnid", "code",
             "type", "id"),
    "cwe": ("cwe", "cweid", "cwes", "weakness", "cweids"),
    "cve": ("cve", "cveid", "cves", "vulnerabilityid", "advisory", "advisoryid", "cveids"),
    "url": ("url", "uri", "endpoint", "targeturl", "requesturl", "link"),
    "package": ("package", "packagename", "pkg", "pkgname", "component", "componentname",
                "dependency", "library", "module", "artifact"),
    "version": ("version", "installedversion", "packageversion", "currentversion",
                "componentversion", "pkgversion"),
    "ecosystem": ("ecosystem", "packagemanager", "packagetype", "pkgtype"),
    "recommendation": ("recommendation", "remediation", "solution", "fix", "mitigation",
                       "resolution", "fixrecommendation"),
    "references": ("references", "links", "urls", "seealso", "refs", "reference"),
}  # fmt: skip


# --- saved mappings ------------------------------------------------------------------------------


def parser_name(mapping_id: str) -> str:
    return f"{PREFIX}{mapping_id}"


def is_mapped(name: str) -> bool:
    return name.startswith(PREFIX)


def save_mapping(
    s: Session,
    *,
    org_id: str,
    name: str,
    spec: MappingSpec,
    proposed_by: str | None = None,
    sample_digest: str | None = None,
    created_by: str | None = None,
) -> IngestMapping:
    """Add the next version of a mapping called `name` (version 1 if new). Never edits a row."""
    name = " ".join(name.split())
    if not NAME_RE.match(name):
        raise MappingError("a mapping name is 1-200 characters")
    reserved = spec.source in PARSERS or spec.source in _TOOL_NAMES
    if reserved:
        raise MappingError(
            f"{spec.source!r} is the name of a built-in parser or scanner; findings from a mapped "
            "report need their own source name, or their deduplication settings would be shared"
        )
    latest = s.scalar(
        select(func.max(IngestMapping.version)).where(
            IngestMapping.org_id == org_id, IngestMapping.name == name
        )
    )
    row = IngestMapping(
        org_id=org_id,
        name=name,
        version=(latest or 0) + 1,
        source=spec.source,
        format=spec.format,
        spec=spec.to_dict(),
        proposed_by=proposed_by,
        sample_digest=sample_digest,
        created_by=created_by,
    )
    s.add(row)
    s.flush()
    return row


def get_mapping(s: Session, mapping_id: str, org_id: str) -> IngestMapping | None:
    return s.scalars(
        select(IngestMapping).where(IngestMapping.id == mapping_id, IngestMapping.org_id == org_id)
    ).one_or_none()


def list_mappings(s: Session, org_id: str) -> list[IngestMapping]:
    """The latest version of each mapping, by name."""
    latest = (
        select(IngestMapping.name, func.max(IngestMapping.version).label("v"))
        .where(IngestMapping.org_id == org_id)
        .group_by(IngestMapping.name)
        .subquery()
    )
    return list(
        s.scalars(
            select(IngestMapping)
            .join(
                latest,
                (IngestMapping.name == latest.c.name) & (IngestMapping.version == latest.c.v),
            )
            .where(IngestMapping.org_id == org_id)
            .order_by(IngestMapping.name)
        )
    )


def versions(s: Session, org_id: str, name: str) -> list[IngestMapping]:
    return list(
        s.scalars(
            select(IngestMapping)
            .where(IngestMapping.org_id == org_id, IngestMapping.name == name)
            .order_by(IngestMapping.version.desc())
        )
    )


def parser_for(row: IngestMapping) -> UniversalParser:
    return UniversalParser(
        MappingSpec.from_dict(row.spec), parser_name(row.id), f"{row.name} (v{row.version})"
    )


def resolve(s: Session, org_id: str, name: str) -> tuple[IngestParser, dict[str, Any] | None]:
    """The parser an import names, and -- for a saved mapping -- the spec to ship into the sandbox.
    A mapping id from another org is "unknown", the same as one that never existed."""
    if not is_mapped(name):
        return get_parser(name), None
    row = get_mapping(s, name[len(PREFIX) :], org_id)
    if row is None:
        raise ValueError(f"unknown mapping {name!r}")
    return parser_for(row), dict(row.spec)


def _tool_names() -> frozenset[str]:
    try:
        from core.scan import ADAPTERS

        return frozenset(ADAPTERS)
    except Exception:  # noqa: BLE001 - a missing optional adapter must not break saving mappings
        return frozenset()


_TOOL_NAMES = _tool_names()


# --- drafting a mapping --------------------------------------------------------------------------


@dataclass
class Proposal:
    spec: dict[str, Any]  # a draft: may still fail validation until a person completes it
    proposed_by: str  # "heuristic" or "model:<name>"
    notes: list[str] = field(default_factory=list)
    tokens_used: int = 0


def _norm(path: str) -> str:
    """The last key of a path, as a bare word: `$.loc["Check ID"]` -> `checkid`."""
    last = re.split(r"[.\[\]/@\"]+", path.replace("[*]", ""))
    words = [w for w in last if w and w != "$"]
    return re.sub(r"[^a-z0-9]", "", words[-1].lower()) if words else ""


def _candidate_score(c: dict[str, Any]) -> tuple[int, int, int]:
    names = {_norm(f["path"]) for f in c.get("fields", [])}
    has_title = int(bool(names & set(SYNONYMS["title"])))
    has_severity = int(bool(names & set(SYNONYMS["severity"])))
    return (has_title + has_severity, int(c.get("count") or 0), len(names))


def propose_heuristic(analysis: dict[str, Any], *, source: str = "") -> Proposal:
    """A draft from field names alone: deterministic, offline, and honest about being a guess."""
    candidates = analysis.get("candidates") or []
    fmt = analysis.get("format") or "json"
    notes: list[str] = []
    if not candidates:
        return Proposal({"format": fmt, "source": source, "fields": {}}, "heuristic",
                        ["The sample has no list of records to map."])  # fmt: skip
    best = max(candidates, key=_candidate_score)
    fields = [f for f in best.get("fields", []) if f.get("filled")]
    chosen: dict[str, str] = {}
    used: set[str] = set()
    for target, words in SYNONYMS.items():
        ranked = []
        for f in fields:
            name = _norm(f["path"])
            if name in words and f["path"] not in used:
                depth = f["path"].count(".") + f["path"].count("/") + f["path"].count("[")
                ranked.append((words.index(name), depth, -int(f.get("filled") or 0), f["path"]))
        if ranked:
            path = min(ranked)[3]
            # A many-valued path ([*]) only fits a many-valued field; "title" from a list is wrong.
            if "[*]" in path and not FIELDS[target]:
                continue
            chosen[target] = path
            used.add(path)
    if "title" not in chosen and "description" in chosen:
        chosen["title"] = chosen.pop("description")
        notes.append("No title-like field was found; the description is used as the title.")
    category = "sast"
    if "package" in chosen and "url" not in chosen:
        category = "sca"
    elif "url" in chosen and "path" not in chosen:
        category = "dast"
    severity_map = _severity_map(best, chosen.get("severity"))
    unknown = [w for w in _severity_examples(best, chosen.get("severity")) if w not in severity_map
               and w not in SEVERITY_WORDS and not _numeric(w)]  # fmt: skip
    if unknown:
        notes.append(
            "These severity values are not common words and are not mapped yet: "
            + ", ".join(repr(w) for w in unknown)
            + ". Unmapped values import as Info."
        )
    if "title" not in chosen:
        notes.append("Choose which field is the title; nothing obviously named was found.")
    return Proposal(
        {
            "format": fmt,
            "source": source,
            "records": best.get("records"),
            "category": category,
            "fields": chosen,
            "severity_map": severity_map,
        },
        "heuristic",
        notes,
    )


def _severity_examples(candidate: dict[str, Any], path: str | None) -> list[str]:
    if not path:
        return []
    for f in candidate.get("fields", []):
        if f["path"] == path:
            return [str(e).strip().lower() for e in f.get("examples", []) if str(e).strip()]
    return []


def _numeric(word: str) -> bool:
    try:
        return 0.0 <= float(word) <= 10.0
    except ValueError:
        return False


# Single-letter and numeric scales are common enough to draft, and say so in the UI.
_SCALES = {"c": "CRITICAL", "h": "HIGH", "m": "MEDIUM", "l": "LOW", "i": "INFO", "p1": "CRITICAL",
           "p2": "HIGH", "p3": "MEDIUM", "p4": "LOW", "p5": "INFO", "blocker": "CRITICAL",
           "major": "HIGH", "warning": "MEDIUM", "warn": "MEDIUM", "error": "HIGH",
           "severe": "HIGH", "urgent": "CRITICAL"}  # fmt: skip


def _severity_map(candidate: dict[str, Any], path: str | None) -> dict[str, str]:
    return {w: _SCALES[w] for w in _severity_examples(candidate, path) if w in _SCALES}


def describe(analysis: dict[str, Any]) -> tuple[str, int, list[str]]:
    """The analysis as the model sees it: secrets scrubbed from every example, cut to size.
    Returns the text, how many secrets were removed, and any prompt-injection signals."""
    slim = {
        "format": analysis.get("format"),
        "candidates": [
            {
                "records": c.get("records"),
                "count": c.get("count"),
                "fields": [
                    {"path": f["path"], "examples": f.get("examples", [])[:3]}
                    for f in c.get("fields", [])[:80]
                ],
            }
            for c in (analysis.get("candidates") or [])[:5]
        ],
    }
    text, scrubbed = scrub_secrets(json.dumps(slim, ensure_ascii=False, indent=1))
    if len(text) > MAX_DESCRIPTION_CHARS:
        text = text[:MAX_DESCRIPTION_CHARS] + "\n[truncated]"
    return text, scrubbed, injection_signals(text)


def build_prompt(analysis: dict[str, Any]) -> tuple[str, int, list[str]]:
    """The user message: the description, nonce-fenced as untrusted data (the same fencing as every
    other prompt, `core.llm.prompt`). Returns it with the secrets-removed count and any signals."""
    text, scrubbed, signals = describe(analysis)
    nonce = secrets.token_hex(6)
    user = (
        f"=====BEGIN UNTRUSTED DATA [{nonce}] kind=description=====\n{text}\n"
        f"=====END UNTRUSTED DATA [{nonce}]=====\n\n"
        "Draft a mapping for the report described in the data block above. Reply with the single "
        "JSON object described in the system message, and nothing else."
    )
    return user, scrubbed, signals


def propose_with_model(
    analysis: dict[str, Any], client: LLMClient, *, source: str = ""
) -> Proposal | None:
    """A model's draft, checked against the sample's own description. `None` when the call fails or
    the reply is unusable -- the caller then offers the heuristic draft, saying why."""
    user, scrubbed, signals = build_prompt(analysis)
    try:
        completion = client.complete(SYSTEM, user)
    except Exception as exc:  # noqa: BLE001 - any failure means "no model draft", never a crash
        log.warning("mapper model call failed: %s", type(exc).__name__)
        return None
    notes: list[str] = []
    if signals:
        notes.append(
            "The sample contained text that looks like instructions to an AI "
            f"({', '.join(signals)}). It was treated as data."
        )
    if scrubbed:
        notes.append(
            f"{scrubbed} possible secret(s) were removed from the examples before sending."
        )
    try:
        reply = json.loads(_strip_fences(completion.text))
    except ValueError:
        log.warning("mapper model reply was not JSON")
        return None
    if not isinstance(reply, dict):
        return None
    spec, dropped = sanitize(reply, analysis, source)
    if dropped:
        notes.append("Ignored from the model's draft: " + "; ".join(dropped) + ".")
    model_note = reply.get("notes")
    if isinstance(model_note, str) and model_note.strip():
        notes.append("Model: " + " ".join(model_note.split())[:400])
    if "title" not in spec["fields"]:
        return None
    return Proposal(spec, f"model:{client.model}", notes, completion.tokens)


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
        t = t.rsplit("```", 1)[0]
    return t.strip()


def sanitize(
    reply: dict[str, Any], analysis: dict[str, Any], source: str
) -> tuple[dict[str, Any], list[str]]:
    """Keep only what the sample can back up: a records path that is one of its candidates, field
    paths that candidate really has, severities that are real severities."""
    dropped: list[str] = []
    candidates = analysis.get("candidates") or []
    by_records = {c.get("records"): c for c in candidates}
    records = reply.get("records")
    if records not in by_records:
        dropped.append(f"records path {records!r} (not in the sample)")
        records = max(candidates, key=_candidate_score).get("records") if candidates else None
    candidate = by_records.get(records) or {}
    paths = {f["path"] for f in candidate.get("fields", [])}
    fields: dict[str, str] = {}
    raw_fields: dict[Any, Any] = reply["fields"] if isinstance(reply.get("fields"), dict) else {}
    for name, path in raw_fields.items():
        if name not in FIELDS:
            dropped.append(f"field {name!r} (not a field)")
        elif not isinstance(path, str) or path not in paths:
            dropped.append(f"{name} -> {path!r} (no such path)")
        elif "[*]" in path and not FIELDS[name]:
            dropped.append(f"{name} -> {path!r} (a list, for a single-valued field)")
        else:
            fields[name] = path
    seen = set(_severity_examples(candidate, fields.get("severity")))
    severity_map: dict[str, str] = {}
    raw_map: dict[Any, Any] = (
        reply["severity_map"] if isinstance(reply.get("severity_map"), dict) else {}
    )
    for word, sev in raw_map.items():
        w, v = str(word).strip().lower(), str(sev).strip().upper()
        if v not in Severity.__members__:
            dropped.append(f"severity {word!r} -> {sev!r}")
        elif w in seen:
            severity_map[w] = v
    category = str(reply.get("category") or "sast").lower()
    if category not in ("sast", "sca", "secrets", "iac", "container", "dast"):
        dropped.append(f"category {category!r}")
        category = "sast"
    return (
        {
            "format": analysis.get("format") or "json",
            "source": source,
            "records": records,
            "category": category,
            "fields": fields,
            "severity_map": severity_map,
        },
        dropped,
    )


def suggest_source(file_name: str | None) -> str:
    """A starting source name from the sample's file name: `acme-scan_2026.json` -> `acme-scan`."""
    stem = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", (file_name or "").strip().lower())
    stem = re.sub(r"[^a-z0-9._-]+", "-", stem)
    stem = re.sub(r"[-_.]*\d{4,}.*$", "", stem).strip("-_.")
    return stem[:40] if len(stem) >= 2 else "mapped-report"


__all__ = [
    "PREFIX",
    "Proposal",
    "build_prompt",
    "describe",
    "get_mapping",
    "is_mapped",
    "list_mappings",
    "parser_for",
    "parser_name",
    "propose_heuristic",
    "propose_with_model",
    "resolve",
    "sanitize",
    "save_mapping",
    "suggest_source",
    "versions",
]
