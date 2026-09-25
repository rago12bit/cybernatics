"""What every JSON-output adapter repeats, once.

An adapter says HOW TO RUN the tool (`spec`, `build_command`) and HOW TO READ one record of its
output (`records`, `to_finding`). Parsing safety (bad JSON, missing keys, one malformed record
must not lose the rest), the canonical Finding shape, hashing and severity normalisation live
here, so a new scanner is short and cannot forget any of them (docs/adding-a-scanner.md).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import Any

from core.adapters.base import ToolAdapter
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
from core.scoring.severity import normalize

log = logging.getLogger(__name__)
CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
_BAD_RECORD = (KeyError, TypeError, ValueError, IndexError, AttributeError)


def make_finding(
    tool: str,
    category: Category,
    *,
    rule: str,
    title: str,
    path: str,
    start: int = 1,
    end: int | None = None,
    snippet: str = "",
    native: str,
    description: str = "",
    confidence: float = 0.5,
    cwe: Iterable[str] = (),
    cve: Iterable[str] = (),
    aliases: Iterable[str] = (),
    refs: Iterable[str | None] = (),
    summary: str = "",
    package: Package | None = None,
    cvss: float | None = None,
    key: str = "",
) -> Finding:
    """The canonical Finding for one record. `key` separates ids sharing rule, path and line."""
    native = native.upper()
    return Finding(
        id=f"{tool}:{rule}:{path}:{key or start}",
        title=title[:300],
        description=description or title,
        location=Location(path, start, end or start, snippet, Location.hash_snippet(snippet)),
        taxonomy=Taxonomy(
            category,
            cwe=tuple(dict.fromkeys(cwe)),
            cve=tuple(dict.fromkeys(cve)),
            aliases=tuple(dict.fromkeys(aliases)),
        ),
        scoring=Scoring(
            native_severity={tool: native},
            normalized_severity=normalize(tool, native),
            cvss_v3_1=cvss,
            confidence=confidence,
        ),
        evidence=Evidence(reported_by=[tool], rule_ids={tool: [rule]}),
        remediation=Remediation(summary=summary, references=[r for r in refs if r]),
        package=package,
    )


class JsonAdapter(ToolAdapter):
    """Adapter for a tool whose output is one JSON document holding a list of records."""

    def records(self, doc: Any) -> Iterable[dict[str, Any]]:
        raise NotImplementedError

    def to_finding(self, rec: dict[str, Any]) -> Finding | None:
        raise NotImplementedError

    def parse(self, raw: bytes) -> list[Finding]:
        """Never raises: unreadable output is [], and one malformed record is skipped, not fatal."""
        tool = self.spec.name
        try:
            records = list(self.records(json.loads(raw)))
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("%s: could not parse output: %s", tool, exc)
            return []
        out: list[Finding] = []
        for rec in records:
            try:
                if (f := self.to_finding(rec)) is not None:
                    out.append(f)
            except _BAD_RECORD as exc:
                log.warning("%s: skipping malformed record: %s", tool, exc)
        return out
