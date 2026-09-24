"""Bandit adapter (Python SAST). The pathfinder adapter: simplest output format."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from core.adapters.base import ToolAdapter, ToolSpec
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

log = logging.getLogger(__name__)

_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
_CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}
_TARGET_PREFIX = "/target/"


class BanditAdapter(ToolAdapter):
    spec = ToolSpec(
        name="bandit",
        image="bulwark/bandit:1.7.10",
        categories=frozenset({"sast"}),
        languages=frozenset({"python"}),
        timeout_seconds=600,
    )

    def build_command(self, target: Path, output: Path) -> list[str]:
        return ["-r", str(target), "-f", "json", "-o", str(output), "-q"]

    def parse(self, raw: bytes) -> list[Finding]:
        try:
            data = json.loads(raw)
            results = data["results"]
            return [f for r in results if (f := self._to_finding(r)) is not None]
        except (ValueError, KeyError, TypeError) as exc:
            log.warning("bandit: could not parse output: %s", exc)
            return []

    def _to_finding(self, r: dict[str, Any]) -> Finding | None:
        try:
            path = str(r["filename"]).removeprefix(_TARGET_PREFIX)
            line_range = r.get("line_range") or [r["line_number"]]
            snippet = str(r.get("code", ""))
            native = str(r["issue_severity"]).upper()
            cwe = r.get("issue_cwe") or {}
            return Finding(
                id=f"bandit:{r['test_id']}:{path}:{r['line_number']}",
                title=str(r["issue_text"]),
                description=f"{r['test_name']} ({r['test_id']}): {r['issue_text']}",
                location=Location(
                    path=path,
                    start_line=int(min(line_range)),
                    end_line=int(max(line_range)),
                    snippet=snippet,
                    snippet_hash=Location.hash_snippet(snippet),
                ),
                taxonomy=Taxonomy(Category.SAST, cwe=(f"CWE-{cwe['id']}",) if "id" in cwe else ()),
                scoring=Scoring(
                    native_severity={"bandit": native},
                    normalized_severity=_SEVERITY.get(native, Severity.INFO),
                    confidence=_CONFIDENCE.get(str(r.get("issue_confidence", "")).upper(), 0.5),
                ),
                evidence=Evidence(reported_by=["bandit"], rule_ids={"bandit": str(r["test_id"])}),
                remediation=Remediation(references=[r["more_info"]] if r.get("more_info") else []),
            )
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("bandit: skipping malformed result: %s", exc)
            return None
