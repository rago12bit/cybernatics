"""Gitleaks adapter (secret detection).

Threat T7: secrets must never leak through our own output. Gitleaks runs with --redact so the
raw secret is never written to the output file, and this adapter additionally never copies
`Secret`/`Match` from the raw record into a Finding.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from core.adapters.base import TARGET_PREFIX, RepoContext, ToolAdapter, ToolSpec
from core.models import (
    Category,
    Evidence,
    Finding,
    Location,
    Remediation,
    Scoring,
    Taxonomy,
)
from core.scoring.severity import normalize

log = logging.getLogger(__name__)


class GitleaksAdapter(ToolAdapter):
    spec = ToolSpec(
        name="gitleaks",
        image="zricethezav/gitleaks:v8.21.0",
        categories=frozenset({"secrets"}),
        languages=frozenset(),
        timeout_seconds=300,
    )

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "detect",
            "--no-git",
            "--source",
            str(target),
            "--report-format",
            "json",
            "--report-path",
            str(output),
            "--redact",
            "--no-banner",
        ]

    def applies_to(self, ctx: RepoContext) -> bool:
        return True  # secrets can live in any file

    def parse(self, raw: bytes) -> list[Finding]:
        try:
            records = json.loads(raw)
            if not isinstance(records, list):
                raise TypeError("expected a JSON array")
        except (ValueError, TypeError) as exc:
            log.warning("gitleaks: could not parse output: %s", exc)
            return []
        return [f for r in records if (f := self._to_finding(r)) is not None]

    def _to_finding(self, r: dict[str, Any]) -> Finding | None:
        try:
            path = str(r["File"]).removeprefix(TARGET_PREFIX)
            start, end = int(r["StartLine"]), int(r["EndLine"])
            rule_id = str(r["RuleID"])
            # Snippet is deliberately a fixed placeholder: never store secret-bearing text.
            snippet = "[secret redacted]"
            ident = hashlib.sha256(f"{rule_id}:{path}:{start}".encode()).hexdigest()[:12]
            return Finding(
                id=f"gitleaks:{ident}",
                title=str(r.get("Description") or rule_id),
                description=f"Possible hardcoded secret matched rule '{rule_id}'.",
                location=Location(path, start, end, snippet, Location.hash_snippet(snippet)),
                taxonomy=Taxonomy(Category.SECRETS, cwe=("CWE-798",)),
                scoring=Scoring(
                    native_severity={"gitleaks": "ALL"},
                    normalized_severity=normalize("gitleaks", "ANY"),
                    confidence=0.7,
                ),
                evidence=Evidence(reported_by=["gitleaks"], rule_ids={"gitleaks": [rule_id]}),
                remediation=Remediation(
                    summary="Rotate this credential and load it from the environment or a "
                    "secrets manager; committed secrets should be treated as compromised.",
                    references=["https://cwe.mitre.org/data/definitions/798.html"],
                    generated_by="static",
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            log.warning("gitleaks: skipping malformed record: %s", exc)
            return None
