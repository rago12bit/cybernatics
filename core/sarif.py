"""Shared SARIF 2.1.0 ingestion (ADR-001). Any tool that emits SARIF reuses this."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from core.adapters.base import TARGET_PREFIX
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

_CWE_RE = re.compile(r"\bCWE-\d+\b")
_OWASP_2021_RE = re.compile(r"\bOWASP-(A\d{2}:2021)\b")
_CONFIDENCE_RE = re.compile(r"\b(LOW|MEDIUM|HIGH) CONFIDENCE\b", re.IGNORECASE)
# SARIF levels -> the tool's own vocabulary in the matrix (Semgrep says ERROR/WARNING/INFO).
_SARIF_LEVELS = {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}
_CONFIDENCE = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}


def parse_sarif(
    raw: bytes,
    *,
    tool: str,
    category: Category,
    strip_rule_prefix: str = "",
) -> list[Finding]:
    """SARIF bytes -> Findings. Never raises on malformed input."""
    try:
        doc = json.loads(raw)
        findings: list[Finding] = []
        for run in doc["runs"]:
            rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                f = _to_finding(result, rules, tool, category, strip_rule_prefix)
                if f is not None:
                    findings.append(f)
        return findings
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        log.warning("%s: could not parse SARIF: %s", tool, exc)
        return []


def _to_finding(
    result: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    tool: str,
    category: Category,
    strip_prefix: str,
) -> Finding | None:
    try:
        raw_rule_id = str(result["ruleId"])
        rule = rules.get(raw_rule_id, {})
        rule_id = raw_rule_id.removeprefix(strip_prefix)
        phys = result["locations"][0]["physicalLocation"]
        region = phys["region"]
        path = str(phys["artifactLocation"]["uri"]).removeprefix(TARGET_PREFIX)
        start = int(region["startLine"])
        end = int(region.get("endLine", start))
        snippet = str(region.get("snippet", {}).get("text", ""))
        level = str(result.get("level") or rule.get("defaultConfiguration", {}).get("level", ""))
        tags = [str(t) for t in rule.get("properties", {}).get("tags", [])]
        tag_text = " | ".join(tags)
        conf = _CONFIDENCE_RE.search(tag_text)
        message = str(result.get("message", {}).get("text", ""))
        title = message.split(". ")[0][:200] or rule_id
        return Finding(
            id=f"{tool}:{rule_id}:{path}:{start}",
            title=title,
            description=message,
            location=Location(path, start, end, snippet, Location.hash_snippet(snippet)),
            taxonomy=Taxonomy(
                category,
                cwe=tuple(dict.fromkeys(_CWE_RE.findall(tag_text))),
                owasp_top_10_2021=tuple(dict.fromkeys(_OWASP_2021_RE.findall(tag_text))),
            ),
            scoring=Scoring(
                native_severity={tool: level.upper()},
                normalized_severity=normalize(tool, _SARIF_LEVELS.get(level.lower(), level)),
                confidence=_CONFIDENCE[conf.group(1).upper()] if conf else 0.5,
            ),
            evidence=Evidence(reported_by=[tool], rule_ids={tool: [rule_id]}),
            remediation=Remediation(
                references=[rule["helpUri"]] if rule.get("helpUri") else [],
                suggested_patch=_patch_from_fixes(result, path, start, end, snippet),
            ),
        )
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        log.warning("%s: skipping malformed SARIF result: %s", tool, exc)
        return None


MAX_PATCH_CHARS = 4000


def _patch_from_fixes(
    result: dict[str, Any], path: str, start: int, end: int, snippet: str
) -> str | None:
    """A tool's own autofix as a one-line unified diff, or None when it is not safely convertible.

    Semgrep reports the replaced columns but the WHOLE fixed line as inserted text, so the fix is
    only converted when the finding is one line and the inserted line keeps the original text
    before and after the replaced columns. Anything else is dropped: a wrong patch is
    worse than none.
    """
    try:
        fixes = result.get("fixes") or []
        if len(fixes) != 1 or start != end or "\n" in snippet.strip("\r\n"):
            return None
        changes = fixes[0]["artifactChanges"]
        if len(changes) != 1 or len(changes[0]["replacements"]) != 1:
            return None
        rep = changes[0]["replacements"][0]
        region = rep["deletedRegion"]
        sc, ec = int(region["startColumn"]), int(region["endColumn"])
        if int(region["startLine"]) != start or int(region["endLine"]) != end or not 0 < sc <= ec:
            return None
        old = snippet.strip("\r\n")
        new = str(rep["insertedContent"]["text"]).strip("\r\n")
        if not old or not new or new == old or "\n" in new or len(new) > MAX_PATCH_CHARS:
            return None
        if not (new.startswith(old[: sc - 1]) and new.endswith(old[ec - 1 :])):
            return None
        return f"--- a/{path}\n+++ b/{path}\n@@ -{start},1 +{start},1 @@\n-{old}\n+{new}\n"
    except (KeyError, IndexError, TypeError, ValueError):
        return None
