"""Cross-tool secret redaction (threat T7).

Gitleaks output is redacted at the source, but other tools (e.g. Bandit B105) echo the
offending source line as their snippet. Any finding whose lines fall within CONTEXT_LINES of a
detected secret has its snippet withheld and quoted literals in its title/description scrubbed,
since we cannot know which nearby line holds the value.
"""

from __future__ import annotations

import re
from collections import defaultdict

from core.models import Category, Finding, Location

CONTEXT_LINES = 3
_QUOTED = re.compile(r"(['\"])[^'\"]{6,}\1")
WITHHELD = "[snippet withheld: near a detected secret]"


def redact_near_secrets(findings: list[Finding]) -> list[Finding]:
    secret_lines: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for f in findings:
        if f.taxonomy.category is Category.SECRETS:
            secret_lines[f.location.path].append((f.location.start_line, f.location.end_line))
    if not secret_lines:
        return findings
    for f in findings:
        if f.taxonomy.category is Category.SECRETS:
            continue
        loc = f.location
        if any(
            loc.start_line <= end + CONTEXT_LINES and loc.end_line >= start - CONTEXT_LINES
            for start, end in secret_lines.get(loc.path, ())
        ):
            f.title = _QUOTED.sub("'[redacted]'", f.title)
            f.description = _QUOTED.sub("'[redacted]'", f.description)
            f.location = Location(
                loc.path, loc.start_line, loc.end_line, WITHHELD, Location.hash_snippet(WITHHELD)
            )
    return findings
