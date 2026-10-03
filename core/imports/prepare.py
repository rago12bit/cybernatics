"""What an imported report's findings go through before they are compared or stored: the same steps
a scan's findings do (`core.scan`, `core.postprocess.finalize`), because an Issue is the same Issue
however it arrived.

Parsers produce canonical `Finding`s without identity or scoring. Skipping this step is not a
shortcut: every finding would carry an empty fingerprint, and reimport -- which matches findings to
Issues by fingerprint -- would collapse a whole report into one Issue (found by the first end-to-end
test of the ingest API, which is why this is a named step and not an inline call).
"""

from __future__ import annotations

from core.correlation import correlate
from core.models import Finding
from core.postprocess import finalize
from core.redact import redact_secret_findings


def prepare(findings: list[Finding]) -> list[Finding]:
    """Redact secrets, give every finding its identity and merge duplicates (`correlate`), then
    enrich, score and redact near secrets (`finalize`) -- in the order a scan does."""
    correlated, _ = correlate(redact_secret_findings(findings))
    return finalize(correlated)
