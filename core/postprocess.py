"""What every scan does to correlated findings before they are stored or shown.

One function, used by both the CLI path (core/scan.py) and the API path (core/pipeline.py), because
those two paths once drifted and one of them silently skipped the OWASP mapping.
"""

from __future__ import annotations

from core.models import Finding
from core.redact import redact_near_secrets
from core.risk import Feeds, apply_risk
from core.taxonomy import enrich_all


def finalize(correlated: list[Finding], feeds: Feeds | None = None) -> list[Finding]:
    # Order matters: correlate (done by the caller) -> map -> score -> redact last.
    return redact_near_secrets(apply_risk(enrich_all(correlated), feeds))
