"""What every scan does to correlated findings before they are stored or shown.

One function, used by both the CLI path (core/scan.py) and the API path (core/pipeline.py), because
those two paths once drifted and one of them silently skipped the OWASP mapping.
"""

from __future__ import annotations

from pathlib import Path

from core.models import Finding
from core.reachability import Reachability, ReachabilityIndex
from core.redact import redact_near_secrets
from core.risk import Feeds, apply_risk
from core.taint import TaintResult
from core.taint.reachability import attach_taint_paths, build_index
from core.taxonomy import enrich_all


def finalize(
    correlated: list[Finding],
    feeds: Feeds | None = None,
    reach: ReachabilityIndex | None = None,
    taint: TaintResult | None = None,
    root: Path | None = None,
) -> list[Finding]:
    # Order matters: correlate (done by the caller) -> map -> attach taint paths (so the confidence
    # bump they carry is in place before scoring runs) -> score -> redact last. `root` (the scanned
    # workspace) only reads a few lines of per-step context for the UI; scoring/reachability need
    # none of it.
    findings = attach_taint_paths(enrich_all(correlated), taint.findings if taint else [], root)
    taint_index = build_index(taint.findings) if taint else None

    def assess(f: Finding) -> Reachability | None:
        # A Finding is SCA (package reachability applies) or SAST (taint reachability applies),
        # never both, but trying taint first costs nothing when it returns None for the other kind.
        if taint_index is not None:
            r = taint_index.assess(f)
            if r is not None:
                return r
        return reach.assess(f) if reach else None

    return redact_near_secrets(apply_risk(findings, feeds, assess))
