"""One-shot clone+analyze for the attack-path API endpoint (plan §21.6). Deliberately NOT cached,
unlike `core.copilot.session.CheckoutCache`: the copilot panel asks several questions in a row
against the same checkout, so caching pays for itself; the attack-paths screen is typically opened
once per visit, so a per-request clone keeps this module free of the cache-invalidation questions a
cache would raise (when does a stale checkout get evicted if the asset gets rescanned?) at the cost
of a slower page load -- a disclosed limitation, not a correctness issue, tracked in
docs/v2-week45-verification.md."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from core.codeintel import analyze
from core.codeintel.models import CodeGraph
from core.gitfetch import clone_repo


def build_graph(source_ref: str, ref: str | None) -> CodeGraph:
    checkout = Path(tempfile.mkdtemp(prefix="bulwark-attackpath-"))
    try:
        clone_repo(source_ref, checkout, ref=ref)
        return analyze(checkout)
    finally:
        shutil.rmtree(checkout, ignore_errors=True)
