"""Feeds taint analysis into the shared risk-scoring signal and attaches a step-by-step path to
the matching Finding (plan §20.3: "Taint paths attached to Issues; reachability v2 feeds scoring";
§28.3: "a taint path... rendered step by step in the UI").

This deliberately never creates a new Finding. It enriches an existing one the same way
`core.reachability`'s package-level reachability already enriches SCA findings: taint analysis
answers "is a sink some other tool (Semgrep, Bandit, ...) already flagged actually reachable from a
real HTTP entrypoint," not "here is a vulnerability nothing else found." A SAST Finding whose own
location has no matching taint sink gets no signal at all (`assess` returns `None`) -- the same
"unknown, not false" discipline `core.reachability.index.Reachability` already established, never a
fabricated "not reachable."
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path

from core.models import Category, Finding, TaintPathStep
from core.reachability.index import Reachability
from core.taint.models import TaintFinding

SNIPPET_CONTEXT_LINES = 2

# A Finding's own risk score, for a non-CVE, non-SCA category (SAST, secrets, IaC), is driven
# directly by `scoring.confidence` -- core/risk/score.py's own final branch, used whenever a
# finding has no CVE/EPSS/KEV data: `likelihood = confidence`. A concrete, mechanically-verified
# exploit path is expressed here as a high confidence value, reusing that existing formula rather
# than adding a second, parallel scoring rule that would need to be kept consistent with it.
TAINT_CONFIRMED_CONFIDENCE = 0.9


@dataclass
class TaintIndex:
    by_location: dict[tuple[str, int], list[TaintFinding]] = field(default_factory=dict)

    def assess(self, f: Finding) -> Reachability | None:
        if f.taxonomy.category is not Category.SAST:
            return None
        matches = self.by_location.get((f.location.path, f.location.start_line))
        if not matches:
            return None
        tf = matches[0]
        category = tf.category.replace("_", " ")
        return Reachability(
            True, f"Reachable from a real HTTP entrypoint via a concrete {category} taint path"
        )


def build_index(findings: list[TaintFinding]) -> TaintIndex:
    by_location: dict[tuple[str, int], list[TaintFinding]] = {}
    for tf in findings:
        by_location.setdefault((tf.sink_path, tf.sink_line), []).append(tf)
    return TaintIndex(by_location)


def _snippet(root: Path | None, path: str, line: int) -> str:
    """A few lines of context around `line`, read from the still-available scan workspace -- the
    one chance to capture this, since nothing downstream of a scan keeps the checked-out source
    around. Best-effort: a missing/unreadable file (an out-of-tree path, a symlink race) yields an
    empty snippet rather than failing the whole attachment."""
    if root is None:
        return ""
    try:
        lines = (root / path).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, line - 1 - SNIPPET_CONTEXT_LINES)
    end = min(len(lines), line + SNIPPET_CONTEXT_LINES)
    return "\n".join(lines[start:end])


def _steps(tf: TaintFinding, root: Path | None) -> tuple[TaintPathStep, ...]:
    hops = tuple(
        TaintPathStep(h.path, h.line, h.description, snippet=_snippet(root, h.path, h.line))
        for h in tf.hops
    )
    sink = TaintPathStep(
        tf.sink_path,
        tf.sink_line,
        f"{tf.sink_name}(...) -- {tf.category.replace('_', ' ')}",
        is_sink=True,
        snippet=_snippet(root, tf.sink_path, tf.sink_line),
    )
    return hops + (sink,)


def attach_taint_paths(
    findings: list[Finding], taint_findings: list[TaintFinding], root: Path | None = None
) -> list[Finding]:
    """Enrichment only: a Finding this doesn't match is returned unchanged. Call before
    `core.risk.apply_risk` so the confidence bump is in place when likelihood is computed. `root`
    (the scanned workspace) is optional so callers that only care about the reachability signal,
    not per-step code snippets, can skip it -- steps still carry path/line/description either way.
    """
    if not taint_findings:
        return findings
    index = build_index(taint_findings)
    out = []
    for f in findings:
        matches = (
            index.by_location.get((f.location.path, f.location.start_line))
            if f.taxonomy.category is Category.SAST
            else None
        )
        if not matches:
            out.append(f)
            continue
        tf = matches[0]  # more than one entrypoint reaching the same sink is one issue, not several
        out.append(
            replace(
                f,
                taint_path=_steps(tf, root),
                scoring=replace(
                    f.scoring, confidence=max(f.scoring.confidence, TAINT_CONFIRMED_CONFIDENCE)
                ),
            )
        )
    return out


__all__ = ["TaintIndex", "attach_taint_paths", "build_index", "TAINT_CONFIRMED_CONFIDENCE"]
