"""The PR comment and the report files for CI. Everything from a scan is untrusted text."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from core.ci.compare import Comparison
from core.export import ReportData

COMMENT_MARKER = "<!-- bulwark-scan-comment -->"
MAX_LISTED = 20
MAX_COMMENT_CHARS = 60_000  # GitHub's limit is 65,536
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]")


def md(text: object, limit: int = 160) -> str:
    """Escape untrusted text for a markdown table cell: no formatting, links, mentions or HTML."""
    s = _CONTROL.sub("", str(text)).replace("\r", " ").replace("\n", " ")[:limit]
    s = re.sub(r"[\\`*_{}\[\]()#+!|<>~&$]", lambda m: "\\" + m.group(0), s)
    return s.replace("@", "@​")  # no @mentions


def code(text: object, limit: int = 120) -> str:
    """Inline code span that cannot be closed early by the content."""
    s = _CONTROL.sub("", str(text)).replace("\n", " ")[:limit].replace("`", "'").replace("|", "/")
    return f"`{s}`"


def _sev(f: dict[str, Any]) -> str:
    return str(f.get("scoring", {}).get("normalized_severity", "INFO")).upper()


def _risk(f: dict[str, Any]) -> int:
    r = f.get("scoring", {}).get("risk_score")
    return r if isinstance(r, int) else -1


def _counts(findings: list[dict[str, Any]]) -> str:
    c = Counter(_sev(f) for f in findings)
    return ", ".join(f"{c[s]} {s.lower()}" for s in SEV_ORDER if c[s]) or "none"


def _where(f: dict[str, Any]) -> str:
    loc = f.get("location", {})
    return f"{loc.get('path', '?')}:{loc.get('start_line', '?')}"


def markdown_comment(
    cmp: Comparison,
    fail_on: str,
    failed: bool,
    run_url: str = "",
    policy_denials: tuple[str, ...] = (),
) -> str:
    shown = cmp.new if cmp.baseline_available else cmp.head.findings
    lines = [COMMENT_MARKER, "## Bulwark security scan", ""]
    if not shown:
        lines.append(
            "No new findings introduced by this change."
            if cmp.baseline_available
            else "No findings."
        )
    else:
        n = len(shown)
        noun = (
            ("new finding" if n == 1 else "new findings")
            if cmp.baseline_available
            else ("finding" if n == 1 else "findings")
        )
        tail = " introduced by this change" if cmp.baseline_available else ""
        lines.append(f"**{n} {noun}{tail}** ({_counts(shown)})")
    if cmp.baseline_available:
        lines.append(
            f"{cmp.existing} existing finding(s) were already present and {cmp.fixed} were fixed."
        )
    elif cmp.baseline_incomplete:
        lines.append(
            "> The base branch could not be scanned cleanly, so every finding is listed "
            "instead of only the new ones."
        )
    else:  # a push, or any run without a base commit: nothing to compare with, not a failure
        lines.append("> No base commit to compare with, so every finding is listed.")
    failing = [
        (s, v) for s, v in cmp.head.tool_status.items() if v.get("status") not in ("ok", "skipped")
    ]
    if failing:
        # Each with its status and error: a bare name left no way to tell why from the PR itself.
        why = ", ".join(md(t, 40) + f" ({md(_failure_reason(v), 160)})" for t, v in failing)
        lines.append(f"> Scanner(s) that did not complete: {why}. Results may be incomplete.")
    if cmp.head.ignored:
        lines.append(f"{cmp.head.ignored} finding(s) hidden by `.bulwarkignore`.")
    if fail_on != "none":
        lines.append(
            f"\nThreshold: fail on **{fail_on}** or higher. "
            + ("**Failing.**" if failed else "Passing.")
        )
    if policy_denials:
        lines += ["", "**Policy violations** (plan §20.4):"]
        lines += [f"- {md(msg)}" for msg in policy_denials]
    if shown:
        top = sorted(
            shown,
            key=lambda f: (-_risk(f), SEV_ORDER.index(_sev(f)) if _sev(f) in SEV_ORDER else 9),
        )
        lines += ["", "| Severity | Finding | Location | Risk |", "|---|---|---|---|"]
        for f in top[:MAX_LISTED]:
            risk = _risk(f)
            lines.append(
                f"| {md(_sev(f), 12)} | {md(f.get('title', ''))} | {code(_where(f))} | {risk if risk >= 0 else ''} |"
            )
        if len(top) > MAX_LISTED:
            lines.append(
                f"\n…and {len(top) - MAX_LISTED} more. See the Security tab or the run summary."
            )
    lines += ["", "<sub>Scanner output ranked by Bulwark, not a guarantee of security."]
    if run_url.startswith("https://"):
        lines[-1] += f" [Workflow run]({run_url})"
    lines[-1] += "</sub>"
    out = "\n".join(lines)
    return out if len(out) <= MAX_COMMENT_CHARS else out[:MAX_COMMENT_CHARS] + "\n\n(truncated)"


def report_data(scan_label: str, cmp: Comparison) -> ReportData:
    h = cmp.head
    counts = Counter(_sev(f) for f in h.findings)
    failed = any(s.get("status") not in ("ok", "skipped") for s in h.tool_status.values())
    return ReportData(
        scan_id="ci",
        source_label=scan_label,
        status="partial" if failed else "completed",
        finished_at=None,
        tool_status={k: {**v, "findings": v.get("findings", 0)} for k, v in h.tool_status.items()},
        raw_findings=h.raw_findings,
        unique_findings=h.unique_findings,
        dedup_rate=h.dedup_rate,
        severity_counts=dict(counts),
        findings=h.findings,
    )


def _failure_reason(status: dict[str, Any]) -> str:
    reason = str(status.get("status", "unknown"))
    error = " ".join(str(status.get("error") or "").split())
    return f"{reason}: {error}" if error else reason
