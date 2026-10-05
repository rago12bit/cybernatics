"""An engagement's report (plan §43.1: "closing an engagement produces its report from a template").

`snapshot` freezes what the report says when the engagement closes -- scope, people, checklist,
findings with their reproduction steps, tests -- as plain JSON stored on the engagement, so a later
change to an Issue never rewrites a delivered report. `markdown` and `html` render that snapshot.

Every value that came from outside (finding titles from imported reports, steps a tester typed) is
escaped for the format it lands in: HTML-escaped for HTML, and for Markdown, HTML-escaped and
Markdown-escaped both, since many Markdown viewers render embedded HTML. The HTML is one
self-contained page with a Content Security Policy that allows no script and no remote loads.

This is the fixed engagement template; the report builder with editable templates is Week 72
(§48.3).
"""

from __future__ import annotations

import html
import re
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.collab.people import names
from core.engagements import checklists
from core.persistence.models import Engagement, ManualFinding

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
FORMAT_VERSION = 1


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt is not None else None


def snapshot(
    s: Session,
    e: Engagement,
    *,
    generated_at: datetime,
    generated_by: str,
    summary: str | None = None,
) -> dict[str, Any]:
    from core.engagements import service

    found = service.findings(s, e)
    manual = {
        m.issue_id: m
        for m in s.scalars(
            select(ManualFinding).where(ManualFinding.issue_id.in_([f["issue_id"] for f in found]))
        )
    }
    items: list[dict[str, Any]] = []
    for n, f in enumerate(found, 1):
        m = manual.get(f["issue_id"])
        if m is not None and m.location_kind == "route":
            where = " ".join(x for x in (m.method, f"{m.host or ''}{m.route or ''}") if x)
        elif m is not None:
            where = f"{m.path}:{m.line}" if m.line else (m.path or "")
        else:
            where = f["path"]
        items.append(
            {
                "n": n,
                "issue_id": f["issue_id"],
                "title": f["title"],
                "severity": f["severity"],
                "state": f["state"],
                "retest_status": f["retest_status"],
                "test": f["test"],
                "location": where,
                "cwe": m.cwe if m else None,
                "cvss_vector": m.cvss_vector if m else None,
                "cvss_score": m.cvss_score if m else None,
                "steps": m.steps if m else "",
                "impact": m.impact if m else "",
                "recommendation": m.recommendation if m else "",
                "references": list(m.references or []) if m else [],
                "also_found_by": f["also_found_by"],
            }
        )
    state = service.checklist_state(s, e)
    checklist = None
    if state is not None:
        checklist = {
            **state.summary(),
            "failed": [
                {"id": i.id, "title": i.title, "note": state.rows[i.id].note}
                for i in state.checklist.items
                if i.id in state.rows and state.rows[i.id].status == "fail"
            ],
        }
    sev = Counter(i["severity"] for i in items)
    retest = Counter(i["retest_status"] for i in items if i["retest_status"])
    return {
        "format": FORMAT_VERSION,
        "name": e.name,
        "type": e.engagement_type,
        "project": service.project_label(s, e),
        "starts_at": _iso(e.started_at),
        "ends_at": _iso(e.target_end_at),
        "closed_at": _iso(generated_at),
        "generated_at": _iso(generated_at),
        "generated_by": generated_by,
        "generated_by_name": names(s, e.org_id, {generated_by}).get(generated_by),
        "summary": summary,
        "scope": {
            "targets": list(e.scope_targets or []),
            "routes": list(e.scope_routes or []),
            "out_of_scope": e.out_of_scope,
        },
        "lead": e.lead,
        "testers": list(e.testers or []),
        "counts": {
            "total": len(items),
            "by_severity": {k: sev.get(k, 0) for k in SEVERITIES},
            "open": sum(1 for i in items if i["state"] != "fixed"),
            "fixed": sum(1 for i in items if i["state"] == "fixed"),
            "retest": dict(retest),
        },
        "checklist": checklist,
        "findings": items,
        "tests": [
            {k: t[k] for k in ("name", "parser", "findings", "uploads")}
            for t in service.tests(s, e)
        ],
    }


# --- Markdown -------------------------------------------------------------------------------------

_MD_INLINE = re.compile(r"([\\`*_\[\]|~])")  # what Markdown acts on anywhere in a line
_MD_LINE_START = re.compile(r"^(\s*)([#+>-]|\d+[.)])")  # ...and only at the start of one


def _md(text: Any) -> str:
    """Safe inline Markdown: HTML-escaped (many viewers render embedded HTML), the characters
    Markdown acts on anywhere backslash-escaped, and a heading, list or quote marker at the start
    escaped too. With brackets escaped no link or image can form, so parentheses stay as typed."""
    out = _MD_INLINE.sub(r"\\\1", html.escape(str(text if text is not None else ""), quote=False))

    def marker(m: re.Match[str]) -> str:
        mark = m.group(2)
        if mark[0].isdigit():  # "1." -> "1\." : the escape goes before the dot
            return f"{m.group(1)}{mark[:-1]}\\{mark[-1]}"
        return f"{m.group(1)}\\{mark}"

    return _MD_LINE_START.sub(marker, out)


def _md_block(text: str) -> str:
    """A multi-line field (steps, impact): every line escaped, line breaks kept."""
    return "\n".join(_md(line) if line.strip() else "" for line in text.strip().splitlines())


def _day(iso: str | None) -> str:
    return iso[:10] if iso else "not set"


def _state(i: dict[str, Any]) -> str:
    word = "Fixed" if i["state"] == "fixed" else "Open"
    retest = {
        "requested": "retest requested",
        "passed": "retest passed",
        "failed": "retest failed",
    }.get(i["retest_status"] or "")
    return f"{word} ({retest})" if retest else word


def markdown(r: dict[str, Any]) -> str:
    out: list[str] = [f"# {_md(r['name'])}", ""]
    out.append(
        f"**Project:** {_md(r['project'])} · **Type:** {_md(r['type'])} · "
        f"**Dates (UTC):** {_day(r['starts_at'])} to {_day(r['ends_at'])} · "
        f"**Closed:** {_day(r['closed_at'])}"
    )
    out += ["", "## Summary", ""]
    if r.get("summary"):
        out += [_md_block(r["summary"]), ""]
    c = r["counts"]
    sev = ", ".join(f"{n} {k.lower()}" for k, n in c["by_severity"].items() if n) or "none"
    out.append(
        f"{c['total']} finding{'s' if c['total'] != 1 else ''} ({sev}); "
        f"{c['open']} open, {c['fixed']} fixed."
    )
    out += ["", "## Scope", ""]
    sc = r["scope"]
    out.append(f"- **In scope:** {', '.join(_md(x) for x in sc['targets']) or 'not recorded'}")
    if sc["routes"]:
        out.append(f"- **Routes:** {', '.join(_md(x) for x in sc['routes'])}")
    out_of_scope = _md(sc["out_of_scope"]) if sc["out_of_scope"] else "nothing recorded"
    out.append(f"- **Out of scope:** {out_of_scope}")
    out += [
        "",
        "## Team",
        "",
        f"- **Lead:** {_md(r['lead']) if r['lead'] else 'not recorded'}",
        f"- **Testers:** {', '.join(_md(t) for t in r['testers']) or 'not recorded'}",
    ]
    if r["checklist"]:
        ch = r["checklist"]
        out += [
            "",
            "## Checklist",
            "",
            f"{_md(ch['name'])}: {ch['done']} of {ch['total']} done "
            f"({ch['pass']} passed, {ch['fail']} failed, {ch['not_applicable']} not applicable).",
        ]
        for f in ch["failed"]:
            note = f": {_md(f['note'])}" if f.get("note") else ""
            out.append(f"- Failed **{_md(f['id'])}** {_md(f['title'])}{note}")
    out += ["", "## Findings", ""]
    if not r["findings"]:
        out.append("No findings were recorded.")
    else:
        out += ["| # | Severity | Finding | Status |", "|---|---|---|---|"]
        for i in r["findings"]:
            out.append(f"| {i['n']} | {i['severity'].title()} | {_md(i['title'])} | {_state(i)} |")
        for i in r["findings"]:
            out += ["", f"### {i['n']}. {_md(i['title'])}", ""]
            out.append(
                f"- **Severity:** {i['severity'].title()}"
                + (
                    f" (CVSS {i['cvss_score']}, `{_md(i['cvss_vector'])}`)"
                    if i["cvss_vector"]
                    else ""
                )
            )
            out.append(f"- **Status:** {_state(i)}")
            if i["location"]:
                out.append(f"- **Location:** {_md(i['location'])}")
            if i["cwe"]:
                out.append(f"- **Weakness:** {_md(i['cwe'])}")
            out.append(
                f"- **Reported by:** {_md(i['test'])}"
                + (
                    f"; also found by {', '.join(_md(x) for x in i['also_found_by'])}"
                    if i["also_found_by"]
                    else ""
                )
            )
            for key, label in (
                ("steps", "Steps to reproduce"),
                ("impact", "Impact"),
                ("recommendation", "Recommendation"),
            ):
                if i[key]:
                    out += ["", f"**{label}**", "", _md_block(i[key])]
            if i["references"]:
                out += ["", "**References**", ""] + [f"- {_md(x)}" for x in i["references"]]
    if r["tests"]:
        out += ["", "## Tests", "", "| Test | Parser | Findings | Uploads |", "|---|---|---|---|"]
        for t in r["tests"]:
            cells = (_md(t["name"]), _md(t["parser"] or ""), t["findings"], t["uploads"])
            out.append("| " + " | ".join(str(c) for c in cells) + " |")
    out += [
        "",
        "---",
        "",
        f"Written by Bulwark on {_day(r['generated_at'])} (UTC) for "
        f"{_md(r.get('generated_by_name') or r['generated_by'])}.",
    ]
    if r["checklist"]:
        out.append(f"Checklist content: {_md(r['checklist']['name'])}, {checklists.ATTRIBUTION}.")
    return "\n".join(out) + "\n"


# --- HTML -----------------------------------------------------------------------------------------

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; "
    "form-action 'none'"
)
STYLE = (
    "body{font:15px/1.5 system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;"
    "color:#1b2430}table{border-collapse:collapse;width:100%}"
    "td,th{border-bottom:1px solid #d3dae2;padding:.35rem .5rem;text-align:left;vertical-align:top}"
    "code{font-family:ui-monospace,monospace;font-size:.9em}.muted{color:#5b6776}"
)


def _h(text: Any) -> str:
    return html.escape(str(text if text is not None else ""))


def _h_block(text: str) -> str:
    return "<br>".join(_h(line) for line in text.strip().splitlines())


def _table(headers: tuple[str, ...], rows: Sequence[tuple[Any, ...]]) -> str:
    """Cells must already be escaped."""
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _ul(items: list[str]) -> str:
    """Items must already be escaped."""
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"


def _or(values: list[str], empty: str) -> str:
    return ", ".join(_h(v) for v in values) or empty


def html_page(r: dict[str, Any]) -> str:
    c, sc = r["counts"], r["scope"]
    sev = ", ".join(f"{n} {k.lower()}" for k, n in c["by_severity"].items() if n) or "none"
    dates = f"{_day(r['starts_at'])} to {_day(r['ends_at'])} · closed {_day(r['closed_at'])} (UTC)"
    parts = [
        '<!doctype html><html lang="en"><head><meta charset="utf-8">',
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_h(r['name'])}</title><style>{STYLE}</style></head><body>",
        f"<h1>{_h(r['name'])}</h1>",
        f'<p class="muted">Project {_h(r["project"])} · {_h(r["type"])} · {dates}</p>',
        "<h2>Summary</h2>",
    ]
    if r.get("summary"):
        parts.append(f"<p>{_h_block(r['summary'])}</p>")
    plural = "s" if c["total"] != 1 else ""
    parts.append(
        f"<p>{c['total']} finding{plural} ({sev}); {c['open']} open, {c['fixed']} fixed.</p>"
    )
    scope = [f"<b>In scope:</b> {_or(sc['targets'], 'not recorded')}"]
    if sc["routes"]:
        scope.append(f"<b>Routes:</b> {_or(sc['routes'], '')}")
    scope.append(f"<b>Out of scope:</b> {_h(sc['out_of_scope']) or 'nothing recorded'}")
    parts += ["<h2>Scope</h2>", _ul(scope), "<h2>Team</h2>"]
    parts.append(
        _ul(
            [
                f"<b>Lead:</b> {_h(r['lead']) or 'not recorded'}",
                f"<b>Testers:</b> {_or(r['testers'], 'not recorded')}",
            ]
        )
    )
    if r["checklist"]:
        ch = r["checklist"]
        counts = f"{ch['pass']} passed, {ch['fail']} failed, {ch['not_applicable']} not applicable"
        parts.append(
            f"<h2>Checklist</h2><p>{_h(ch['name'])}: {ch['done']} of {ch['total']} done "
            f"({counts}).</p>"
        )
        if ch["failed"]:
            parts.append(
                _ul(
                    [
                        f"Failed <b>{_h(f['id'])}</b> {_h(f['title'])}"
                        + (f": {_h(f['note'])}" if f.get("note") else "")
                        for f in ch["failed"]
                    ]
                )
            )
    parts.append("<h2>Findings</h2>")
    if not r["findings"]:
        parts.append("<p>No findings were recorded.</p>")
    else:
        rows = [
            (str(i["n"]), i["severity"].title(), _h(i["title"]), _state(i)) for i in r["findings"]
        ]
        parts.append(_table(("#", "Severity", "Finding", "Status"), rows))
        for i in r["findings"]:
            parts.append(f"<h3>{i['n']}. {_h(i['title'])}</h3>")
            cvss = ""
            if i["cvss_vector"]:
                cvss = f" (CVSS {_h(i['cvss_score'])}, <code>{_h(i['cvss_vector'])}</code>)"
            facts = [
                f"<b>Severity:</b> {i['severity'].title()}{cvss}",
                f"<b>Status:</b> {_state(i)}",
            ]
            if i["location"]:
                facts.append(f"<b>Location:</b> <code>{_h(i['location'])}</code>")
            if i["cwe"]:
                facts.append(f"<b>Weakness:</b> {_h(i['cwe'])}")
            also = f"; also found by {_or(i['also_found_by'], '')}" if i["also_found_by"] else ""
            facts.append(f"<b>Reported by:</b> {_h(i['test'])}{also}")
            parts.append(_ul(facts))
            for key, label in (
                ("steps", "Steps to reproduce"),
                ("impact", "Impact"),
                ("recommendation", "Recommendation"),
            ):
                if i[key]:
                    parts.append(f"<h4>{label}</h4><p>{_h_block(i[key])}</p>")
            if i["references"]:
                parts.append("<h4>References</h4>" + _ul([_h(x) for x in i["references"]]))
    if r["tests"]:
        rows = [
            (_h(t["name"]), _h(t["parser"] or ""), str(t["findings"]), str(t["uploads"]))
            for t in r["tests"]
        ]
        parts += ["<h2>Tests</h2>", _table(("Test", "Parser", "Findings", "Uploads"), rows)]
    who = _h(r.get("generated_by_name") or r["generated_by"])
    foot = f"Written by Bulwark on {_day(r['generated_at'])} (UTC) for {who}."
    if r["checklist"]:
        foot += f" Checklist content: {_h(r['checklist']['name'])}, {checklists.ATTRIBUTION}."
    parts.append(f'<hr><p class="muted">{foot}</p></body></html>')
    return "\n".join(parts)
