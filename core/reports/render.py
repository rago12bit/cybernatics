"""A report as one self-contained HTML document, printed to PDF by Chromium (`core.reports.pdf`).

Every value is escaped (`html.escape`): Issue titles and paths come from scanned code. The page's
own Content-Security-Policy allows its inline styles and data: images and nothing else -- no
scripts, no fetches -- on top of the renderer having no network. Charts are inline SVG bars.
"""

from __future__ import annotations

from datetime import date, datetime
from html import escape
from typing import Any

from core import compliance
from core.metrics.definitions import BY_ID

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:"
STYLE = """
@page { size: A4; margin: 18mm 16mm 20mm; }
* { box-sizing: border-box; }
body { font: 10.5pt/1.45 "DejaVu Sans", "Liberation Sans", Arial, sans-serif; color: #1b2430; margin: 0; }
h1 { font-size: 24pt; margin: 0 0 6mm; color: #1f6f78; }
h2 { font-size: 14pt; margin: 9mm 0 3mm; border-bottom: 1px solid #d3dae2; padding-bottom: 1.5mm; break-after: avoid; page-break-after: avoid; }
h3 { font-size: 11pt; margin: 5mm 0 2mm; break-after: avoid; page-break-after: avoid; }
.headline, .meta { break-after: avoid; page-break-after: avoid; }
thead { display: table-header-group; }
p { margin: 0 0 2.5mm; }
.cover { height: 240mm; display: flex; flex-direction: column; justify-content: center; page-break-after: always; }
.cover .sub { font-size: 14pt; color: #5b6776; }
.meta { color: #5b6776; font-size: 9pt; }
.headline { font-size: 13pt; margin: 1mm 0 3mm; }
.label { display: inline-block; font-size: 8.5pt; padding: 0.6mm 2mm; border: 1px solid #a16207; color: #7a4a05; border-radius: 2px; margin-bottom: 2mm; }
table { width: 100%; border-collapse: collapse; margin: 2mm 0 4mm; font-size: 9.5pt; page-break-inside: auto; }
th, td { text-align: left; padding: 1.4mm 2mm; border-bottom: 1px solid #d3dae2; vertical-align: top; }
thead th { color: #5b6776; font-weight: 600; font-size: 8.5pt; }
tr { page-break-inside: avoid; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.bar { height: 3mm; background: #1f6f78; display: block; }
.track { background: #eef1f4; width: 45mm; }
section { page-break-inside: auto; }
.block { margin-bottom: 4mm; }
.missing { color: #b42318; }
pre { white-space: pre-wrap; font: 9pt/1.4 "DejaVu Sans Mono", monospace; background: #f4f6f8; padding: 2mm; }
.disclaimer { font-size: 8.5pt; color: #5b6776; }
"""


def e(v: Any) -> str:
    return escape("" if v is None else str(v), quote=True)


def _day(v: Any) -> str:
    if isinstance(v, datetime):
        return v.date().isoformat()
    if isinstance(v, date):
        return v.isoformat()
    return str(v)[:10] if v else "—"


def _n(v: Any) -> str:
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return e(v)


def pct(part: Any, whole: Any) -> str:
    p, w = int(part or 0), int(whole or 0)
    return f"{round(p / w * 100)}% ({p:,} of {w:,})" if w else "no data"


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n:,} {one if n == 1 else (many or one + 's')}"


def table(head: list[str], rows: list[list[Any]], *, nums: tuple[int, ...] = ()) -> str:
    if not rows:
        return '<p class="meta">Nothing to list.</p>'
    th = "".join(f'<th{" class=num" if i in nums else ""}>{e(h)}</th>' for i, h in enumerate(head))
    body = "".join(
        "<tr>" + "".join(f'<td{" class=num" if i in nums else ""}>{c if isinstance(c, Markup) else e(c)}</td>'
                         for i, c in enumerate(r)) + "</tr>"
        for r in rows
    )  # fmt: skip
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


class Markup(str):
    """Already-escaped HTML (built here, never from data)."""


def bar(value: float, most: float) -> Markup:
    width = 0 if most <= 0 else max(1.0, value / most * 100)
    return Markup(f'<span class="track bar" style="background:#eef1f4"><span class="bar" '
                  f'style="width:{width:.1f}%"></span></span>')  # fmt: skip


def name_of(actor: Any, names: dict[str, str]) -> str:
    return names.get(str(actor), str(actor)) if actor else "—"


# --- each metric, as the dashboard shows it (web/lib/dashboard-present.ts) -----------------------


def metric_html(r: dict[str, Any], names: dict[str, str], group_by: str = "band") -> str:
    c, rows, series = r.get("counts") or {}, r.get("rows") or [], r.get("series") or []
    m = r["metric"]
    group = {"band": "Priority", "portfolio": "Portfolio", "project": "Project"}
    if m in ("open_issues", "open_risk"):
        risk = m == "open_risk"
        most = max([float(x.get("score" if risk else "count") or 0) for x in rows] or [0])
        head = (f"Risk score {_n(r['value'])} across {_plural(int(c.get('open', 0)), 'open issue')}"
                if risk else _plural(int(r.get("value") or 0), "open issue"))  # fmt: skip
        body = table([group.get(group_by, "Priority"), "Open issues", "Risk score", ""],
                     [[x.get("label") or x.get("key"), _n(x.get("count")), _n(x.get("score")),
                       bar(float(x.get("score" if risk else "count") or 0), most)] for x in rows],
                     nums=(1, 2))  # fmt: skip
        if risk and series:
            body += "<h3>Risk at the end of each week</h3>" + table(
                ["Week of", "Risk score"],
                [[x.get("week"), _n(x.get("risk"))] for x in series],
                nums=(1,),
            )
        return f'<p class="headline">{e(head)}</p>{body}'
    if m == "sla_adherence":
        due = int(c.get("due", 0))
        head = (
            f"{pct(c.get('met'), due)} fixed within SLA"
            if due
            else "No SLA deadlines in this period"
        )
        detail = (f"{_plural(int(c.get('missed', 0)), 'issue')} fixed late · "
                  f"{_plural(int(c.get('open_past_deadline', 0)), 'issue')} still open past the deadline · "
                  f"{_plural(int(c.get('exempt', 0)), 'issue')} exempt")  # fmt: skip
        return (f'<p class="headline">{e(head)}</p><p class="meta">{e(detail)}</p>'
                + table(["Week of", "Fixed in time", "Due", "On time"],
                        [[x.get("week"), _n(x.get("met")), _n(x.get("due")), pct(x.get("met"), x.get("due"))]
                         for x in series], nums=(1, 2)))  # fmt: skip
    if m == "mttr":
        head = (
            "Nothing fixed in this period"
            if r.get("value") is None
            else f"{r['value']} days on average, over {_plural(int(c.get('fixed', 0)), 'fixed issue')}"
        )
        most = max([float(x.get("days") or 0) for x in rows] or [0])
        return f'<p class="headline">{e(head)}</p>' + table(
            ["Priority", "Fixed", "Mean days", ""],
            [[x.get("key"), _n(x.get("fixed")), x.get("days"), bar(float(x.get("days") or 0), most)] for x in rows],
            nums=(1, 2))  # fmt: skip
    if m == "new_vs_fixed":
        head = f"{_plural(int(c.get('new', 0)), 'new issue')}, {_plural(int(c.get('fixed', 0)), 'fixed issue')}"
        return f'<p class="headline">{e(head)}</p>' + table(
            ["Week of", "New", "Fixed"], [[x.get("week"), _n(x.get("new")), _n(x.get("fixed"))] for x in series],
            nums=(1, 2))  # fmt: skip
    if m == "backlog_age":
        head = (
            "No open issues"
            if r.get("value") is None
            else f"Median age {_plural(int(r['value']), 'day')}, across {_plural(int(c.get('open', 0)), 'open issue')}"
        )
        return f'<p class="headline">{e(head)}</p>' + table(
            ["Age", "Open issues"],
            [[f"Older than {str(x.get('key')).replace('over_', '')} days", _n(x.get("count"))] for x in rows],
            nums=(1,))  # fmt: skip
    if m == "past_sla":
        total = int(r.get("value") or 0)
        shown = f'<p class="meta">The {len(rows)} most overdue.</p>' if total > len(rows) else ""
        return f'<p class="headline">{e(_plural(total, "issue"))} past SLA</p>{shown}' + table(
            ["Portfolio", "Issue", "Project", "Overdue", "Assignee"],
            [[x.get("portfolio") or "—", x.get("title"), x.get("project"), _plural(int(x.get("days_over") or 0), "day"),
              x.get("assignee_name") or name_of(x.get("assignee"), names) if x.get("assignee") else "Unassigned"]
             for x in rows], nums=(3,))  # fmt: skip
    if m == "scan_coverage":
        head = (
            f"{pct(c.get('scanned_recently'), c.get('projects'))} projects scanned in the last "
            f"{r.get('days', 30)} days"
        )
        return f'<p class="headline">{e(head)}</p>' + table(
            ["Project", "Last full scan", "Scanners"],
            [[x.get("project"), "never" if x.get("days_since") is None else _plural(int(x["days_since"]), "day") + " ago",
              f"{x.get('scanners_ok')} of {x.get('scanners_applicable')}" if x.get("scanners_applicable") else "—"]
             for x in rows])  # fmt: skip
    if m == "vulnerable_components":
        return f'<p class="headline">{e(_plural(int(r.get("value") or 0), "library", "libraries"))} with a known vulnerability</p>' + table(
            ["Library", "Projects", "Most vulnerabilities", "Known exploited in"],
            [[x.get("library"), _n(x.get("projects")), _n(x.get("vulns")), _plural(int(x.get("kev_projects") or 0), "project")]
             for x in rows], nums=(1, 2))  # fmt: skip
    if m == "expiring_acceptances":
        return f'<p class="headline">{e(_plural(int(r.get("value") or 0), "risk acceptance"))} expiring in the next {r.get("days", 30)} days</p>' + table(
            ["Project", "Issues", "Expires in", "Approved by"],
            [[x.get("project"), _n(x.get("issues")), _plural(int(x.get("days_left") or 0), "day"),
              name_of(x.get("approved_by"), names)] for x in rows], nums=(1,))  # fmt: skip
    if m == "engagement_status":
        detail = ", ".join(f"{v} {k}" for k, v in c.items())
        return (
            f'<p class="headline">{e(_plural(int(r.get("value") or 0), "active engagement"))}</p>'
            f'<p class="meta">{e(detail)}</p>'
            + table(
                ["Engagement", "Project", "Lead", "Target end"],
                [
                    [
                        x.get("name"),
                        x.get("project"),
                        x.get("lead") or "—",
                        _day(x.get("target_end_at")) + (" (overdue)" if x.get("overdue") else ""),
                    ]
                    for x in rows
                ],
            )
        )
    if m == "advisory_impact":
        head = (
            f"{_plural(int(r.get('value') or 0), 'new vulnerability', 'new vulnerabilities')} affecting projects; "
            f"{_n(c.get('kev'))} known exploited, {_n(c.get('not_acted_on'))} not acted on yet"
        )
        return f'<p class="headline">{e(head)}</p>' + table(
            ["Vulnerability", "Projects", "Known exploited", "State"],
            [[x.get("vuln_key"), _n(x.get("projects")), "Yes" if x.get("kev") else "No",
              "Not acted on" if x.get("state") == "new" else "Issues created"] for x in rows], nums=(1,))  # fmt: skip
    return f'<p class="headline">{e(r.get("value"))}</p>'


KIND_TITLE = {"open": "Open issues", "past_sla": "Issues past their SLA",
              "opened": "Issues first seen in the period", "fixed": "Issues fixed in the period"}  # fmt: skip


def _block(b: dict[str, Any], ctx: dict[str, Any]) -> str:
    cfg, data, kind, names = b["config"], b.get("data") or {}, b["type"], ctx["names"]
    if kind == "cover":
        return (f'<div class="cover"><h1>{e(cfg["title"])}</h1>'
                + (f'<p class="sub">{e(cfg["subtitle"])}</p>' if cfg.get("subtitle") else "")
                + f'<p class="meta">{e(ctx["org"])} · {e(ctx["period"])} · generated {e(ctx["generated"])}'
                f' by {e(ctx["by"])}</p></div>')  # fmt: skip
    if kind == "summary":
        label = ""
        if cfg.get("source") == "ai":
            label = (f'<p class="label">Drafted by AI ({e(cfg.get("drafted_by_model") or "a model")}) from this '
                     f'report\'s data; reviewed by {e(name_of(cfg.get("reviewed_by"), names))} on '
                     f'{e(_day(cfg.get("reviewed_at")))}.</p>')  # fmt: skip
        paras = "".join(
            f"<p>{e(p)}</p>" for p in str(cfg.get("text") or "").split("\n\n") if p.strip()
        )
        return (
            f"<h2>Executive summary</h2>{label}{paras or '<p class=meta>No summary written.</p>'}"
        )
    if kind == "metric":
        title = BY_ID[cfg["metric"]].name
        f = cfg.get("filters") or {}
        scope = []
        if f.get("portfolios") or f.get("projects"):
            scope.append("filtered by portfolio or project")
        if f.get("tag"):
            scope.append(f"tag “{f['tag']}”")
        if data.get("period"):
            scope.append(f"{data['period'][0]} to {data['period'][1]}")
        return (f"<h2>{e(title)}</h2>" + (f'<p class="meta">{e(" · ".join(scope))}</p>' if scope else "")
                + metric_html(data, names, f.get("group") or "band"))  # fmt: skip
    if kind == "issues":
        title = cfg.get("title") or KIND_TITLE[cfg["kind"]] + (
            f", {cfg['band']}" if cfg.get("band") else ""
        )
        rows = data.get("rows") or []
        more = f" (the first {len(rows)})" if data.get("next") else ""
        return f"<h2>{e(title)}</h2><p class=\"meta\">{_plural(len(rows), 'issue')}{e(more)}</p>" + table(
            ["Issue", "Project", "Priority", "Severity", "First seen", "Fixed" if cfg["kind"] == "fixed" else "Assignee"],
            [[r.get("title"), r.get("project"), r.get("band") or "—", r.get("severity"), _day(r.get("first_seen_at")),
              _day(r.get("fixed_at")) if cfg["kind"] == "fixed" else (r.get("assignee_name") or "Unassigned")]
             for r in rows])  # fmt: skip
    if kind == "issue":
        i = data.get("issue")
        if i is None:
            return '<h2>Issue</h2><p class="missing">This Issue no longer exists.</p>'
        facts = [["Project", i["project"]], ["Location", f"{i['path']}:{i['line']}" if i.get("line") else i["path"]],
                 ["Severity", i["severity"]], ["Priority", i.get("band") or "—"],
                 ["State", i["state"] + ("" if i["triage"] == "open" else f" ({i['triage'].replace('_', ' ')})")],
                 ["First seen", _day(i["first_seen_at"])], ["Fixed", _day(i["fixed_at"])],
                 ["CWE", ", ".join(i["cwe"]) or "—"], ["Assignee", name_of(i["assignee"], names)]]  # fmt: skip
        desc = (
            f"<h3>Description</h3><pre>{e(i['description'])}</pre>" if i.get("description") else ""
        )
        return f"<h2>{e(i['title'])}</h2>" + table(["", ""], facts) + desc
    if kind == "acceptances":
        word = {"approved": "Risk acceptances in force", "requested": "Risk acceptances awaiting a decision",
                "expiring": "Risk acceptances expiring soon", "all": "Risk acceptances"}[cfg["state"]]  # fmt: skip
        rows = data.get("rows") or []
        return f"<h2>{e(word)}</h2>" + table(
            ["Project", "Decision", "Issues", "Why", "Controls", "State", "Expires", "Approved by"],
            [[r["project"], r["decision"], _n(r["issues"]), r["justification"], r["controls"], r["state"],
              _day(r["expires_at"]), name_of(r["decided_by"], names)] for r in rows], nums=(2,))  # fmt: skip
    if kind == "compliance":
        fw = data.get("framework") or {}
        rows = []
        for c in fw.get("controls", []):
            evidence = "; ".join(
                f"{x.get('label')}: {x.get('here') or 'none here'}" for x in c.get("evidence", [])
            )
            rows.append([c.get("id"), c.get("title"), evidence or "—"])
        return (f"<h2>{e(fw.get('name') or 'Compliance')}</h2>"
                f'<p class="meta">{e(fw.get("source") or "")} {e(fw.get("version") or "")}</p>'
                + table(["Control", "Requirement", "Evidence Bulwark holds"], rows)
                + f'<p class="disclaimer">{e(data.get("disclaimer") or compliance.DISCLAIMER)}</p>')  # fmt: skip
    if kind == "engagement":
        g = data.get("engagement")
        if g is None:
            return '<h2>Engagement</h2><p class="missing">This engagement no longer exists.</p>'
        facts = [["Project", g["project"]], ["Kind", g["type"]], ["Status", g["status"]],
                 ["Lead", g["lead"] or "—"], ["Testers", ", ".join(g["testers"]) or "—"],
                 ["Started", _day(g["started_at"])], ["Target end", _day(g["target_end_at"])],
                 ["In scope", ", ".join(g["targets"]) or "—"], ["Routes", ", ".join(g["routes"]) or "—"],
                 ["Out of scope", g["out_of_scope"] or "—"]]  # fmt: skip
        return f"<h2>Scope: {e(g['name'])}</h2>" + table(["", ""], facts)
    # appendix
    used = sorted({x["config"]["metric"] for x in ctx["blocks"] if x["type"] == "metric"})
    defs = "".join(f"<h3>{e(BY_ID[m].name)}</h3><p>{e(BY_ID[m].definition)}</p>" for m in used)
    return ("<h2>Appendix</h2>" + (f"<h3>How each number is defined</h3>{defs}" if defs else "")
            + "<h3>Checking this report</h3><p>Bulwark records the SHA-256 of this PDF when it is "
            "generated, and signs it with the deployment's cosign key when one is set up. To check a "
            "copy: compute its SHA-256 and compare it with the one shown where the report was shared, "
            "or run <code>cosign verify-blob --key cosign.pub --bundle report.pdf.sig "
            "--insecure-ignore-tlog report.pdf</code>.</p>")  # fmt: skip


def html(report_name: str, blocks: list[dict[str, Any]], *, org: str, period: str, generated: str,
         by: str, names: dict[str, str]) -> str:  # fmt: skip
    ctx = {"org": org, "period": period, "generated": generated, "by": by, "names": names,
           "blocks": blocks}  # fmt: skip
    body = "".join(f'<section class="block">{_block(b, ctx)}</section>' for b in blocks)
    return (
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">'
        f"<title>{e(report_name)}</title><style>{STYLE}</style></head><body>{body}</body></html>"
    )
