"""Self-contained HTML report: one file, no scripts, no external requests.

Everything from a scan (titles, paths, snippets, descriptions) is untrusted, so every value goes through
`html.escape`. The report also ships a Content-Security-Policy that forbids scripts and network access, so
even a missed escape cannot execute code (threat T9). Prints cleanly (the PDF-from-browser path).
"""

from __future__ import annotations

from html import escape
from typing import Any

from core.export.model import SEVERITY_ORDER, ReportData, loc_label

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
DISCLAIMER = (
    "Risk scores are a heuristic for ordering work (severity combined with EPSS and CISA KEV), not a "
    "probability. Scanners produce false positives and miss real issues."
)

CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a17;--mut:#5b5c52;--line:#d9d9d0;--card:#f6f6f1;--acc:#0c7a5e}
@media (prefers-color-scheme:dark){:root{--bg:#131310;--fg:#ecebe4;--mut:#a3a496;--line:#34352e;--card:#1b1b17;--acc:#12b58b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:64rem;margin:0 auto;padding:2rem 1.25rem 4rem}h1{font-size:1.9rem;margin:.2rem 0}h2{margin:2.2rem 0 .8rem;font-size:1.25rem}
h3{margin:.2rem 0;font-size:1rem}.mut{color:var(--mut)}.eyebrow{font:600 .72rem/1 ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--acc)}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut)}code,pre{font:12.5px/1.45 ui-monospace,Menlo,monospace}
pre{background:var(--card);border:1px solid var(--line);padding:.7rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}
.tag{display:inline-block;border:1px solid currentColor;padding:.1rem .4rem;font:600 .68rem/1.4 ui-monospace,Menlo,monospace;letter-spacing:.05em}
.CRITICAL{color:#c2185b}.HIGH{color:#c74a1e}.MEDIUM{color:#8a6100}.LOW{color:#2f7d3b}.INFO{color:var(--mut)}
.risk{display:inline-block;min-width:2rem;text-align:center;background:var(--acc);color:#fff;padding:.1rem .35rem;font:600 .75rem ui-monospace,Menlo,monospace}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:.75rem}.card{background:var(--card);border:1px solid var(--line);padding:.8rem}
.card b{display:block;font-size:1.7rem;font-weight:400}details{border:1px solid var(--line);margin:.5rem 0;background:var(--card)}
summary{cursor:pointer;padding:.6rem .8rem;display:flex;gap:.6rem;align-items:baseline;flex-wrap:wrap}details>div{padding:0 .8rem .8rem}
dl{display:grid;grid-template-columns:9rem 1fr;gap:.25rem .8rem}dt{color:var(--mut)}dd{margin:0;overflow-wrap:anywhere}
@media print{details{break-inside:avoid}details>*{display:block}body{background:#fff;color:#000}}
"""


def _e(v: Any) -> str:
    return escape(str(v), quote=True)


def _sev_tag(sev: str) -> str:
    s = sev if sev in SEVERITY_ORDER else "INFO"
    return f'<span class="tag {s}">{_e(s)}</span>'


def _risk(f: dict[str, Any]) -> str:
    r = f["scoring"].get("risk_score")
    return f'<span class="risk">{int(r)}</span>' if isinstance(r, (int, float)) else ""


def _signals(f: dict[str, Any]) -> str:
    sc = f["scoring"]
    out = ""
    if sc.get("in_cisa_kev"):
        out += ' <span class="tag CRITICAL">KEV</span>'
    elif isinstance(sc.get("epss_score"), (int, float)) and sc["epss_score"] >= 0.1:
        out += f' <span class="tag MEDIUM">EPSS {round(sc["epss_score"] * 100)}%</span>'
    return out


def _finding(f: dict[str, Any]) -> str:
    sc, tax, ev = f["scoring"], f["taxonomy"], f["evidence"]
    rows = [("Location", f"<code>{_e(loc_label(f))}</code>")]
    if f.get("package"):
        p = f["package"]
        rows.append(
            ("Package", f"<code>{_e(p['name'])}@{_e(p['version'])}</code> ({_e(p['ecosystem'])})")
        )
    rows.append(
        (
            "Found by",
            _e(", ".join(ev["reported_by"])) + f" ({int(ev['agreement_count'])} scanner(s))",
        )
    )
    ids = [*tax["cwe"], *tax["cve"], *tax["owasp_top_10_2021"]]
    if ids:
        rows.append(("References", _e(", ".join(ids))))
    if sc.get("risk_factors"):
        rows.append(("Why this ranks here", "<br>".join(_e(x) for x in sc["risk_factors"])))
    body = "".join(f"<dt>{_e(k)}</dt><dd>{v}</dd>" for k, v in rows)
    parts = [f"<dl>{body}</dl>"]
    if f["location"].get("snippet"):
        parts.append(f"<pre>{_e(f['location']['snippet'])}</pre>")
    if f["description"]:
        parts.append(f"<p>{_e(f['description'])}</p>")
    if f["remediation"]["summary"]:
        parts.append(f"<p><b>How to fix:</b> {_e(f['remediation']['summary'])}</p>")
    return (
        f"<details><summary>{_sev_tag(sc['normalized_severity'])} {_risk(f)}{_signals(f)} "
        f"<h3>{_e(f['title'])}</h3></summary><div>{''.join(parts)}</div></details>"
    )


def to_html(report: ReportData) -> str:
    counts = "".join(
        f'<div class="card">{_sev_tag(s)}<b>{int(report.severity_counts.get(s, 0))}</b></div>'
        for s in SEVERITY_ORDER
        if report.severity_counts.get(s, 0)
    )
    tools = "".join(
        f"<tr><td>{_e(name)}</td><td>{_e(st.get('status', ''))}</td><td>{int(st.get('findings') or 0)}</td>"
        f"<td>{_e(st.get('error') or '')}</td></tr>"
        for name, st in report.tool_status.items()
    )
    top = "".join(
        f"<tr><td>{i}</td><td>{_risk(f)}{_signals(f)}</td><td>{_sev_tag(f['scoring']['normalized_severity'])}</td>"
        f"<td>{_e(f['title'])}<br><code class=\"mut\">{_e(loc_label(f))}</code></td></tr>"
        for i, f in enumerate(report.top(), 1)
        if f["scoring"].get("risk_score") is not None
    )
    top_section = (
        f"<h2>Fix these first</h2><table><thead><tr><th>#</th><th>Risk</th><th>Severity</th><th>Finding</th></tr></thead>"
        f"<tbody>{top}</tbody></table>"
        if top
        else ""
    )
    dedup = (
        f"{report.raw_findings} raw findings became {report.unique_findings} after merging duplicates "
        f"across scanners ({round(report.dedup_rate * 100)}% fewer)."
        if report.raw_findings
        else "No findings reported by any scanner."
    )
    findings = "".join(_finding(f) for f in report.by_severity())
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{_e(CSP)}">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bulwark report: {_e(report.source_label)}</title><style>{CSS}</style></head>
<body><main>
<span class="eyebrow">Bulwark security report</span>
<h1>{_e(report.source_label)}</h1>
<p class="mut">Scan {_e(report.scan_id)} · {_e(report.status)}{' · finished ' + _e(report.finished_at) if report.finished_at else ''}</p>
<div class="cards">{counts or '<p class="mut">No findings.</p>'}</div>
<p>{_e(dedup)}</p>
{top_section}
<h2>Scanners</h2>
<table><thead><tr><th>Scanner</th><th>Status</th><th>Findings</th><th>Error</th></tr></thead><tbody>{tools}</tbody></table>
<h2>All findings ({int(report.unique_findings)})</h2>
{findings or '<p class="mut">Nothing to review.</p>'}
<p class="mut"><small>{_e(DISCLAIMER)}</small></p>
</main></body></html>
"""
