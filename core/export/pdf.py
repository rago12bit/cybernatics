"""PDF export via ReportLab (pure Python, no browser needed).

ReportLab's Paragraph parses XML-like markup, so every scan-derived string is escaped first. The built-in
PDF fonts are Latin-1 only: other characters in titles or paths become "?" rather than failing the export.
"""

from __future__ import annotations

import io
import re
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from core.export.html import DISCLAIMER
from core.export.model import SEVERITY_ORDER, ReportData, loc_label

MAX_FINDINGS = (
    1000  # a runaway scan must not produce an unbounded PDF; the count is stated when capped
)
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SEV_COLOR = {
    "CRITICAL": "#c2185b", "HIGH": "#c74a1e", "MEDIUM": "#8a6100", "LOW": "#2f7d3b", "INFO": "#5b5c52",
}  # fmt: skip


def _t(v: Any, limit: int = 600) -> str:
    """Untrusted text -> safe Paragraph markup: no control chars, Latin-1 only, escaped, bounded."""
    s = _CTRL.sub("", str(v))[:limit]
    s = s.encode("latin-1", "replace").decode("latin-1")
    return escape(s)


def to_pdf(report: ReportData) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"Bulwark report: {_t(report.source_label, 100)}", author="Bulwark",
    )  # fmt: skip
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle(
        "s", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#5b5c52")
    )
    mono = ParagraphStyle("m", parent=small, fontName="Courier")
    cell = ParagraphStyle("c", parent=body, fontSize=8.5, leading=11)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=20, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, spaceBefore=14, spaceAfter=6)

    def sev(s: str) -> Paragraph:
        s = s if s in SEVERITY_ORDER else "INFO"
        return Paragraph(f'<font color="{SEV_COLOR[s]}"><b>{s}</b></font>', cell)

    def grid(data: list[list[Any]], widths: list[float]) -> Table:
        t = Table(data, colWidths=widths, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#5b5c52")),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#d9d9d0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return t

    w = doc.width
    story: list[Any] = [
        Paragraph("BULWARK SECURITY REPORT", small),
        Paragraph(_t(report.source_label, 200), h1),
        Paragraph(
            f"Scan {_t(report.scan_id, 40)} · {_t(report.status, 20)}"
            + (f" · finished {_t(report.finished_at, 40)}" if report.finished_at else ""),
            small,
        ),
        Spacer(1, 8),
    ]
    counts = "  ".join(
        f'<font color="{SEV_COLOR[s]}"><b>{report.severity_counts[s]} {s}</b></font>'
        for s in SEVERITY_ORDER
        if report.severity_counts.get(s)
    )
    story.append(Paragraph(counts or "No findings.", body))
    if report.raw_findings:
        story.append(
            Paragraph(
                f"{report.raw_findings} raw findings became {report.unique_findings} after merging "
                f"duplicates across scanners ({round(report.dedup_rate * 100)}% fewer).",
                body,
            )
        )
    top = [f for f in report.top() if f["scoring"].get("risk_score") is not None]
    if top:
        story.append(Paragraph("Fix these first", h2))
        rows: list[list[Any]] = [["#", "RISK", "SEVERITY", "FINDING"]]
        for i, f in enumerate(top, 1):
            sc = f["scoring"]
            flag = " KEV" if sc.get("in_cisa_kev") else ""
            rows.append(
                [str(i), Paragraph(f"<b>{int(sc['risk_score'])}</b>{flag}", cell), sev(sc["normalized_severity"]),
                 Paragraph(f"{_t(f['title'], 200)}<br/><font name='Courier' size='7'>{_t(loc_label(f), 120)}</font>", cell)]
            )  # fmt: skip
        story.append(grid(rows, [8 * mm, 20 * mm, 24 * mm, w - 52 * mm]))
    story.append(Paragraph("Scanners", h2))
    srows: list[list[Any]] = [["SCANNER", "STATUS", "FINDINGS", "ERROR"]]
    for name, st in report.tool_status.items():
        srows.append([_t(name, 40), _t(st.get("status", ""), 20), str(int(st.get("findings") or 0)),
                      Paragraph(_t(st.get("error") or "", 200), cell)])  # fmt: skip
    story.append(grid(srows, [34 * mm, 24 * mm, 22 * mm, w - 80 * mm]))

    findings = report.by_severity()
    shown = findings[:MAX_FINDINGS]
    story.append(Paragraph(f"All findings ({report.unique_findings})", h2))
    if len(findings) > len(shown):
        story.append(
            Paragraph(
                f"Showing the first {len(shown)}; export SARIF or JSON for the complete list.",
                small,
            )
        )
    for f in shown:
        sc, ev = f["scoring"], f["evidence"]
        head = f"<b>{_t(f['title'], 220)}</b>"
        story.append(Spacer(1, 6))
        story.append(
            Table(
                [[sev(sc["normalized_severity"]), Paragraph(head, cell)]],
                colWidths=[24 * mm, w - 24 * mm],
                style=[("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEABOVE", (0, 0), (-1, 0), 0.4, colors.HexColor("#d9d9d0"))],
            )
        )  # fmt: skip
        meta = f"{_t(loc_label(f), 160)} · found by {_t(', '.join(ev['reported_by']), 80)}"
        if sc.get("risk_score") is not None:
            meta += f" · risk {int(sc['risk_score'])}"
        story.append(Paragraph(meta, mono))
        if f["description"]:
            story.append(Paragraph(_t(f["description"], 500), small))
        if f["remediation"]["summary"]:
            story.append(Paragraph(f"<b>Fix:</b> {_t(f['remediation']['summary'], 400)}", small))
    story.append(Spacer(1, 12))
    story.append(Paragraph(_t(DISCLAIMER, 400), small))
    doc.build(story)
    return buf.getvalue()
