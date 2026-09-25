"""Report exports: SARIF (GitHub Code Scanning), HTML and PDF. Each is a pure function of `ReportData`."""

from __future__ import annotations

import json

from core.export.html import to_html
from core.export.model import ReportData
from core.export.pdf import to_pdf
from core.export.sarif import to_sarif

# format -> (media type, file extension)
FORMATS: dict[str, tuple[str, str]] = {
    "json": ("application/json", "json"),
    "sarif": ("application/sarif+json", "sarif"),
    "html": ("text/html; charset=utf-8", "html"),
    "pdf": ("application/pdf", "pdf"),
}


def render(fmt: str, report: ReportData) -> bytes:
    if fmt == "sarif":
        return json.dumps(to_sarif(report), indent=2).encode()
    if fmt == "html":
        return to_html(report).encode("utf-8")
    if fmt == "pdf":
        return to_pdf(report)
    if fmt == "json":
        doc = {
            "scan_id": report.scan_id,
            "source": report.source_label,
            "status": report.status,
            "raw_findings": report.raw_findings,
            "unique_findings": report.unique_findings,
            "severity_counts": report.severity_counts,
            "findings": report.findings,
        }
        return json.dumps(doc, indent=2).encode()
    raise ValueError(f"unknown export format: {fmt}")


__all__ = ["FORMATS", "ReportData", "render", "to_html", "to_pdf", "to_sarif"]
