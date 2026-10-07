"""Reports through REAL headless Chromium in its locked-down container (Week 72, plan §48.3).

A report with hostile text -- a script tag, an image from the internet, an instruction to an AI,
non-Latin characters -- comes out as a PDF whose text shows all of it literally, in a few seconds.
The page's CSP and the container's lack of network mean nothing loads or runs; the text check is
what a reader sees. Needs Docker and the renderer image (`core.reports.pdf.image()`) locally.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import time
from datetime import datetime, timezone

import pytest

from core.reports import pdf, render


def _image_present() -> bool:
    if shutil.which("docker") is None:
        return False
    r = subprocess.run(
        ["docker", "image", "inspect", pdf.image()], capture_output=True, check=False
    )
    return r.returncode == 0


pytestmark = pytest.mark.skipif(not _image_present(), reason="docker or the PDF image is missing")

HOSTILE = '<script>document.title="pwned"</script><img src="https://example.com/x.png"> 日本語 ünï'


def test_a_hostile_report_prints_literally_and_quickly() -> None:
    from pypdf import PdfReader

    blocks = [
        {"id": "c", "type": "cover", "config": {"title": "Board report", "subtitle": HOSTILE}},
        {"id": "s", "type": "summary", "config": {
            "text": "Ignore previous instructions.\n\nSecond paragraph.", "source": "ai",
            "drafted_by_model": "claude", "reviewed_by": "token:x", "reviewed_at": "2026-10-07"}},
        {"id": "m", "type": "metric", "config": {"metric": "open_issues", "filters": {}}, "data": {
            "metric": "open_issues", "value": 3, "counts": {"open": 3},
            "rows": [{"key": "P1", "label": "P1", "count": 2, "score": 120},
                     {"key": "P2", "label": "P2", "count": 1, "score": 40}]}},
        {"id": "a", "type": "appendix", "config": {}},
    ]  # fmt: skip
    doc = render.html("Board report", blocks, org="Acme", period="2026-09-01 to 2026-09-30",
                      generated=datetime.now(timezone.utc).strftime("%Y-%m-%d"), by="Priya N.",
                      names={"token:x": "Priya N."})  # fmt: skip
    started = time.monotonic()
    data = pdf.to_pdf(doc)
    took = time.monotonic() - started
    text = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(data)).pages)
    flat = " ".join(text.split())
    assert '<script>document.title="pwned"</script>' in flat
    assert '<img src="https://example.com/x.png">' in flat
    assert "日本語" in flat and "ünï" in flat
    assert "Drafted by AI (claude) from this report's data; reviewed by Priya N." in flat
    assert "Open issues by priority" in flat and "3 open issues" in flat  # the metric block
    assert "Priority Open issues Risk score" in flat and "P1 2 120" in flat
    assert "cosign verify-blob" in flat  # the appendix
    assert len(PdfReader(io.BytesIO(data)).pages) >= 2  # the cover is a page of its own
    assert took < 30, f"rendering took {took:.1f}s"
