"""Reports to PDF with headless Chromium (plan §48.3), run in a locked-down container: no network,
read-only, every capability dropped, a non-root user, memory and process limits -- the same shape as
cosign's (`core.attest.cosign`). The HTML is Bulwark's own, every value escaped, and it carries a
Content-Security-Policy allowing nothing but its inline styles and data: images; with no network
as well, a report cannot fetch, post or run anything, whatever an Issue's title says.

The image is Microsoft's Playwright image at the version the web tests pin, by digest; Chromium's
headless shell is all that is used from it. Set `BULWARK_PDF_IMAGE` to use another image with the
same layout (an air-gapped mirror, say). Chromium's own sandbox is off (`--no-sandbox`): it needs
privileges the container deliberately lacks, so the container is the sandbox.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from core.config import scratch_dir
from core.sandbox.output import OutputRefused, read_output

PDF_IMAGE = (
    "mcr.microsoft.com/playwright:v1.63.0-jammy"
    "@sha256:167d0506cfbe3c294fb214b2d11737326eeee028aa611fa1ba538e5057675847"
)
TIMEOUT_SECONDS = 120
MAX_HTML_BYTES = 20 * 1024 * 1024
MAX_PDF_BYTES = 50 * 1024 * 1024
_SHELL = (
    "exec /ms-playwright/chromium_headless_shell-*/chrome-headless-shell-*/chrome-headless-shell "
    "--no-sandbox --disable-gpu --disable-dev-shm-usage --no-pdf-header-footer "
    "--run-all-compositor-stages-before-draw --disable-extensions --disable-background-networking "
    "--print-to-pdf=/work/out.pdf file:///work/report.html"
)


class RenderError(RuntimeError):
    pass


def image() -> str:
    return os.environ.get("BULWARK_PDF_IMAGE", "").strip() or PDF_IMAGE


def to_pdf(html: str) -> bytes:
    """Render one HTML document to PDF. Raises RenderError with a reason a person can act on."""
    data = html.encode("utf-8")
    if len(data) > MAX_HTML_BYTES:
        raise RenderError("the report is too large to render (over 20 MB of HTML)")
    work = Path(tempfile.mkdtemp(prefix="bulwark-pdf-", dir=scratch_dir()))
    try:
        work.chmod(0o777)  # the image's own non-root user writes out.pdf here
        (work / "report.html").write_bytes(data)
        argv = [
            "docker", "run", "--rm", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--memory=1g", "--pids-limit=256",
            "--tmpfs=/tmp:rw,nosuid,size=256m", "-e", "HOME=/tmp", "--user=pwuser",
            "-v", f"{work}:/work", image(), "sh", "-c", _SHELL,
        ]  # fmt: skip
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
        except FileNotFoundError as exc:
            raise RenderError("docker is not installed or not on PATH") from exc
        except subprocess.TimeoutExpired as exc:
            raise RenderError("rendering the PDF took longer than two minutes") from exc
        try:  # a regular file, not whatever a link in the shared directory points to
            pdf = read_output(work / "out.pdf", MAX_PDF_BYTES)
        except OutputRefused as exc:
            raise RenderError("Chromium's output was not a usable PDF") from exc
        if proc.returncode != 0 or pdf is None:
            err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            tail = next((ln for ln in reversed(err) if "ERROR" in ln or "rror" in ln), "")
            if (
                "Unable to find image" in proc.stderr.decode("utf-8", "replace")
                or "No such image" in tail
            ):
                raise RenderError(f"the PDF renderer image is not available locally: {image()}")
            raise RenderError(f"Chromium could not render the PDF: {tail[:300] or 'no output'}")
        if not pdf.startswith(b"%PDF-"):
            raise RenderError("Chromium's output was not a usable PDF")
        return pdf
    finally:
        shutil.rmtree(work, ignore_errors=True)
