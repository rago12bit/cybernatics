"""The predicate of a Bulwark scan attestation: what was scanned, with what, and what came out.

The attestation says "this Bulwark, with these scanner images, produced these artifacts from this input".
It does not say the findings are correct or complete, and it holds counts, never the findings themselves.
"""

from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from typing import Any

PREDICATE_TYPE = "https://github.com/Rag2102/cyberimp/attestations/scan/v1"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def bulwark_version() -> str:
    try:
        return metadata.version("bulwark-scan")
    except metadata.PackageNotFoundError:
        return "unknown"


def image_id(image: str) -> str | None:
    """Local image id (a content hash of the scanner image), or None if Docker cannot say."""
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, timeout=20, check=False,
        )  # fmt: skip
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = out.stdout.decode().strip()
    return text if out.returncode == 0 and text.startswith("sha256:") else None


def build_predicate(
    scan: dict[str, Any],
    artifacts: dict[str, Path],
    images: dict[str, str],
    source: dict[str, str] | None = None,
    now: datetime | None = None,
    resolve_image: Any = image_id,
) -> dict[str, Any]:
    """`scan` is `bulwark scan --format json` output; `images` maps tool name to its image reference."""
    findings = scan.get("findings", [])
    by_sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = str(f.get("scoring", {}).get("normalized_severity", "")).upper()
        if sev in by_sev:
            by_sev[sev] += 1
    stats = scan.get("stats", {})
    tools = []
    for name, st in sorted(scan.get("tool_status", {}).items()):
        entry: dict[str, Any] = {"name": name, "status": st.get("status", "unknown")}
        if "findings" in st:
            entry["findings"] = st["findings"]
        if name in images:
            entry["image"] = images[name]
            iid = resolve_image(images[name])
            if iid:
                entry["imageId"] = iid
        tools.append(entry)
    return {
        "scanner": {"name": "bulwark", "version": bulwark_version()},
        "source": {k: v for k, v in (source or {}).items() if v},
        "tools": tools,
        "result": {
            "uniqueFindings": stats.get("unique_findings", len(findings)),
            "rawFindings": stats.get("raw_findings", len(findings)),
            "ignoredFindings": stats.get("ignored_findings", 0),
            "bySeverity": by_sev,
        },
        "artifacts": [
            {"name": n, "sha256": sha256_file(p), "bytes": p.stat().st_size}
            for n, p in sorted(artifacts.items())
        ],
        "generatedAt": (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limitations": (
            "Attests that this Bulwark produced these artifacts from this input with these scanner images. "
            "It does not attest that the findings are correct or complete."
        ),
    }
