"""Software bill of materials (CycloneDX 1.6) from Syft, run in the same sandbox as every scanner.

Syft lists what the project contains; it does not judge it. The SBOM is a separate artifact from the findings,
and `bulwark attest` can sign it. It is generated from the sanitized workspace, so installed dependency
directories (node_modules, virtualenvs) are not in it: lockfiles and manifests are.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.adapters.base import RepoContext, ToolAdapter, ToolSpec
from core.models import Finding
from core.runner import run_tool

SYFT_IMAGE = "bulwark/syft:1.52.0"
SPEC_VERSION = "1.6"
MAX_SBOM_BYTES = 200 * 1024 * 1024


class SbomError(RuntimeError):
    pass


class SyftAdapter(ToolAdapter):
    """Fits the runner's contract; produces a document, not findings."""

    spec = ToolSpec(
        name="syft",
        image=SYFT_IMAGE,
        categories=frozenset({"sbom"}),
        languages=frozenset(),
        timeout_seconds=600,
    )

    def __init__(self, source_name: str = "project") -> None:
        self.source_name = source_name

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "scan", f"dir:{target}",
            "--output", f"cyclonedx-json@{SPEC_VERSION}={output}",
            "--source-name", self.source_name,
            "--quiet",
        ]  # fmt: skip

    def parse(self, raw: bytes) -> list[Finding]:
        return []  # not a findings tool


@dataclass(frozen=True)
class Sbom:
    raw: bytes
    components: int
    spec_version: str
    ecosystems: dict[str, int]


def summarize(raw: bytes) -> Sbom:
    """Validate the essentials of a CycloneDX document and count what is in it."""
    try:
        doc: Any = json.loads(raw)
        if doc["bomFormat"] != "CycloneDX" or not isinstance(doc.get("components", []), list):
            raise ValueError("not a CycloneDX document")
        eco: dict[str, int] = {}
        comps = doc.get("components", [])
        for c in comps:
            purl = str(c.get("purl", ""))
            if purl.startswith("pkg:"):
                kind = purl[4:].split("/", 1)[0]
                eco[kind] = eco.get(kind, 0) + 1
        return Sbom(raw, len(comps), str(doc.get("specVersion", "")), eco)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise SbomError(f"Syft output is not a valid CycloneDX document: {exc}") from exc


def generate_sbom(target: Path, source_name: str = "project") -> Sbom:
    """Run Syft on `target` (already a sanitized workspace). Raises SbomError with a readable reason."""
    result = run_tool(SyftAdapter(source_name[:200] or "project"), target)
    if result.status != "ok":
        detail = result.stderr.strip().splitlines()[-1:] or [result.status]
        raise SbomError(f"Syft did not produce an SBOM ({result.status}): {detail[0][:300]}")
    if len(result.raw) > MAX_SBOM_BYTES:
        raise SbomError("SBOM is unreasonably large")
    return summarize(result.raw)
