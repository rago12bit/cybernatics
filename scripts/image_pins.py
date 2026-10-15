"""Every container image this repository pins by digest, and where (THREAT-MODEL T10).

Shared by scripts/verify-image-signatures.py (CI checks each signed one's signature) and
tests/unit/test_image_signers.py (each one is either signed by a known publisher or recorded as
unsigned, with the reason). Images Bulwark builds itself (`bulwark/*`) are not pinned: they are never
pulled (core.sandbox.docker_runtime.pull_policy).
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Where images are named: Dockerfiles, compose, CI, the Action's build script, the Helm chart and
# the code (adapters, the PDF renderer, cosign, ZAP).
SOURCES = (
    "docker/*/Dockerfile",
    "web/Dockerfile",
    "docker-compose.yml",
    ".github/workflows/*.yml",
    "action/*.sh",
    "helm/**/*.yaml",
    "helm/**/*.tpl",
    "core/**/*.py",
)

_REF = re.compile(
    r"(?<![\w./:-])((?:[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*"
    r"(?::[\w][\w.-]*)?)@(sha256:[0-9a-f]{64})"
)
# "image:tag"\n    "@sha256:..." -- a reference split over two Python string literals.
_SPLIT_LITERAL = re.compile(r'"\s*\n\s*"')


def repository(ref: str) -> str:
    """`aquasec/trivy:0.55.2@sha256:...` -> `aquasec/trivy` (the registry host is kept)."""
    name = ref.split("@", 1)[0]
    head, _, last = name.rpartition("/")
    last = last.split(":", 1)[0]
    return f"{head}/{last}" if head else last


def pinned_images(root: Path = ROOT) -> dict[str, list[str]]:
    """`{image@digest: [files that name it]}` for every digest-pinned reference."""
    found: dict[str, set[str]] = defaultdict(set)
    for pattern in SOURCES:
        for path in sorted(root.glob(pattern)):
            text = path.read_text()
            if path.suffix == ".py":
                text = _SPLIT_LITERAL.sub("", text)
            for name, digest in _REF.findall(text):
                found[f"{name}@{digest}"].add(str(path.relative_to(root)))
    return {ref: sorted(files) for ref, files in sorted(found.items())}
