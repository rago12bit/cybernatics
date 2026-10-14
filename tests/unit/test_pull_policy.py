"""Images Bulwark builds itself are never pulled (core.sandbox.docker_runtime.pull_policy).

They are built from docker/<tool>/Dockerfile and never published, so with Docker's default pull
policy a missing one would be fetched as `docker.io/bulwark/<tool>` -- a Docker Hub namespace
Bulwark does not own (no public repository there on 2026-10-14). A missing image is now Docker's
"No such image" error, reported as the tool's error. Images that are meant to be pulled are left
alone: digest-pinned ones, official ones, and a plugin's own image, checked by signature first."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from core.attest.cosign import COSIGN_IMAGE
from core.dast.adapters import nuclei
from core.dast.adapters.zap import ZAP_IMAGE
from core.imports.parsers import ParseLimits
from core.imports.parsers.sandbox import IngestParseAdapter
from core.reports.pdf import PDF_IMAGE
from core.sandbox.docker_runtime import LOCAL_NAMESPACE, build_docker_argv, pull_policy
from core.sbom.syft import SyftAdapter
from core.scan import ADAPTERS


def _argv(adapter: Any) -> list[str]:
    return build_docker_argv(adapter, Path("/tmp/t"), Path("/tmp/o"), "c")


@pytest.mark.parametrize(
    "adapter",
    [*ADAPTERS.values(), SyftAdapter(), IngestParseAdapter("sarif", ParseLimits())],
    ids=lambda a: a.spec.name,
)
def test_every_built_in_image_is_built_here_or_pinned_by_digest(adapter: Any) -> None:
    """Built here: never pulled. Anyone else's (gitleaks, from its author): pinned by digest, so a
    moved tag cannot change what runs. A new built-in tool must be one or the other."""
    image = adapter.spec.image
    argv = _argv(adapter)
    if image.startswith(LOCAL_NAMESPACE):
        assert argv[argv.index(image) - 1] == "--pull=never"
    else:
        assert "@sha256:" in image, image
        assert "--pull=never" not in argv  # it has to be fetched; the digest is what it must be


def test_a_tool_version_is_its_tag_even_when_pinned_by_digest() -> None:
    from core.scan import _tool_version

    assert _tool_version("gitleaks") == "v8.21.0"
    assert _tool_version("bandit") == "1.7.10"


def test_nuclei_runs_with_pull_never(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess
    import sys

    seen: dict[str, list[str]] = {}
    real = subprocess.Popen

    def fake(argv: list[str], **kw: Any) -> Any:
        seen["argv"] = argv
        return real([sys.executable, "-c", "pass"], **kw)

    monkeypatch.setattr(nuclei.subprocess, "Popen", fake)
    nuclei.run_nuclei("https://example.com/")
    argv = seen["argv"]
    assert argv[argv.index(nuclei.NUCLEI_IMAGE) - 1] == "--pull=never"


@pytest.mark.parametrize(
    "image",
    [
        COSIGN_IMAGE,  # pinned by digest: what is pulled cannot change
        PDF_IMAGE,
        ZAP_IMAGE,  # ZAP's own registry namespace
        "python:3.12-slim",  # the fix agent's language images, Docker official images
        "ghcr.io/acme/bulwark-plugin-demo:1.0",  # a plugin's image, signature-checked before use
        "docker.io/bulwark/semgrep:1.90.0",  # not a reference Bulwark itself uses
    ],
)
def test_images_meant_to_be_pulled_keep_dockers_default(image: str) -> None:
    assert pull_policy(image) == []
