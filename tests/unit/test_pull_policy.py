"""Images Bulwark builds itself are never pulled (core.sandbox.docker_runtime.pull_policy).

They are built from docker/<tool>/Dockerfile and never published, so with Docker's default pull
policy a missing one would be fetched as `docker.io/bulwark/<tool>` -- a Docker Hub namespace
Bulwark does not own (no public repository there on 2026-10-14). A missing image is now Docker's
"No such image" error, reported as the tool's error. Images that are meant to be pulled are left
alone: digest-pinned ones, official ones, and a plugin's own image, checked by signature first."""

from __future__ import annotations

import re
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
        ZAP_IMAGE,  # ZAP's own registry namespace, pinned by digest
        "python:3.12-slim",  # the fix agent's language images, Docker official images
        "ghcr.io/acme/bulwark-plugin-demo:1.0",  # a plugin's image, signature-checked before use
        "docker.io/bulwark/semgrep:1.90.0",  # not a reference Bulwark itself uses
    ],
)
def test_images_meant_to_be_pulled_keep_dockers_default(image: str) -> None:
    assert pull_policy(image) == []


ROOT = Path(__file__).resolve().parents[2]


def _stage_names(dockerfile: str) -> set[str]:
    return {m.lower() for m in re.findall(r"(?im)^FROM\s+\S+\s+AS\s+(\S+)", dockerfile)}


def _dockerfiles() -> list[Path]:
    found = [*ROOT.glob("docker/*/Dockerfile"), ROOT / "web" / "Dockerfile"]
    assert len(found) > 15
    return sorted(found)


@pytest.mark.parametrize("dockerfile", _dockerfiles(), ids=lambda p: str(p.relative_to(ROOT)))
def test_every_base_image_is_pinned_by_digest(dockerfile: Path) -> None:
    """A tag can be moved; a rebuild then takes whatever it points to. (tests/fixtures' deliberately
    old ubuntu image is a scan fixture, never built.)"""
    text = dockerfile.read_text()
    stages = _stage_names(text)
    for ref in re.findall(r"(?im)^FROM\s+(?:--\S+\s+)*(\S+)", text):
        assert ref.lower() in stages or "@sha256:" in ref, f"{dockerfile.name}: FROM {ref}"


def test_every_compose_image_is_built_here_or_pinned_by_digest() -> None:
    for ref in re.findall(r"(?m)^\s+image:\s+(\S+)", (ROOT / "docker-compose.yml").read_text()):
        assert ref.startswith(LOCAL_NAMESPACE) or "@sha256:" in ref, ref


def test_every_image_ci_runs_is_pinned_by_digest() -> None:
    text = "\n".join(p.read_text() for p in (ROOT / ".github" / "workflows").glob("*.yml"))
    refs = re.findall(r"(?m)^\s+image:\s+([^\s$]\S*)", text)
    refs += re.findall(r"docker pull\s+(?:--\S+\s+)*(\S+)", text)
    # and any registry image named elsewhere, e.g. in a `docker run` (ZAP, Keycloak)
    refs += re.findall(
        r"\b(?:[a-z0-9-]+\.)+(?:io|com|dev)/[\w./-]+:[\w.-]+(?:@sha256:[0-9a-f]+)?", text
    )
    assert refs
    for ref in refs:
        assert "@sha256:" in ref, ref


def test_the_images_the_code_pulls_are_pinned_by_digest() -> None:
    for ref in (ZAP_IMAGE, COSIGN_IMAGE, PDF_IMAGE):
        assert "@sha256:" in ref, ref


def test_every_ci_job_runs_on_a_pinned_runner_image() -> None:
    """`ubuntu-latest` moves (to Ubuntu 26 from 2026-10-19): apt packages, Docker and Python can
    change under an unchanged commit. A new runner image is a change made on purpose."""
    runners = []
    for p in (ROOT / ".github" / "workflows").glob("*.yml"):
        runners += [(p.name, r) for r in re.findall(r"(?m)^\s+runs-on:\s+(\S+)", p.read_text())]
    assert len(runners) >= 19
    for name, runner in runners:
        assert not runner.endswith("-latest"), f"{name}: runs-on {runner}"


def test_every_helm_chart_image_is_pinned_by_digest() -> None:
    """The chart's images were by tag (one `:latest`) until 2026-10-15; the app's own images come
    from `.Values.image.*`, which the operator sets to what they built."""
    refs = []
    for p in (ROOT / "helm").rglob("*"):
        if p.suffix in (".yaml", ".tpl"):
            refs += re.findall(r"(?m)^[ \t]+image:[ \t]+([^\s\"{]\S*)", p.read_text())
    assert len(refs) >= 6
    for ref in refs:
        assert "@sha256:" in ref, ref
