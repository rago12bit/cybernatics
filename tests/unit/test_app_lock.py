"""The app image installs from docker/app/requirements.txt with --require-hashes; it must stay in step
with pyproject.toml, or a dependency added there never reaches the image (the build fails instead).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "docker" / "app" / "requirements.txt"
INPUTS = ROOT / "docker" / "app" / "requirements.in"
EXTRAS = ("llm", "otel")  # what the Dockerfile's image carries
IMAGE_ENV = {"python_version": "3.12", "python_full_version": "3.12.0", "sys_platform": "linux",
             "platform_system": "Linux", "os_name": "posix", "implementation_name": "cpython",
             "platform_python_implementation": "CPython", "extra": ""}  # fmt: skip
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?==([^\s;\\]+)")


def _pins(text: str) -> dict[str, str]:
    return {canonicalize_name(m[1]): m[3] for line in text.splitlines() if (m := PIN.match(line))}


def _wanted() -> list[Requirement]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    lines = list(project["dependencies"])
    for extra in EXTRAS:
        lines += project["optional-dependencies"][extra]
    for line in INPUTS.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    reqs = [Requirement(line) for line in lines]
    return [r for r in reqs if r.marker is None or r.marker.evaluate(IMAGE_ENV)]


def test_every_image_dependency_is_pinned_at_a_version_pyproject_allows() -> None:
    pins = _pins(LOCK.read_text())
    problems = []
    for req in _wanted():
        version = pins.get(canonicalize_name(req.name))
        if version is None:
            problems.append(f"{req.name}: not in the lock")
        elif not req.specifier.contains(version, prereleases=True):
            problems.append(f"{req.name}: lock has {version}, pyproject wants {req.specifier}")
    assert not problems, "run scripts/lock-app-deps.sh:\n" + "\n".join(problems)


def test_every_pin_carries_a_hash() -> None:
    blocks = re.split(r"\n(?=[A-Za-z0-9])", LOCK.read_text())
    unhashed = [b.split()[0] for b in blocks if PIN.match(b) and "--hash=sha256:" not in b]
    assert not unhashed, f"pins without a hash: {unhashed}"


def test_the_pin_parser_reads_the_lock() -> None:
    # Guards the two tests above against passing vacuously on a format change.
    pins = _pins(LOCK.read_text())
    assert len(pins) > 50 and "fastapi" in pins and "setuptools" in pins
