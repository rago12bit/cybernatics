"""What every registered parser must be wired into, so adding one cannot quietly skip a step:
the fuzzing matrix, the sandbox image, the licence inventory and (for ported parsers) the vendored
fixtures. Each of these has bitten a real change -- a parser importing a module the sandbox image
did not copy only failed once the image was built and run."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from core.imports.parsers import PARSERS

ROOT = Path(__file__).resolve().parents[2]


def test_the_fuzz_matrix_covers_every_registered_parser() -> None:
    text = (ROOT / ".github/workflows/fuzz.yml").read_text()
    block = text[text.index("fuzz-ingest:") :]
    match = re.search(r"parser:\s*\[([^\]]*)\]", block)
    assert match, "fuzz-ingest has no parser matrix"
    # Every built-in parser, plus the universal mapper's fixed fuzz mappings and the sample analysis
    # (Week 59, tests/fuzz/mappings.py).
    from tests.fuzz.mappings import FUZZ_MAPPINGS

    expected = sorted({*PARSERS, *FUZZ_MAPPINGS, "analyze"})
    assert sorted(p.strip() for p in match.group(1).split(",")) == expected


def test_the_sandbox_image_copies_every_module_a_parser_imports() -> None:
    """Import the worker in a fresh interpreter, list every `core.*` module it pulled in, and check
    the Dockerfile copies each one. (tests/integration/test_ingest_sandbox_docker.py proves the same
    thing by running the image; this catches it without Docker.)"""
    code = (
        "import sys, core.imports.parsers.worker; "
        "print('\\n'.join(sorted(m for m in sys.modules if m == 'core' or m.startswith('core.'))))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True, cwd=ROOT
    ).stdout.split()
    copied = [
        tuple(line.split()[1:-1])
        for line in (ROOT / "docker/ingest-parser/Dockerfile").read_text().splitlines()
        if line.startswith("COPY ")
    ]
    sources = {Path(s).as_posix() for srcs in copied for s in srcs}

    def covered(module: str) -> bool:
        rel = module.replace(".", "/")
        return any(
            f"{rel}.py" == s or f"{rel}/__init__.py" == s or rel == s or rel.startswith(s + "/")
            for s in sources
        )

    missing = [m for m in out if not covered(m)]
    assert not missing, f"docker/ingest-parser/Dockerfile does not copy: {missing}"


@pytest.mark.parametrize("name", sorted(p for p, v in PARSERS.items() if v.ported_from))
def test_a_ported_parser_has_its_fixtures_and_its_licence_entry(name: str) -> None:
    parser = PARSERS[name]
    fixtures = ROOT / "tests/golden/ingest/defectdojo" / name
    assert (fixtures / "MANIFEST.json").is_file(), f"no vendored DefectDojo fixtures for {name}"
    licences = (ROOT / "THIRD_PARTY_LICENSES.md").read_text()
    assert f"`{parser.ported_from}`" in licences, "run scripts/gen-licenses.py"
    assert "Copyright (c) 2015-2023 DefectDojo, Inc." in licences
    src = Path(sys.modules[type(parser).__module__].__file__ or "").read_text()
    assert "THIRD_PARTY_LICENSES.md" in src, "the ported file must point at the licence"
    assert parser.ported_from.startswith("dojo/tools/")


def test_every_parser_suggests_a_real_deduplication_strategy() -> None:
    from core.dedup.strategies import STRATEGIES

    assert {p.default_dedup for p in PARSERS.values()} <= set(STRATEGIES)
    assert (
        PARSERS["nessus"].default_dedup == "tool_id" and PARSERS["grype"].default_dedup == "package"
    )
