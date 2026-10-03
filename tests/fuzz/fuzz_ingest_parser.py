"""Atheris fuzz harness for one uploaded-report parser (Week 54 task 6, plan §42.2/§22.3).

Usage:
    python tests/fuzz/fuzz_ingest_parser.py <parser-name> <corpus-dir> [libFuzzer args...]

Seed `corpus-dir` with real files first (`scripts/seed-fuzz-corpus.sh` does it from tests/golden).

The contract being fuzzed is the one `core.imports.parsers.base` states: parsing untrusted bytes
**never raises**, and always reports either a complete parse or an error. So the target calls the
parser with no try/except of its own -- any exception that escapes is a genuine finding. Run with
libFuzzer's own `-timeout=` and `-rss_limit_mb=` too: a parse that hangs or balloons is as much a
bug as one that raises (the parser's own limits are meant to prevent exactly that).

Needs `atheris`, which needs a Linux Clang+libFuzzer build (it does not install on macOS). Run it
in CI (.github/workflows/fuzz.yml) or in a Linux container. A crash libFuzzer writes as
`crash-<hash>` belongs in `tests/fuzz_regressions/ingest-<parser-name>/`, where
`tests/unit/test_fuzz_regressions.py` replays it forever.
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from core.imports.parsers import PARSERS, get_parser, run_parser_on_bytes


def _target(data: bytes) -> None:
    result = run_parser_on_bytes(get_parser(_target.parser_name), data)  # type: ignore[attr-defined]
    # The invariant the importer relies on: a result is complete or it says why not.
    assert result.complete or result.error, "parse neither completed nor reported an error"


def main(argv: list[str]) -> None:
    if len(argv) < 3 or argv[1] not in PARSERS:
        print(f"usage: {argv[0]} <parser-name> <corpus-dir> [libFuzzer args...]", file=sys.stderr)
        print(f"known parsers: {', '.join(sorted(PARSERS))}", file=sys.stderr)
        raise SystemExit(2)
    _target.parser_name = argv[1]  # type: ignore[attr-defined]
    atheris.Setup([argv[0], *argv[2:]], _target)
    atheris.Fuzz()


if __name__ == "__main__":
    main(sys.argv)
