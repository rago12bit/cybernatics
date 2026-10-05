"""The container entrypoint: parse one uploaded file and write the result as JSON.

    python -m core.imports.parsers.worker \
        --parser sarif --input /target/report --output /out/result.json

A saved mapping (the universal mapper, plan §42.4) is parsed with `--parser universal:<id>
--mapping /target/mapping.json`; `--analyze` describes a sample's shape instead of parsing it
(`analyze.py`), for writing a mapping. Both read the uploaded bytes, so both run here.

Runs inside the same locked-down sandbox as the scanners (no network, read-only root, every
capability dropped, non-root, memory and CPU caps) so that a parser bug triggered by a hostile
report is contained, instead of running in the API process that holds database credentials. The
input is mounted read-only; the only thing this writes is the output file. It deliberately imports
nothing from the database or API layers, which are not in the image.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.imports.parsers.analyze import analyze
from core.imports.parsers.base import IngestParser, ParseContext, ParseLimits
from core.imports.parsers.registry import get_parser
from core.imports.parsers.universal import MappingSpec, UniversalParser


def _parser(name: str, mapping: Path | None) -> IngestParser:
    if name.startswith("universal:"):
        if mapping is None:
            raise ValueError("a mapped import needs --mapping")
        return UniversalParser(MappingSpec.from_dict(json.loads(mapping.read_text())), name)
    return get_parser(name)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parser", required=True)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--max-bytes", type=int, default=ParseLimits().max_bytes)
    ap.add_argument("--max-seconds", type=float, default=ParseLimits().max_seconds)
    ap.add_argument("--mapping", type=Path, default=None)
    ap.add_argument("--analyze", action="store_true")
    args = ap.parse_args(argv)

    if args.analyze:
        with args.input.open("rb") as fh:
            result = analyze(
                fh, ParseLimits(max_bytes=args.max_bytes, max_seconds=args.max_seconds)
            )
        args.output.write_text(json.dumps(result))
        return 0

    ctx = ParseContext(limits=ParseLimits(max_bytes=args.max_bytes, max_seconds=args.max_seconds))
    name = args.parser
    # The result is written as it is produced: one finding in memory at a time, not a list, then
    # a list of dicts, then one giant string (three copies, which ran a 1 GiB container out of
    # memory at about 250,000 findings). `findings` comes first and the verdict (`error`,
    # `warnings`, ...) last, because only the end of the file says whether it was read in full.
    with args.output.open("w") as out:
        out.write('{"findings":[')
        try:
            parser = _parser(name, args.mapping)
            name = parser.name
            first = True
            with args.input.open("rb") as fh:
                for finding in parser.parse(fh, ctx):
                    out.write(("" if first else ",") + json.dumps(finding.to_dict()))
                    first = False
        except (ValueError, OSError) as exc:  # unknown parser, unreadable input
            ctx.error = str(exc)
        verdict = {
            "parser": name,
            "error": ctx.error,
            "can_close_missing": ctx.can_close_missing,
            "warnings": ctx.all_warnings(),
        }
        out.write("]," + json.dumps(verdict)[1:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
