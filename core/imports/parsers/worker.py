"""The container entrypoint: parse one uploaded file and write the result as JSON.

    python -m core.imports.parsers.worker \
        --parser sarif --input /target/report --output /out/result.json

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

from core.imports.parsers.base import ParseLimits, run_parser
from core.imports.parsers.registry import get_parser


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parser", required=True)
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--max-bytes", type=int, default=ParseLimits().max_bytes)
    ap.add_argument("--max-seconds", type=float, default=ParseLimits().max_seconds)
    args = ap.parse_args(argv)

    limits = ParseLimits(max_bytes=args.max_bytes, max_seconds=args.max_seconds)
    try:
        parser = get_parser(args.parser)
        with args.input.open("rb") as fh:
            result = run_parser(parser, fh, limits)
        payload = {
            "parser": result.parser,
            "error": result.error,
            "warnings": result.warnings,
            "findings": [f.to_dict() for f in result.findings],
        }
    except (ValueError, OSError) as exc:  # unknown parser, unreadable input
        payload = {"parser": args.parser, "error": str(exc), "warnings": [], "findings": []}
    args.output.write_text(json.dumps(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main())
