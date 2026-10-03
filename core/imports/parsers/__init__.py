"""Parsers for uploaded reports (plan §42.2). `registry.get_parser(name)` / `registry.detect(head)`;
`base.run_parser` runs one to completion. See `base.py` for the two rules every parser follows:
never raise on bad input, and never let a half-read file pass for a whole one."""

from core.imports.parsers.base import (
    IngestParser,
    ParseContext,
    ParseLimits,
    ParseResult,
    run_parser,
    run_parser_on_bytes,
)
from core.imports.parsers.registry import CONFIDENT, PARSERS, detect, get_parser

__all__ = [
    "CONFIDENT",
    "PARSERS",
    "IngestParser",
    "ParseContext",
    "ParseLimits",
    "ParseResult",
    "detect",
    "get_parser",
    "run_parser",
    "run_parser_on_bytes",
]
