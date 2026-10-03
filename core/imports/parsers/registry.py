"""Which parsers exist, and picking one from a file's first bytes (plan §42.2: "sniff() ...
confidence 0-1 that a file is this format. Drives auto-detection")."""

from __future__ import annotations

from core.imports.parsers.base import IngestParser
from core.imports.parsers.cyclonedx import CycloneDxParser
from core.imports.parsers.osv import OsvParser
from core.imports.parsers.sarif import SarifParser
from core.imports.parsers.spdx import SpdxParser

PARSERS: dict[str, IngestParser] = {
    p.name: p for p in (SarifParser(), CycloneDxParser(), SpdxParser(), OsvParser())
}

# Below this the import screen asks the person to confirm the format before showing counts (§55.1).
CONFIDENT = 0.9


def get_parser(name: str) -> IngestParser:
    try:
        return PARSERS[name]
    except KeyError:
        raise ValueError(f"unknown parser {name!r}; available: {sorted(PARSERS)}") from None


def detect(head: bytes) -> list[tuple[IngestParser, float]]:
    """Every parser that thinks it recognises `head`, most confident first."""
    scored = [(p, p.sniff(head)) for p in PARSERS.values()]
    return sorted(((p, c) for p, c in scored if c > 0), key=lambda pc: -pc[1])
