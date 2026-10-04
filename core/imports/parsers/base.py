"""The parser interface (plan §42.2): `sniff` says how likely a file is this format, `parse` streams
canonical Findings out of it.

Two rules shape everything here, both about untrusted input -- an uploaded report is attacker-
controlled bytes, parsed by us:

1. **Parsing never raises on bad input, and a bad file is never mistaken for a good one.** `parse`
   catches every failure and records it on the `ParseContext` instead. That matters more than it
   sounds: reimport closes whatever a file *no longer lists*, so a truncated or half-parsed file
   would look like "everything was fixed." A parse that did not reach the end of the file sets
   `ctx.error`, and callers must refuse to apply it (`ParseResult.complete`).
2. **Limits are enforced as the file is read, not after.** Size, nesting depth, wall-clock time and
   record count are checked in the streaming loop (`safe.py`), so a hostile file is stopped early
   instead of exhausting memory first.
"""

from __future__ import annotations

import io
import logging
import tempfile
import time
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from core.models.finding import Finding

log = logging.getLogger(__name__)

MAX_WARNINGS_KEPT = 50


class ParseAborted(Exception):
    """Internal: a limit was hit or the file is not valid. Never escapes `IngestParser.parse`."""


@dataclass(frozen=True)
class ParseLimits:
    max_bytes: int = 100 * 1024 * 1024  # the plan's own benchmark file size (§60)
    max_depth: int = 64  # real reports nest a dozen levels; a billion-laughs one nests thousands
    max_seconds: float = 60.0
    max_findings: int = 500_000


@dataclass
class ParseContext:
    """What a parse reports back, since a generator cannot return it: warnings (things that were
    skipped or approximated) and `error` (the file was not fully read -- do not apply it)."""

    limits: ParseLimits = field(default_factory=ParseLimits)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    # Whether this file can say a finding is *gone*. A scan report can ("it isn't listed, so it's
    # fixed"); an SBOM cannot -- it lists packages, not the absence of vulnerabilities -- so
    # importing one must never close anything. Parsers set this to False for such files, and the
    # importer then ignores `close_missing` (a request to close is not a licence to).
    can_close_missing: bool = True
    findings_seen: int = 0
    unknown_severities: Counter[str] = field(default_factory=Counter)
    _started: float = field(default_factory=time.monotonic, repr=False)
    _dropped_warnings: int = field(default=0, repr=False)

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS_KEPT:
            self.warnings.append(message)
        else:
            self._dropped_warnings += 1

    def unknown_severity(self, label: str) -> None:
        """A severity this format does not define: imported as Info, and said so at the end."""
        self.unknown_severities[label.strip().lower() or "(empty)"] += 1

    def all_warnings(self) -> list[str]:
        more = [f"... and {self._dropped_warnings} more warnings"] if self._dropped_warnings else []
        return [*self.warnings, *more]

    def check_time(self) -> None:
        if time.monotonic() - self._started > self.limits.max_seconds:
            raise ParseAborted(f"parsing took longer than {self.limits.max_seconds:g}s")

    def count_finding(self) -> None:
        self.findings_seen += 1
        if self.findings_seen > self.limits.max_findings:
            raise ParseAborted(f"more than {self.limits.max_findings} findings in one file")


@dataclass(frozen=True)
class ParseResult:
    parser: str
    findings: list[Finding]
    warnings: list[str]
    error: str | None
    can_close_missing: bool = True

    @property
    def complete(self) -> bool:
        """True only if the whole file was read. An incomplete result must never be applied."""
        return self.error is None


class IngestParser(ABC):
    name: str  # "sarif" -- what a caller passes to select it
    formats: frozenset[str]  # {"json"}; what the file can be
    categories: frozenset[str]  # {"sast"}: what it can produce
    label: str = ""  # "SARIF 2.1.0" -- how the import screen says "looks like ..."
    # Set when this parser is derived from another project's (the DefectDojo parsers, BSD-3-Clause):
    # the upstream file path, e.g. "dojo/tools/zap/parser.py". scripts/gen-licenses.py turns every
    # such parser into a THIRD_PARTY_LICENSES.md entry, so a ported file cannot ship without one.
    # The deduplication strategy suited to this source (plan §42.2's `default_dedup`): what the
    # settings screen recommends. It is only a recommendation: every source is matched by
    # `fingerprint_v2` until a project chooses otherwise through a previewed change (ADR-0042).
    default_dedup: str = "fingerprint_v2"
    ported_from: str = ""
    ported_into: tuple[str, ...] = ()  # other Bulwark files the port lives in (a shared mapper)

    @abstractmethod
    def sniff(self, head: bytes) -> float:
        """Confidence 0-1 that a file starting with `head` (its first few KB) is this format. Drives
        auto-detection; below 0.9 the import screen asks the user to confirm."""

    @abstractmethod
    def _parse(self, stream: BinaryIO, ctx: ParseContext) -> Iterator[Finding]:
        """The format-specific streaming parse. May raise `ParseAborted` or ValueError-family
        errors for bad input; `parse` turns those into `ctx.error`."""

    def parse(self, stream: BinaryIO, ctx: ParseContext | None = None) -> Iterator[Finding]:
        """Streaming; never loads the whole file; never raises on bad input (see module docstring).
        Pass a `ParseContext` to receive warnings and the error; without one they are only logged.
        """
        ctx = ctx or ParseContext()
        try:
            for finding in self._parse(stream, ctx):
                ctx.count_finding()
                yield finding
        except ParseAborted as exc:
            ctx.error = str(exc)
        except (ValueError, KeyError, TypeError, AttributeError, IndexError, OSError) as exc:
            ctx.error = f"not a valid {self.label or self.name} file ({type(exc).__name__}: {exc})"
        except Exception as exc:  # noqa: BLE001 - untrusted input must never crash the importer
            log.exception("%s parser failed unexpectedly", self.name)
            ctx.error = f"{self.name} parser failed unexpectedly ({type(exc).__name__})"
        for label, n in sorted(ctx.unknown_severities.items()):
            ctx.warn(
                f"{n} finding(s) use the severity {label!r}, which is not a known severity; "
                "imported as Info"
            )
        if ctx.error:
            log.warning("%s: %s", self.name, ctx.error)


def run_parser(
    parser: IngestParser, stream: BinaryIO, limits: ParseLimits | None = None
) -> ParseResult:
    """Run a parser to completion and collect everything it reports."""
    ctx = ParseContext(limits=limits or ParseLimits())
    findings = list(parser.parse(stream, ctx))
    return ParseResult(parser.name, findings, ctx.all_warnings(), ctx.error, ctx.can_close_missing)


def run_parser_on_bytes(
    parser: IngestParser, data: bytes, limits: ParseLimits | None = None
) -> ParseResult:
    limits = limits or ParseLimits()
    if len(data) > limits.max_bytes:
        return ParseResult(
            parser.name, [], [], f"file is {len(data)} bytes; the limit is {limits.max_bytes}"
        )
    return run_parser(parser, io.BytesIO(data), limits)


def seekable(stream: BinaryIO, limits: ParseLimits) -> BinaryIO:
    """A seekable stream for parsers that need two passes (SARIF reads rule metadata first, then
    streams results, so it doesn't matter which one the file lists first). Uploads already are;
    anything else is spooled to a temp file, bounded by the same size limit."""
    if stream.seekable():
        stream.seek(0)
        return stream
    spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)  # noqa: SIM115 - returned open
    copied = 0
    while chunk := stream.read(1024 * 1024):
        copied += len(chunk)
        if copied > limits.max_bytes:
            spool.close()
            raise ParseAborted(f"file exceeds the {limits.max_bytes} byte limit")
        spool.write(chunk)
    spool.seek(0)
    return spool  # type: ignore[return-value]
