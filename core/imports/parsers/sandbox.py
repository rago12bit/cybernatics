"""Parse an uploaded report inside the scanner sandbox (plan §42.2: "Parse in the same sandbox as
scanners"). Every report is attacker-controlled input; running its parser in a container with no
network, a read-only filesystem and no capabilities means a parser bug costs one throwaway
container, not the process that holds the database credentials.

This reuses `core.runner.run_tool` -- the one place that builds the hardened `docker run`, enforces
the wall-clock timeout and kills a runaway container -- through a small pseudo-adapter, so there is
no second implementation of the sandbox to keep as strict as the first.
"""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path

from core.adapters.base import RepoContext, ToolAdapter, ToolSpec
from core.config import scratch_dir
from core.imports.parsers.base import ParseLimits, ParseResult
from core.models import Finding, finding_from_dict
from core.runner import RunResult, run_tool
from core.sandbox.runtime import SandboxRuntime

log = logging.getLogger(__name__)

INPUT_NAME = "report"  # what the uploaded file is called inside the container; never user-chosen


class IngestParseAdapter(ToolAdapter):
    """Not a scanner: it only gives `run_tool` a spec and a command for the parser image."""

    spec = ToolSpec(
        name="ingest-parser",
        image="bulwark/ingest-parser:1",
        categories=frozenset(),
        languages=frozenset(),
        timeout_seconds=300,
        memory_limit="1g",
        cpus=1.0,
    )

    def __init__(self, parser_name: str, limits: ParseLimits) -> None:
        self._parser_name = parser_name
        self._limits = limits

    def build_command(
        self, target: Path, output: Path, ctx: RepoContext | None = None
    ) -> list[str]:
        return [
            "--parser", self._parser_name,
            "--input", str(target / INPUT_NAME),
            "--output", str(output),
            "--max-bytes", str(self._limits.max_bytes),
            "--max-seconds", str(self._limits.max_seconds),
        ]  # fmt: skip

    def parse(self, raw: bytes) -> list[Finding]:
        return _decode(raw, self._parser_name).findings


def _decode(raw: bytes, parser_name: str) -> ParseResult:
    """The container's JSON -> a ParseResult. Never raises: the container is untrusted too, so a
    malformed result is reported as an error rather than trusted or crashed on."""
    try:
        doc = json.loads(raw)
        error = doc.get("error")
        # A file that was not read in full is never applied, so its partial findings are not built.
        findings = [] if error else [finding_from_dict(d) for d in doc["findings"]]
        return ParseResult(
            str(doc.get("parser", parser_name)),
            findings,
            [str(w) for w in doc.get("warnings", [])],
            None if error is None else str(error),
            # A container that does not say, or says something odd, is not trusted to allow closing.
            doc.get("can_close_missing") is True,
        )
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        return ParseResult(
            parser_name, [], [], f"the parser sandbox returned unreadable output ({exc})"
        )


def _failure(run: RunResult, spec: ToolSpec) -> str:
    """What to tell a person when the container produced nothing. Retrying only helps for a
    transient failure, which is not what a timeout or an exhausted memory limit is."""
    if run.status == "timeout":
        return (
            f"the parser did not finish within {spec.timeout_seconds}s; the file is too large or "
            "too slow to import"
        )
    if run.exit_code == 137:  # SIGKILL: what the kernel does to a container over its memory limit
        return (
            f"the parser was stopped for using more than its {spec.memory_limit} memory limit; "
            "the file has too many findings to import in one piece -- split it"
        )
    return f"the parser sandbox did not finish ({run.status}, exit {run.exit_code}); try again"


def parse_in_sandbox(
    path: Path,
    parser_name: str,
    limits: ParseLimits | None = None,
    *,
    runtime: SandboxRuntime | None = None,
) -> ParseResult:
    """Parse `path` with `parser_name` in a container. A container that fails, times out or is
    killed produces an *error* result, never an empty successful one: an empty parse would look like
    "the report lists nothing" and close everything it used to list."""
    limits = limits or ParseLimits()
    adapter = IngestParseAdapter(parser_name, limits)
    # The shared scratch directory, not the process's own /tmp: in the worker container the Docker
    # daemon is on the host, so the bind-mount source must be a path that exists on both (the same
    # reason `core.runner.run_tool` uses it for its own output directory).
    with tempfile.TemporaryDirectory(prefix="bulwark-ingest-", dir=scratch_dir()) as tmp:
        shutil.copyfile(path, Path(tmp) / INPUT_NAME)
        Path(tmp).chmod(0o755)
        (Path(tmp) / INPUT_NAME).chmod(0o644)  # the container runs as a different, non-root uid
        run: RunResult = run_tool(adapter, Path(tmp), runtime=runtime)
    # The worker exits 0 whenever it finished, even on a bad file (the verdict is in its output). A
    # non-zero exit with output means it was killed part-way through writing it.
    if run.status != "ok" or run.exit_code not in (0, None):
        log.warning("ingest sandbox: %s (%s)", run.status, run.stderr.strip()[-300:])
        return ParseResult(parser_name, [], [], _failure(run, adapter.spec))
    return _decode(run.raw, parser_name)
