"""Orchestrates the pre-commit checks over a set of (path, text) pairs (plan §23, Week 51 task 4).

Deliberately source-agnostic about *where* the files came from -- core/precommit/git_staged.py
(native hook, reads the git index) and the `pre-commit` framework (which passes file paths already
checked out to the content it wants scanned) both reduce to the same `list[(path, text)]` shape, so
this module and its tests don't need to know which caller it was.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core.ignore import IgnoreRules, apply_ignore
from core.models import Finding
from core.precommit.sast_scan import scan_python_sast
from core.precommit.secrets_scan import scan_secrets

# Skip anything bigger than this outright: a generated lockfile or vendored blob dwarfs the time
# budget for no security value, and secret/credential patterns don't hide in multi-megabyte files
# any more effectively than in the first chunk of one.
MAX_FILE_BYTES = 512 * 1024

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class PrecommitResult:
    findings: list[Finding]
    files_scanned: int
    files_skipped_binary: list[str] = field(default_factory=list)
    files_skipped_large: list[str] = field(default_factory=list)
    ignored_count: int = 0
    elapsed_seconds: float = 0.0

    def blocking(self, fail_on: str = "HIGH") -> list[Finding]:
        floor = _SEVERITY_RANK.get(fail_on.upper(), _SEVERITY_RANK["HIGH"])
        return [
            f for f in self.findings
            if _SEVERITY_RANK.get(f.scoring.normalized_severity.value.upper(), 0) >= floor
        ]  # fmt: skip


def scan_files(
    files: list[tuple[str, str | bytes | None]], *, ignore_rules: IgnoreRules | None = None
) -> PrecommitResult:
    """`files` is (repo-relative path, text content or None-for-binary). Bytes are decoded as
    UTF-8 and treated as binary (skipped) on failure, so callers can pass raw file content without
    pre-checking it themselves."""
    start = time.monotonic()
    findings: list[Finding] = []
    scanned = 0
    skipped_binary: list[str] = []
    skipped_large: list[str] = []

    for path, content in files:
        if isinstance(content, bytes):
            if len(content) > MAX_FILE_BYTES:
                skipped_large.append(path)
                continue
            try:
                content = content.decode("utf-8")
            except UnicodeDecodeError:
                content = None
        if content is None:
            skipped_binary.append(path)
            continue
        if len(content.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
            skipped_large.append(path)
            continue

        scanned += 1
        findings.extend(scan_secrets(path, content))
        if path.endswith(".py"):
            findings.extend(scan_python_sast(path, content))

    ignored_count = 0
    if ignore_rules is not None and ignore_rules.patterns:
        findings, ignored_count = apply_ignore(findings, ignore_rules)

    return PrecommitResult(
        findings=findings,
        files_scanned=scanned,
        files_skipped_binary=skipped_binary,
        files_skipped_large=skipped_large,
        ignored_count=ignored_count,
        elapsed_seconds=time.monotonic() - start,
    )
