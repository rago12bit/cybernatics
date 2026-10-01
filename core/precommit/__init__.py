"""Pre-commit hook: fast, native (no Docker) secrets + SAST checks on staged files (Week 51 task 4,
plan §23). See core/precommit/git_staged.py for reading the git index,
core/precommit/secrets_scan.py and core/precommit/sast_scan.py for the checks themselves, and
core/precommit/runner.py for how they compose. `bulwark precommit run`/`install` (cli/main.py) is
the command-line surface."""

from __future__ import annotations

from core.precommit.runner import MAX_FILE_BYTES, PrecommitResult, scan_files

__all__ = ["MAX_FILE_BYTES", "PrecommitResult", "scan_files"]
