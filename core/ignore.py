""".bulwarkignore: paths whose findings should not be reported (test fixtures, vendored code).

One glob per line, `#` starts a comment. A pattern without a slash matches a file or directory name anywhere;
with a slash it is anchored at the project root. A trailing slash means "this directory and everything under
it". `*` does not cross `/`; `**` does. Ignored findings are dropped from the report but COUNTED, and the
count is shown, so ignoring is never silent.

Trust: a change can add an ignore file to hide its own findings. CI therefore passes the file from the base
branch explicitly (`bulwark scan --ignore-file`) instead of trusting the one in the code under review.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from core.models import Finding

IGNORE_FILE = ".bulwarkignore"
MAX_BYTES = 64 * 1024
MAX_PATTERNS = 500


def _regex(pattern: str) -> re.Pattern[str]:
    anchored = "/" in pattern.rstrip("/")
    directory = pattern.endswith("/")
    body = pattern.strip("/")
    out, i = "", 0
    while i < len(body):
        c = body[i]
        if body.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif body.startswith("**", i):
            out += ".*"
            i += 2
        elif c == "*":
            out += "[^/]*"
            i += 1
        elif c == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(c)
            i += 1
    prefix = "" if anchored else r"(?:.*/)?"
    suffix = r"/.*" if directory else r"(?:/.*)?"
    return re.compile(f"^{prefix}{out}{suffix}$")


class IgnoreRules:
    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self.patterns = [p for p in patterns][:MAX_PATTERNS]
        self._res = [_regex(p) for p in self.patterns]

    @staticmethod
    def parse(text: str) -> IgnoreRules:
        lines = [ln.strip() for ln in text.splitlines()]
        return IgnoreRules(ln for ln in lines if ln and not ln.startswith("#"))

    @staticmethod
    def load(path: Path) -> IgnoreRules:
        """Read an ignore file. A missing file is no rules; an oversized one is an error, not a guess."""
        if not path.is_file():
            return IgnoreRules()
        if path.stat().st_size > MAX_BYTES:
            raise ValueError(f"{path.name} is larger than {MAX_BYTES} bytes")
        return IgnoreRules.parse(path.read_text("utf-8", errors="replace"))

    def matches(self, rel_path: str) -> bool:
        p = rel_path.replace("\\", "/")
        p = p[2:] if p.startswith("./") else p
        return any(r.match(p) for r in self._res)


def apply_ignore(findings: list[Finding], rules: IgnoreRules) -> tuple[list[Finding], int]:
    if not rules.patterns:
        return findings, 0
    kept = [f for f in findings if not rules.matches(f.location.path)]
    return kept, len(findings) - len(kept)
