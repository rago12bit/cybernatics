"""Snippet normalization for cross-tool matching (design doc §6.1).

Tools quote code differently: Bandit gives numbered context lines, Semgrep just the matched
expression, and both may include comments or different whitespace. We reduce a snippet to a token
stream with comments removed and identifiers/strings/numbers masked, so the same construct
compares equal regardless of naming or formatting.
"""

from __future__ import annotations

import hashlib
import re

# Placeholders written by our own redaction: they carry no comparable content.
PLACEHOLDER_MARKERS = ("[secret redacted]", "[snippet withheld")

_LINENO = re.compile(r"^\s*\d+(?: |\t)", re.MULTILINE)
_TOKEN = re.compile(
    r"""
    (?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`)
  | (?P<num>\b\d[\d_.xXa-fA-F]*\b)
  | (?P<id>[A-Za-z_$][A-Za-z0-9_$]*)
  | (?P<op>[^\sA-Za-z0-9_$"'`])
    """,
    re.VERBOSE,
)
_COMMENT = re.compile(r"#[^\n]*|//[^\n]*|/\*.*?\*/", re.DOTALL)

# Structure-bearing words stay verbatim; every other identifier becomes ID.
_KEYWORDS = frozenset(
    "def return import from if else elif for while class new func function var let const try "
    "except catch finally with as in is not and or lambda yield await async raise throw None "
    "True False null nil true false this self public private static void int string".split()
)


def is_placeholder(snippet: str) -> bool:
    return any(m in snippet for m in PLACEHOLDER_MARKERS)


def strip_line_numbers(snippet: str) -> str:
    """Remove leading line-number prefixes (Bandit style) only if every non-empty line has one."""
    lines = [ln for ln in snippet.splitlines() if ln.strip()]
    if lines and all(_LINENO.match(ln) for ln in lines):
        return _LINENO.sub("", snippet)
    return snippet


def tokens(snippet: str) -> list[str]:
    text = _COMMENT.sub(" ", strip_line_numbers(snippet))
    out: list[str] = []
    for m in _TOKEN.finditer(text):
        kind = m.lastgroup
        if kind == "str":
            out.append("STR")
        elif kind == "num":
            out.append("NUM")
        elif kind == "id":
            out.append(m.group() if m.group() in _KEYWORDS else "ID")
        else:
            out.append(m.group())
    return out


def snippet_hash(snippet: str) -> str:
    return hashlib.sha256(" ".join(tokens(snippet)).encode()).hexdigest()


def overlap(a: list[str], b: list[str]) -> float:
    """Overlap coefficient of the two token *sets*: |A∩B| / min(|A|,|B|).

    Jaccard punishes one tool quoting more context than another (Bandit shows surrounding lines,
    Semgrep just the match), which is the normal case. Containment does not.
    """
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / min(len(sa), len(sb))
