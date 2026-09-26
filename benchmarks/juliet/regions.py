"""Which lines of a Juliet Java test file are vulnerable and which are safe?

Juliet's ground truth is in its naming, not a CSV. By convention:

    * a method whose name starts with `bad` (bad, badSink, badSource) is the vulnerable flow;
    * a method whose name starts with `good` (good, goodG2B, goodB2GSink, ...) is the safe flow;
    * in the multi-file variants, a file named `..._bad.java` is entirely vulnerable and `..._good*.java` entirely
      safe; `_base` files (abstract helpers) carry no verdict.

A tool is scored on whether it reports the weakness INSIDE a vulnerable region (a hit) or inside a safe one (a false
alarm). Comments and string literals are blanked before brace matching so a `{` in either cannot end a method early.
"""

from __future__ import annotations

import re

_DECL = re.compile(
    r"^\s*(?:public|private|protected)\s+(?:static\s+)?(?:final\s+)?[\w<>\[\],. ?]+?\s+((?:bad|good)\w*)\s*\("
)
_BAD_FILE = re.compile(r"_bad\.java$")
_GOOD_FILE = re.compile(r"_good\w*\.java$")
_BASE_FILE = re.compile(r"_base\.java$")


def blank_comments_and_strings(src: str) -> str:
    """The source with comment and literal contents replaced by spaces; newlines (so line numbers) are kept."""
    out, i, n = [], 0, len(src)
    while i < n:
        c, two = src[i], src[i : i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(c + "".join("\n" if ch == "\n" else " " for ch in src[i + 1 : j - 1]) + c)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def extract_regions(source: str, filename: str) -> dict[str, list[tuple[int, int]]]:
    """{"bad": [(start, end), ...], "good": [...]} with 1-based inclusive line ranges."""
    total = source.count("\n") + 1
    if _BASE_FILE.search(filename):
        return {"bad": [], "good": []}
    if _BAD_FILE.search(filename):
        return {"bad": [(1, total)], "good": []}
    if _GOOD_FILE.search(filename):
        return {"bad": [], "good": [(1, total)]}
    lines = blank_comments_and_strings(source).split("\n")
    regions: dict[str, list[tuple[int, int]]] = {"bad": [], "good": []}
    i = 0
    while i < len(lines):
        m = _DECL.match(lines[i])
        if not m:
            i += 1
            continue
        kind = "bad" if m.group(1).startswith("bad") else "good"
        depth, seen_open, j = 0, False, i
        while j < len(lines) and j < i + 6 + 4000:
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    seen_open = True
                elif ch == "}":
                    depth -= 1
            if seen_open and depth <= 0:
                break
            if (
                not seen_open and j > i + 5
            ):  # no body found near the declaration: not a method definition
                break
            j += 1
        if seen_open and depth <= 0:
            regions[kind].append((i + 1, j + 1))
            i = j + 1
        else:
            i += 1
    return regions


def region_of(line: int, end: int, regions: dict[str, list[tuple[int, int]]]) -> str | None:
    """ "bad" or "good" if the line range lies in such a region (a finding is judged by where it STARTS)."""
    for kind in ("bad", "good"):
        for s, e in regions[kind]:
            if s <= line <= e:
                return kind
    return None
