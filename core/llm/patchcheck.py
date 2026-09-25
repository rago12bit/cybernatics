"""Does a suggested patch actually apply to the code the model was shown?

The contract (contract.py) checks a patch's SHAPE: one file, well-formed hunks, sane counts. That says nothing
about whether its context and removed lines exist in the code. Models are good at plausible-looking diffs and
bad at line numbers, so this module checks the CONTENT against the code we sent:

  verified    every hunk's context and removed lines match the code exactly. Line numbers are corrected if the
              block is found elsewhere in the snippet, and context is balanced, so the patch then really applies
              with `patch` or `git apply` (tested against the real tools)
  unverified  the hunk reaches outside the snippet we have, so it cannot be judged either way
  rejected    a hunk does not match the code, or the patch changes nothing: it must not be shown

This is a necessary check, not a sufficient one: a patch that applies cleanly can still be the wrong fix.
Correctness is judged by a person (docs/evaluation-remediation.md).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Literal

from core.llm.prompt import CodeContext

Status = Literal["verified", "unverified", "rejected"]
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")


@dataclass(frozen=True)
class PatchCheck:
    status: Status
    detail: str
    patch: str  # the patch to show: identical unless line numbers were corrected


@dataclass
class _Hunk:
    old_start: int
    section: str
    lines: list[str]  # raw hunk lines including their leading ' ', '+', '-' or '\\'

    def old_block(self) -> list[str]:
        return [ln[1:] for ln in self.lines if ln[:1] in (" ", "-")]

    def added(self) -> list[str]:
        return [ln[1:] for ln in self.lines if ln[:1] == "+"]

    def removed(self) -> list[str]:
        return [ln[1:] for ln in self.lines if ln[:1] == "-"]


def _parse(patch: str) -> tuple[list[str], list[_Hunk]]:
    lines = patch.splitlines()
    head, hunks = lines[:2], []
    for ln in lines[2:]:
        m = _HUNK.match(ln)
        if m:
            hunks.append(_Hunk(int(m.group(1)), m.group(5), []))
        elif hunks:
            hunks[-1].lines.append(
                ln if ln else " "
            )  # a blank context line whose space was stripped
    return head, hunks


def _norm(s: str) -> str:
    return s.rstrip()  # trailing whitespace and CR differences do not make a patch inapplicable


def _find(block: list[str], src: list[str], near: int) -> int | None:
    """0-based index where `block` occurs in `src`; when several, the one nearest `near`; None if absent."""
    n = len(block)
    hits = [
        i
        for i in range(len(src) - n + 1)
        if all(_norm(src[i + j]) == _norm(block[j]) for j in range(n))
    ]
    return min(hits, key=lambda i: abs(i - near)) if hits else None


CONTEXT = 3  # lines of context either side, as `diff -u` writes them


def _balance_context(
    hunks: list[_Hunk], starts: list[int], src: list[str], first: int
) -> tuple[list[_Hunk], list[int]]:
    """Give every hunk the same amount of context before and after, taken from the code we have.

    `patch` and `git apply` treat a hunk with less trailing than leading context as anchored to the END of the
    file (and the reverse for the start), so a minimal hunk a model wrote in the middle of a file fails to
    apply even though its lines are right. Balanced context removes the anchoring. Context is only ever taken
    from the snippet, never invented, and expansions never reach into a neighbouring hunk.
    """
    out: list[_Hunk] = []
    new_starts: list[int] = []
    prev_end = 0  # 0-based index just past the previous hunk's last line
    for n, (h, start) in enumerate(zip(hunks, starts, strict=True)):
        block = h.old_block()
        if not block:
            out.append(h)
            new_starts.append(start)
            prev_end = max(prev_end, start - first)
            continue
        idx = start - first
        lead = next((k for k, ln in enumerate(h.lines) if ln[:1] != " "), len(h.lines))
        trail = next((k for k, ln in enumerate(reversed(h.lines)) if ln[:1] != " "), len(h.lines))
        end = idx + len(block)
        nxt = starts[n + 1] - first if n + 1 < len(starts) else len(src)
        room_before = max(0, idx - prev_end)
        room_after = max(0, (nxt - end) // 2 if n + 1 < len(starts) else len(src) - end)
        k = min(CONTEXT, lead + room_before, trail + room_after)
        lines = list(h.lines)
        if k > lead:
            lines = [" " + t for t in src[idx - (k - lead) : idx]] + lines
            idx -= k - lead
        elif k < lead:
            lines = lines[lead - k :]
            idx += lead - k
        end = idx + len(_Hunk(0, "", lines).old_block())
        if k > trail:
            lines = lines + [" " + t for t in src[end : end + (k - trail)]]
        elif k < trail:
            lines = lines[: len(lines) - (trail - k)]
        out.append(_Hunk(first + idx, h.section, lines))
        new_starts.append(first + idx)
        prev_end = idx + len(_Hunk(0, "", lines).old_block())
    return out, new_starts


def _render(head: list[str], hunks: list[_Hunk], starts: list[int]) -> str:
    out = list(head)
    delta = 0
    for h, old_start in zip(hunks, starts, strict=True):
        old_n = len(h.old_block())
        new_n = old_n - len(h.removed()) + len(h.added())
        out.append(f"@@ -{old_start},{old_n} +{old_start + delta},{new_n} @@{h.section}")
        out.extend(h.lines)
        delta += new_n - old_n
    return "\n".join(out) + "\n"


def check_patch(patch: str, code: CodeContext | None) -> PatchCheck:
    """`patch` has already passed contract.validate_patch (well-formed, right file)."""
    head, hunks = _parse(patch)
    if not hunks:
        return PatchCheck("rejected", "the patch has no hunks", patch)
    if Counter(x for h in hunks for x in h.added()) == Counter(
        x for h in hunks for x in h.removed()
    ):
        return PatchCheck(
            "rejected", "the patch changes nothing (added and removed lines are identical)", patch
        )
    if code is None or not code.text.strip():
        return PatchCheck("unverified", "there is no code to check the patch against", patch)

    src = code.text.splitlines()
    first = code.first_line
    starts: list[int] = []
    verified = 0
    for i, h in enumerate(hunks, 1):
        block = h.old_block()
        if not block:  # a pure insertion at a line: nothing to compare against
            starts.append(h.old_start)
            continue
        idx = h.old_start - first
        exact = (
            0 <= idx
            and idx + len(block) <= len(src)
            and all(_norm(src[idx + j]) == _norm(block[j]) for j in range(len(block)))
        )
        if exact:
            starts.append(h.old_start)
            verified += 1
            continue
        found = _find(block, src, idx)
        if found is not None:
            starts.append(first + found)  # right lines, wrong numbers: correct them
            verified += 1
            continue
        stated_inside = (
            first <= h.old_start and h.old_start + len(block) - 1 <= first + len(src) - 1
        )
        if stated_inside:
            return PatchCheck(
                "rejected",
                f"hunk {i} does not match the code at lines {h.old_start}-{h.old_start + len(block) - 1}",
                patch,
            )
        starts.append(h.old_start)  # reaches outside the snippet: we cannot tell
    if verified == len([h for h in hunks if h.old_block()]):
        hunks, starts = _balance_context(hunks, starts, src, first)
        return PatchCheck("verified", "every hunk matches the code", _render(head, hunks, starts))
    return PatchCheck(
        "unverified",
        "part of the patch is outside the code snippet we have, so it could not be checked",
        patch,
    )


def apply_to(code: CodeContext, check: PatchCheck) -> list[str] | None:
    """The snippet after applying a VERIFIED patch (for tests and future syntax checks); None otherwise."""
    if check.status != "verified":
        return None
    _, hunks = _parse(check.patch)
    src = code.text.splitlines()
    for h in reversed(hunks):
        old_n = len(h.old_block())
        idx = h.old_start - code.first_line
        new = [ln[1:] for ln in h.lines if ln[:1] in (" ", "+")]
        src[idx : idx + old_n] = new
    return src
