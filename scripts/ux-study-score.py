#!/usr/bin/env python3
"""Score the third usability study (docs/ux-study-v3-protocol.md) into docs/ux-study.md.

Reads docs/ux-study-data/sessions.csv (one row per participant per task) and sus.csv (one row per
participant), checks them, and rewrites the generated section of docs/ux-study.md -- the part between
its `<!-- results:begin -->` and `<!-- results:end -->` markers. Quotes and the problems found are
written there by hand, outside the markers.

    python scripts/ux-study-score.py            # write docs/ux-study.md
    python scripts/ux-study-score.py --check    # validate the data only
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs/ux-study-data"
OUT = ROOT / "docs/ux-study.md"
BEGIN, END = "<!-- results:begin -->", "<!-- results:end -->"

#: Plan §53.1's targets, in seconds; J9's is per finding (five findings).
TASKS = {
    "J6": ("Import a report", 60, 1),
    "J7": ("New-CVE morning", 300, 1),
    "J8": ("Risk acceptance (both people)", 2 * 180, 1),
    "J9": ("Pen test, five findings", 180, 5),
    "J10": ("Monthly report", 300, 1),
}
SUCCESS = ("yes", "partial", "no")


class DataError(ValueError):
    pass


def sus_score(answers: list[int]) -> float:
    """Brooke's System Usability Scale: odd items score answer - 1, even items 5 - answer; the sum
    times 2.5 is 0-100."""
    if len(answers) != 10 or any(a not in (1, 2, 3, 4, 5) for a in answers):
        raise DataError(f"SUS needs ten answers from 1 to 5, got {answers}")
    return 2.5 * sum((a - 1) if i % 2 == 0 else (5 - a) for i, a in enumerate(answers))


@dataclass(frozen=True)
class Row:
    participant: str
    role: str
    task: str
    success: str
    seconds: int
    confidence: int | None
    hint: bool


def read_sessions(path: Path) -> list[Row]:
    rows = []
    with path.open(newline="") as f:
        for n, r in enumerate(csv.DictReader(f), start=2):
            task, success = r["task"].strip().upper(), r["success"].strip().lower()
            if task not in TASKS:
                raise DataError(f"{path.name}:{n}: unknown task {r['task']!r}")
            if success not in SUCCESS:
                raise DataError(f"{path.name}:{n}: success must be one of {SUCCESS}")
            conf = r.get("confidence", "").strip()
            rows.append(Row(
                r["participant"].strip(), r["role"].strip(), task, success, int(r["seconds"]),
                int(conf) if conf else None, r.get("hint", "").strip().lower() in ("yes", "true", "1"),
            ))  # fmt: skip
    return rows


def read_sus(path: Path) -> dict[str, float]:
    with path.open(newline="") as f:
        return {
            r["participant"].strip(): sus_score([int(r[f"q{i}"]) for i in range(1, 11)])
            for r in csv.DictReader(f)
        }


def render(rows: list[Row], sus: dict[str, float]) -> str:
    people = sorted({r.participant for r in rows} | set(sus))
    if not people:
        return "_No sessions recorded yet._\n"
    missing = [p for p in people if p not in sus]
    if missing:
        raise DataError(f"no SUS answers for {', '.join(missing)}")
    roles = {r.participant: r.role for r in rows}
    out = ["### System Usability Scale", "", "| Participant | Role | SUS |", "|---|---|---|"]
    out += [f"| {p} | {roles.get(p, '')} | {sus[p]:.1f} |" for p in people]
    scores = list(sus.values())
    out += ["", f"Mean **{statistics.mean(scores):.1f}**, median {statistics.median(scores):.1f}, "
            f"range {min(scores):.1f}-{max(scores):.1f}, n = {len(scores)}. Five people is a small "
            "sample: read the range with the mean.", ""]  # fmt: skip
    out += ["### Tasks", "",
            "| Task | Succeeded | Partly | Failed | Hints | Median time | Plan target | Within target | Median confidence |",
            "|---|---|---|---|---|---|---|---|---|"]  # fmt: skip
    for task, (name, target, per) in TASKS.items():
        t = [r for r in rows if r.task == task]
        if not t:
            out.append(
                f"| {task} {name} | -- | -- | -- | -- | -- | {_target(target, per)} | -- | -- |"
            )
            continue
        times = [r.seconds / per for r in t]
        within = sum(1 for r in t if r.success == "yes" and r.seconds / per <= target)
        confs = [r.confidence for r in t if r.confidence is not None]
        out.append(
            f"| {task} {name} | {_n(t, 'yes')} | {_n(t, 'partial')} | {_n(t, 'no')} | "
            f"{sum(r.hint for r in t)} | {_dur(statistics.median(times))}{' per finding' if per > 1 else ''} | "
            f"{_target(target, per)} | {within} of {len(t)} | "
            f"{statistics.median(confs) if confs else '--'} |"
        )
    out += ["", "Within target counts a participant only when they succeeded without help and in "
            "time; confidence is their own 1-5 rating after the task."]  # fmt: skip
    return "\n".join(out) + "\n"


def _n(rows: list[Row], success: str) -> int:
    return sum(1 for r in rows if r.success == success)


def _dur(s: float) -> str:
    return f"{int(s // 60)} min {int(s % 60):02d} s"


def _target(seconds: int, per: int) -> str:
    return f"under {seconds // 60} min" + (" per finding" if per > 1 else "")


def write(text: str) -> None:
    doc = OUT.read_text()
    if BEGIN not in doc or END not in doc:
        raise DataError(f"{OUT.name} has lost its results markers")
    head, rest = doc.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    OUT.write_text(f"{head}{BEGIN}\n{text}{END}{tail}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate the data, write nothing")
    args = ap.parse_args()
    try:
        text = render(read_sessions(DATA / "sessions.csv"), read_sus(DATA / "sus.csv"))
        if not args.check:
            write(text)
    except (DataError, KeyError, ValueError) as exc:
        sys.exit(f"error: {exc}")
    print("ok" if args.check else f"wrote {OUT}")


if __name__ == "__main__":
    main()
