"""The usability study scorer (Week 74, docs/ux-study-v3-protocol.md): SUS scored as Brooke defines
it, task times against the plan's targets, bad data refused, and only the generated section of
docs/ux-study.md rewritten. Synthetic rows in a temporary folder -- never the real data files."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("ux_score", ROOT / "scripts/ux-study-score.py")
assert _spec is not None and _spec.loader is not None
score = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = score  # dataclasses look their module up there
_spec.loader.exec_module(score)


def test_sus_is_scored_as_brooke_defines_it() -> None:
    assert score.sus_score([3] * 10) == 50.0  # neutral throughout
    assert score.sus_score([5, 1] * 5) == 100.0  # agree with the odd items, disagree with the even
    assert score.sus_score([1, 5] * 5) == 0.0
    assert score.sus_score([4, 2, 4, 2, 4, 2, 4, 2, 4, 2]) == 75.0
    for bad in ([3] * 9, [0] + [3] * 9, [6] + [3] * 9):
        with pytest.raises(score.DataError):
            score.sus_score(bad)


def _files(tmp: Path, sessions: str, sus: str) -> tuple[Path, Path]:
    (tmp / "sessions.csv").write_text(
        "participant,role,task,success,seconds,confidence,hint,notes\n" + sessions
    )
    (tmp / "sus.csv").write_text("participant,q1,q2,q3,q4,q5,q6,q7,q8,q9,q10\n" + sus)
    return tmp / "sessions.csv", tmp / "sus.csv"


def test_tasks_are_compared_with_the_plan_per_finding_for_j9(tmp_path: Path) -> None:
    s, u = _files(
        tmp_path,
        "P1,pen tester,J6,yes,45,5,,\n"
        "P2,lead,J6,yes,90,4,,slow to find Import\n"
        "P1,pen tester,J9,yes,600,4,,\n"  # 2 min per finding: within 3
        "P2,lead,J9,partial,1200,2,yes,needed the hint\n",
        "P1,5,1,5,1,5,1,5,1,5,1\nP2,3,3,3,3,3,3,3,3,3,3\n",
    )
    text = score.render(score.read_sessions(s), score.read_sus(u))
    assert "| P1 | pen tester | 100.0 |" in text and "| P2 | lead | 50.0 |" in text
    assert "Mean **75.0**, median 75.0, range 50.0-100.0, n = 2" in text
    j6 = next(line for line in text.splitlines() if line.startswith("| J6"))
    assert "| 2 | 0 | 0 | 0 |" in j6 and "under 1 min" in j6 and "1 of 2" in j6  # P2 took 90 s
    j9 = next(line for line in text.splitlines() if line.startswith("| J9"))
    assert "per finding" in j9 and "1 of 2" in j9  # P2 partial and over time
    assert "| J7 New-CVE morning | -- |" in text  # nobody ran it: said, not invented


@pytest.mark.parametrize(
    ("sessions", "sus", "words"),
    [
        ("P1,lead,J11,yes,10,5,,\n", "P1,3,3,3,3,3,3,3,3,3,3\n", "unknown task"),
        ("P1,lead,J6,maybe,10,5,,\n", "P1,3,3,3,3,3,3,3,3,3,3\n", "success must be"),
        ("P1,lead,J6,yes,10,5,,\n", "", "no SUS answers for P1"),
    ],
)
def test_bad_data_is_refused(tmp_path: Path, sessions: str, sus: str, words: str) -> None:
    s, u = _files(tmp_path, sessions, sus)
    with pytest.raises(score.DataError, match=words):
        score.render(score.read_sessions(s), score.read_sus(u))


def test_only_the_generated_section_is_rewritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    doc = tmp_path / "ux-study.md"
    doc.write_text(f"intro\n{score.BEGIN}\nold\n{score.END}\nquotes written by hand\n")
    monkeypatch.setattr(score, "OUT", doc)
    score.write("new table\n")
    assert (
        doc.read_text() == f"intro\n{score.BEGIN}\nnew table\n{score.END}\nquotes written by hand\n"
    )


def test_the_page_matches_the_recorded_sessions() -> None:
    """No number on docs/ux-study.md is a participant's unless a session was recorded: with no rows
    the page says so, and with rows it holds what the scorer makes of them (rerun it)."""
    data = ROOT / "docs/ux-study-data"
    rows = score.read_sessions(data / "sessions.csv")
    page = (ROOT / "docs/ux-study.md").read_text()
    if not rows:
        assert "_No sessions recorded yet._" in page
    else:
        assert score.render(rows, score.read_sus(data / "sus.csv")) in page, (
            "run scripts/ux-study-score.py"
        )
