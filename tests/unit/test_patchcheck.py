from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from core.llm.patchcheck import apply_to, check_patch
from core.llm.prompt import CodeContext
from core.llm.service import suggest
from tests.unit.test_llm import PATH, FakeModel, finding, kb, reply  # noqa: F401 - kb is a fixture

SRC = "\n".join(
    [
        "import sqlite3",
        "",
        "def get(uid):",
        "    db = sqlite3.connect('x.db')",
        "    return db.execute('SELECT * FROM t WHERE id=' + uid)",
        "",
        "def other():",
        "    return 1",
    ]
)
CODE = CodeContext(SRC, 1)
GOOD = (
    f"--- a/{PATH}\n+++ b/{PATH}\n@@ -4,2 +4,2 @@\n     db = sqlite3.connect('x.db')\n"
    "-    return db.execute('SELECT * FROM t WHERE id=' + uid)\n"
    "+    return db.execute('SELECT * FROM t WHERE id=?', (uid,))\n"
)


def with_header(start: int, body: str, old_n: int = 2, new_n: int = 2) -> str:
    return f"--- a/{PATH}\n+++ b/{PATH}\n@@ -{start},{old_n} +{start},{new_n} @@\n{body}"


HDR = re.compile(r"^@@ -(\d+),(\d+) \+(\d+),(\d+) @@", re.M)


def balanced(patch: str) -> bool:
    """Every hunk has as many leading as trailing context lines: nothing anchors it to a file edge."""
    for body in re.split(r"^@@.*$", patch, flags=re.M)[1:]:
        lines = [ln for ln in body.split("\n") if ln]
        lead = next((i for i, ln in enumerate(lines) if ln[0] != " "), len(lines))
        trail = next((i for i, ln in enumerate(reversed(lines)) if ln[0] != " "), len(lines))
        if lead != trail:
            return False
    return True


def test_a_patch_that_matches_the_code_is_verified_and_makes_the_intended_change() -> None:
    c = check_patch(GOOD, CODE)
    assert c.status == "verified" and balanced(c.patch)
    after = apply_to(CODE, c)
    assert after and after[4] == "    return db.execute('SELECT * FROM t WHERE id=?', (uid,))"
    assert (
        after[:4] == SRC.splitlines()[:4] and after[5:] == SRC.splitlines()[5:] and len(after) == 8
    )


def test_wrong_line_numbers_are_corrected_when_the_lines_are_found_elsewhere() -> None:
    wrong = GOOD.replace("@@ -4,2 +4,2 @@", "@@ -40,2 +40,2 @@")
    c = check_patch(wrong, CODE)
    assert c.status == "verified" and "-40," not in c.patch
    assert apply_to(CODE, c) == apply_to(CODE, check_patch(GOOD, CODE))


def test_a_patch_about_lines_that_are_not_there_is_rejected() -> None:
    bad = with_header(
        4, "     db = sqlite3.connect('y.db')\n-    return other(uid)\n+    return safe(uid)\n"
    )
    c = check_patch(bad, CODE)
    assert c.status == "rejected" and "does not match" in c.detail


def test_a_no_op_patch_is_rejected() -> None:
    same = with_header(
        4,
        "     db = sqlite3.connect('x.db')\n-    return db.execute('SELECT * FROM t WHERE id=' + uid)\n+    return db.execute('SELECT * FROM t WHERE id=' + uid)\n",
    )
    assert check_patch(same, CODE).status == "rejected"


def test_a_hunk_outside_the_snippet_is_unverified_not_rejected() -> None:
    far = with_header(500, " context\n-old\n+new\n", 2, 2)
    assert check_patch(far, CODE).status == "unverified"
    assert check_patch(GOOD, None).status == "unverified"
    assert check_patch(GOOD, CodeContext("   \n", 1)).status == "unverified"


def test_trailing_whitespace_and_crlf_do_not_defeat_matching() -> None:
    crlf = CodeContext(SRC.replace("\n", "  \r\n"), 1)
    assert check_patch(GOOD, crlf).status == "verified"


def test_several_hunks_get_consistent_new_line_numbers_and_do_not_overlap() -> None:
    patch = (
        f"--- a/{PATH}\n+++ b/{PATH}\n@@ -1,1 +1,2 @@\n import sqlite3\n+import os\n"
        "@@ -7,2 +99,2 @@\n def other():\n-    return 1\n+    return 2\n"
    )
    c = check_patch(patch, CODE)
    assert c.status == "verified" and balanced(c.patch)
    heads = [tuple(map(int, m.groups())) for m in HDR.finditer(c.patch)]
    assert len(heads) == 2
    (o1, n1, p1, q1), (o2, n2, p2, q2) = heads
    assert o1 + n1 <= o2, "hunks must not overlap in the old file"
    assert p1 == o1 and p2 == o2 + (q1 - n1), "new start = old start + lines added so far"
    after = apply_to(CODE, c)
    assert after and after[1] == "import os" and after[-1] == "    return 2"


def test_an_ambiguous_block_prefers_the_stated_position() -> None:
    dup = CodeContext("a = 1\nb = 2\nx = 0\na = 1\nb = 2\n", 1)
    patch = with_header(4, " a = 1\n-b = 2\n+b = 3\n")
    c = check_patch(patch, dup)
    after = apply_to(dup, c)
    assert c.status == "verified" and after == [
        "a = 1",
        "b = 2",
        "x = 0",
        "a = 1",
        "b = 3",
    ]  # the second copy changed


def test_pure_insertions_and_partial_verification() -> None:
    ins = f"--- a/{PATH}\n+++ b/{PATH}\n@@ -3,0 +3,1 @@\n+# note\n"
    assert check_patch(ins, CODE).status in {"verified", "unverified"}
    mixed = (
        f"--- a/{PATH}\n+++ b/{PATH}\n@@ -1,1 +1,1 @@\n-import sqlite3\n+import sqlite3, os\n"
        "@@ -900,1 +900,1 @@\n-nothing\n+something\n"
    )
    assert check_patch(mixed, CODE).status == "unverified"


@pytest.mark.skipif(shutil.which("patch") is None, reason="needs the `patch` tool")
def test_a_verified_patch_really_applies_with_the_patch_tool(tmp_path: Path) -> None:
    """The ground truth for 'applies cleanly': the real `patch` program, including after line-number correction."""
    for text in (GOOD, GOOD.replace("@@ -4,2 +4,2 @@", "@@ -40,2 +40,2 @@")):
        (tmp_path / "app").mkdir(exist_ok=True)
        target = tmp_path / PATH
        target.write_text(SRC + "\n")
        shown = check_patch(text, CODE).patch
        (tmp_path / "p.diff").write_text(shown)
        r = subprocess.run(
            ["patch", "-p1", "--dry-run", "-i", "p.diff"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        subprocess.run(
            ["patch", "-p1", "-i", "p.diff"], cwd=tmp_path, capture_output=True, check=True
        )
        assert "id=?" in target.read_text()


@pytest.mark.skipif(shutil.which("patch") is None, reason="needs the `patch` tool")
def test_a_multi_hunk_patch_and_minimal_model_style_hunks_apply_with_the_patch_tool(
    tmp_path: Path,
) -> None:
    cases = [
        (
            f"--- a/{PATH}\n+++ b/{PATH}\n@@ -1,1 +1,2 @@\n import sqlite3\n+import os\n@@ -7,2 +99,2 @@\n def other():\n-    return 1\n+    return 2\n"
        ),
        (
            f"--- a/{PATH}\n+++ b/{PATH}\n@@ -5,1 +5,1 @@\n-    return db.execute('SELECT * FROM t WHERE id=' + uid)\n+    return db.execute('SELECT * FROM t WHERE id=?', (uid,))\n"
        ),  # no context at all
        (
            f"--- a/{PATH}\n+++ b/{PATH}\n@@ -3,3 +3,3 @@\n def get(uid):\n     db = sqlite3.connect('x.db')\n-    return db.execute('SELECT * FROM t WHERE id=' + uid)\n+    return None\n"
        ),  # leading only
    ]
    for text in cases:
        (tmp_path / "app").mkdir(exist_ok=True)
        (tmp_path / PATH).write_text(SRC + "\n")
        c = check_patch(text, CODE)
        assert c.status == "verified" and balanced(c.patch), text
        (tmp_path / "p.diff").write_text(c.patch)
        r = subprocess.run(
            ["patch", "-p1", "--dry-run", "-i", "p.diff"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 0, c.patch + r.stdout
        subprocess.run(
            ["patch", "-p1", "-i", "p.diff"], cwd=tmp_path, capture_output=True, check=True
        )
        assert (tmp_path / PATH).read_text().splitlines() == apply_to(
            CODE, c
        )  # the tool and our model agree


# ---- inside the service ---------------------------------------------------------------------------------


def test_service_keeps_a_verified_patch_and_reports_it(kb) -> None:  # type: ignore[no-untyped-def]
    f = finding()
    r = suggest(
        f,
        kb,
        FakeModel(reply(suggested_patch=GOOD.replace("@@ -4,2 +4,2 @@", "@@ -9,2 +9,2 @@"))),
        CODE,
    )
    assert r.source == "ai" and r.patch_status == "verified" and r.suggested_patch
    again = check_patch(
        r.suggested_patch, CODE
    )  # the patch we show is exactly what applies to the code
    assert again.status == "verified" and "id=?" in (apply_to(CODE, again) or [""])[4]


def test_service_drops_a_patch_that_does_not_match_the_code_but_keeps_the_explanation(kb) -> None:  # type: ignore[no-untyped-def]
    bad = with_header(
        4, "     db = sqlite3.connect('y.db')\n-    return other(uid)\n+    return safe(uid)\n"
    )
    r = suggest(finding(), kb, FakeModel(reply(suggested_patch=bad)), CODE)
    assert r.source == "ai" and r.suggested_patch is None and r.patch_status is None
    assert r.explanation and any(
        "patch was discarded" in w and "does not match" in w for w in r.warnings
    )


def test_service_marks_a_patch_outside_the_snippet_unverified(kb) -> None:  # type: ignore[no-untyped-def]
    far = with_header(500, " context\n-old\n+new\n")
    r = suggest(finding(), kb, FakeModel(reply(suggested_patch=far)), CODE)
    assert (
        r.suggested_patch
        and r.patch_status == "unverified"
        and any("could not be fully checked" in w for w in r.warnings)
    )
