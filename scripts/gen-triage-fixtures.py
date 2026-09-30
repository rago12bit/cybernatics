"""Regenerate core/llm/prompts/triage/fixtures/*.txt from the REAL build_prompt() (plan §21.3).

Run this after a change to `core/triage_assistant/prompt.py`'s rendering shape -- never hand-edit the
fixture files directly, or they silently drift from the real prompt format.

    python3 scripts/gen-triage-fixtures.py
"""

from __future__ import annotations

import json
from pathlib import Path

from core.llm.prompt import CodeContext
from core.models import Category, Finding, Location, TaintPathStep, Taxonomy
from core.triage_assistant.prompt import build_prompt

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "core" / "llm" / "prompts" / "triage" / "fixtures"


def _sqli_with_full_path() -> tuple[Finding, CodeContext | None]:
    f = Finding(
        "f1",
        "SQL injection",
        "String-built SQL query.",
        Location("app/users.py", 10, 11, "x"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
        taint_path=(
            TaintPathStep("app/routes.py", 5, "request.args['id'] enters get_user()"),
            TaintPathStep(
                "app/users.py", 10, "cursor.execute('SELECT * FROM users WHERE id=' + uid)",
                is_sink=True,
            ),  # fmt: skip
        ),
    )
    code = CodeContext(
        'def get_user(uid):\n    return db.execute("SELECT * FROM users WHERE id=" + uid)', 10
    )
    return f, code


def _sanitized_input() -> tuple[Finding, CodeContext | None]:
    f = Finding(
        "f2",
        "Possible SQL injection",
        "Parameterized query flagged by a broad rule.",
        Location("app/users.py", 20, 21, "x"),
        Taxonomy(Category.SAST, cwe=("CWE-89",)),
        taint_path=(
            TaintPathStep("app/routes.py", 5, "request.args['id'] enters get_user_safe()"),
            TaintPathStep(
                "app/users.py", 20, "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
                is_sink=True,
            ),  # fmt: skip
        ),
    )
    code = CodeContext(
        'def get_user_safe(uid):\n    return db.execute("SELECT * FROM users WHERE id=%s", (uid,))',
        20,
    )
    return f, code


def _no_taint_path() -> tuple[Finding, CodeContext | None]:
    f = Finding(
        "f3",
        "Weak hash algorithm",
        "MD5 used for password hashing.",
        Location("app/auth.py", 30, 30, "x"),
        Taxonomy(Category.SAST, cwe=("CWE-327",)),
    )
    code = CodeContext(
        "def hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()", 30
    )
    return f, code


CASES: dict[str, tuple[Finding, CodeContext | None]] = {
    "sqli_full_path": _sqli_with_full_path(),
    "sanitized_input": _sanitized_input(),
    "no_taint_path": _no_taint_path(),
}


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    meta = {}
    for name, (finding, code) in CASES.items():
        prompt = build_prompt(finding, code)
        (FIXTURES / f"{name}.txt").write_text(prompt.user)
        meta[name] = {"first_line": prompt.first_line, "last_line": prompt.last_line}
        print(f"wrote {name}.txt (lines {prompt.first_line}-{prompt.last_line})")
    (FIXTURES / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")


if __name__ == "__main__":
    main()
