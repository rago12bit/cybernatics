"""Regenerate core/llm/prompts/fix/fixtures/*.txt from the REAL build_prompt() (plan §21.1).

Run this after a change to `core/llm/prompt.py`'s rendering shape so the promptfoo eval suite's
fixtures stay a faithful example of what production actually sends -- never hand-edit the fixture
files directly, or they silently drift from the real prompt format.

    python3 scripts/gen-promptfoo-fixtures.py
"""

from __future__ import annotations

from pathlib import Path

from core.llm.prompt import CodeContext, build_prompt
from core.models import Category, Finding, Location, Taxonomy
from core.rag.retrieve import RemediationContext

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "core" / "llm" / "prompts" / "fix" / "fixtures"

EMPTY_CTX = RemediationContext(basis="none")


def _sqli() -> tuple[Finding, CodeContext | None]:
    f = Finding(
        "f1",
        "SQL injection",
        "String-built SQL query.",
        Location("app/users.py", 10, 11, "x"),
        Taxonomy(Category.SAST, cwe=("CWE-89",), owasp_top_10_2021=("A03:2021",)),
    )
    code = CodeContext(
        'def get_user(uid):\n    return db.execute("SELECT * FROM users WHERE id=" + uid)', 10
    )
    return f, code


def _vulnerable_dependency() -> tuple[Finding, CodeContext | None]:
    f = Finding(
        "f2",
        "Known-vulnerable dependency",
        "flask 2.2.0 has a known CVE.",
        Location("requirements.txt", 3, 3, "flask==2.2.0"),
        Taxonomy(Category.SCA, cve=("CVE-2023-30861",)),
    )
    return f, None


def _leaked_secret() -> tuple[Finding, CodeContext | None]:
    f = Finding(
        "f3",
        "Hardcoded AWS access key",
        "An AWS access key is committed to source.",
        Location("infra/deploy.sh", 4, 4, "[redacted upstream]"),
        Taxonomy(Category.SECRETS),
    )
    code = CodeContext('export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"', 4)
    return f, code


CASES: dict[str, tuple[Finding, CodeContext | None]] = {
    "sql_injection": _sqli(),
    "vulnerable_dependency": _vulnerable_dependency(),
    "leaked_secret": _leaked_secret(),
}


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, (finding, code) in CASES.items():
        prompt = build_prompt(finding, EMPTY_CTX, code)
        (FIXTURES / f"{name}.txt").write_text(prompt.user)
        # The finding's own path is set directly as each test case's `path` var in
        # promptfooconfig.yaml (read by promptfoo_assert.py) -- not written out here, since nothing
        # loads a `.path` file back in.
        print(f"wrote {name}.txt ({len(prompt.user)} chars, path={finding.location.path})")


if __name__ == "__main__":
    main()
