"""Regenerate core/llm/prompts/hypotheses/fixtures/*.txt from the REAL build_prompt() (plan §21.4).

Run this after a change to `core/hypotheses/prompt.py`'s rendering shape -- never hand-edit the
fixture files directly, or they silently drift from the real prompt format.

    python3 scripts/gen-hypotheses-fixtures.py
"""

from __future__ import annotations

from pathlib import Path

from core.codeintel.models import Entrypoint
from core.hypotheses.facts import Candidate
from core.hypotheses.prompt import build_prompt

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "core" / "llm" / "prompts" / "hypotheses" / "fixtures"


def _missing_admin_check() -> tuple[Candidate, str]:
    route = Entrypoint("app.py:delete_user:20", "flask", "DELETE", "/users/<id>")
    sibling = Entrypoint(
        "app.py:list_users:10", "flask", "GET", "/users", auth_markers=("login_required",)
    )
    candidate = Candidate(route, "app.py", 20, (sibling,))
    code = "def delete_user(id):\n    db.delete(User, id)\n    return '', 204"
    return candidate, code


def _plausibly_public_health_check() -> tuple[Candidate, str]:
    route = Entrypoint("app.py:health:5", "flask", "GET", "/health")
    sibling = Entrypoint(
        "app.py:list_users:10", "flask", "GET", "/users", auth_markers=("login_required",)
    )
    candidate = Candidate(route, "app.py", 5, (sibling,))
    code = "def health():\n    return {'status': 'ok'}"
    return candidate, code


CASES = {
    "missing_admin_check": _missing_admin_check(),
    "plausibly_public_health_check": _plausibly_public_health_check(),
}


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, (candidate, code) in CASES.items():
        prompt = build_prompt(candidate, code)
        (FIXTURES / f"{name}.txt").write_text(prompt.user)
        print(f"wrote {name}.txt")


if __name__ == "__main__":
    main()
