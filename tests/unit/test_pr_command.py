"""`/fix`'s rules (plan §50): the command, who may give it, what is fixable, the cost, and that
everything Bulwark echoes back from the pull request is shown as text."""

from __future__ import annotations

import re
from typing import Any

import pytest

from core.fixagent import pr_command as cmd


def finding(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "semgrep:x:app.py:3", "title": "SQL injection",
        "taxonomy": {"category": "sast"}, "location": {"path": "app.py", "start_line": 3},
        "scoring": {"normalized_severity": "HIGH", "risk_score": 70},
        "issue": {"id": None, "state": "new"},
    }  # fmt: skip
    base.update(kw)
    return base


@pytest.mark.parametrize(
    ("body", "want"),
    [
        ("/fix", cmd.Command("preview")),
        ("  /fix  \nthanks!", cmd.Command("preview")),
        ("/fix confirm k7m2pq9x", cmd.Command("confirm", "K7M2PQ9X")),
        ("/fix cancel K7M2PQ9X", cmd.Command("cancel", "K7M2PQ9X")),
        ("please /fix", None),  # not the whole line
        ("> /fix", None),  # a quoted reply
        ("hello\n/fix", None),  # only the first line counts
        ("/fixed it", None),
        ("/fix confirm", None),
        ("/fix confirm abc", None),  # too short to be a code
        ("/fix confirm K7M2PQ9X; rm -rf /", None),
        ("/fix now", None),
        ("", None),
    ],
)
def test_only_a_whole_first_line_is_a_command(body: str, want: cmd.Command | None) -> None:
    assert cmd.parse(body) == want


def test_codes_are_unambiguous_to_read_and_random() -> None:
    codes = {cmd.new_code() for _ in range(200)}
    assert len(codes) == 200
    for c in codes:
        assert len(c) == 8 and not set(c) & set("01IO")
        assert cmd.parse(f"/fix confirm {c}") == cmd.Command("confirm", c)


MEMBER = cmd.Commenter("ana", "MEMBER", False)
OPEN = cmd.PullRequest(7, "open", "a" * 40, "acme/widgets", "acme/widgets")


@pytest.mark.parametrize(
    ("commenter", "pr", "rank", "words"),
    [
        (MEMBER, OPEN, 2, None),
        (MEMBER, OPEN, 3, None),
        (cmd.Commenter("ana", "COLLABORATOR", False), OPEN, 2, None),
        (cmd.Commenter("ana", "OWNER", False), OPEN, 2, None),
        (cmd.Commenter("x", "CONTRIBUTOR", False), OPEN, 3, "owner, member or collaborator"),
        (cmd.Commenter("x", "FIRST_TIME_CONTRIBUTOR", False), OPEN, 3, "owner, member"),
        (cmd.Commenter("x", "NONE", False), OPEN, 3, "owner, member"),
        (MEMBER, OPEN, None, "not linked"),
        (MEMBER, OPEN, 1, "Member role"),  # a viewer in Bulwark
        (MEMBER, OPEN, 0, "Member role"),
        (MEMBER, None, 2, "could not read"),
        (MEMBER, cmd.PullRequest(7, "open", "a" * 40, "eve/widgets", "acme/widgets"), 2, "fork"),
        (MEMBER, cmd.PullRequest(7, "open", "a" * 40, None, "acme/widgets"), 2, "fork"),  # deleted
        (MEMBER, cmd.PullRequest(7, "closed", "a" * 40, "acme/widgets", "acme/widgets"), 2, "not open"),
    ],
)  # fmt: skip
def test_who_may_use_it(
    commenter: cmd.Commenter, pr: cmd.PullRequest | None, rank: int | None, words: str | None
) -> None:
    reason = cmd.refusal(commenter, pr, rank)
    if words is None:
        assert reason is None
    else:
        assert reason is not None and words in reason


def test_a_fork_never_passes_even_for_an_admin_owner() -> None:
    fork = cmd.PullRequest(7, "open", "a" * 40, "acme-fork/widgets", "acme/widgets")
    assert "fork" in (cmd.refusal(cmd.Commenter("boss", "OWNER", False), fork, 3) or "")
    # The repository name is compared without case, as GitHub does.
    same = cmd.PullRequest(7, "open", "a" * 40, "Acme/Widgets", "acme/widgets")
    assert cmd.refusal(MEMBER, same, 2) is None


def test_only_new_code_findings_are_fixable_most_severe_first_at_most_five() -> None:
    fs = [
        finding(id="known", issue={"id": "i1", "state": "open"}),  # already on the branch
        finding(id="dep", taxonomy={"category": "sca"}),  # a dependency bump, not a code patch
        finding(id="nopath", location={"path": "", "start_line": 0}),
        finding(id="noissue", issue=None),
        *[finding(id=f"m{i}", scoring={"normalized_severity": "MEDIUM", "risk_score": i})
          for i in range(5)],
        finding(id="crit", scoring={"normalized_severity": "CRITICAL", "risk_score": 10}),
        finding(id="secret", taxonomy={"category": "secrets"},
                scoring={"normalized_severity": "HIGH", "risk_score": 90}),
    ]  # fmt: skip
    picked, left_out = cmd.fixable(fs)
    assert [f["id"] for f in picked] == ["crit", "secret", "m4", "m3", "m2"]
    assert left_out == 2


def test_the_estimate_is_the_cap_and_its_price() -> None:
    est = cmd.Estimate(3, 60_000, 0.015, 1_000_000)
    assert est.cap == 180_000 and est.usd == 2.7 and not est.over_budget
    assert cmd.Estimate(3, 60_000, None, None).usd is None
    assert not cmd.Estimate(3, 60_000, None, None).over_budget  # no budget: unlimited
    assert cmd.Estimate(3, 60_000, None, 179_999).over_budget


def test_the_preview_says_what_and_how_much_and_spends_nothing() -> None:
    est = cmd.Estimate(1, 60_000, 0.015, 500_000)
    body = cmd.preview_body("K7M2PQ9X", [finding()], 2, est)
    assert body.startswith(cmd.MARKER)
    assert "at most 60,000 model tokens (about $0.90)" in body
    assert "500,000 tokens left this month" in body
    assert "`/fix confirm K7M2PQ9X`" in body and "within 24 hours" in body
    assert "and 2 more, not included" in body
    assert "Nothing has run and nothing is spent" in body

    over = cmd.preview_body("K7M2PQ9X", [finding()], 0, cmd.Estimate(1, 60_000, None, 10))
    assert "cannot run" in over and "/fix confirm" not in over


def test_text_from_the_pull_request_is_escaped_in_every_comment() -> None:
    hostile = finding(
        title="x](https://evil.example) <img src=x onerror=alert(1)> @everyone",
        location={"path": "a`b|c.py", "start_line": 1},
    )
    body = cmd.preview_body("K7M2PQ9X", [hostile], 0, cmd.Estimate(1, 1000, None, None))
    assert not re.search(r"(?<!\\)<img", body) and not re.search(r"(?<!\\)\]\(https", body)
    assert "@everyone" not in body  # no mentions pinged from a finding title
    result = cmd.result_body(
        hostile,
        {"patch": "--- a/x\n+++ b/x\n```\n</details><script>", "explanation": "<b>trust me</b>"},
        [{"attempt": 1, "steps": [{"name": "rerun_rule", "passed": True}]}],
    )
    assert "<script>" not in result.split("```", 1)[0]  # nothing before the fence is markup
    assert not re.search(r"(?<!\\)<b>", result)
    fence = "````"  # longer than the ``` inside the patch, so the patch cannot close it
    assert f"{fence}diff\n--- a/x" in result and result.count(fence) == 2


def test_a_result_lists_what_was_checked_or_why_there_is_no_patch() -> None:
    record = [
        {"attempt": 1, "steps": [{"name": "rerun_rule", "passed": False}], "feedback": "still there"},
        {"attempt": 2, "steps": [{"name": "rerun_rule", "passed": True},
                                 {"name": "rerun_scanners", "passed": True}]},
    ]  # fmt: skip
    ok = cmd.result_body(
        finding(), {"patch": "--- a/app.py\n+++ b/app.py\n", "explanation": "e"}, record
    )
    assert "The rule that flagged it, run again: passed" in ok
    assert "Every scanner on the changed file, run again: passed" in ok
    assert "Bulwark has not changed this branch" in ok

    none = cmd.result_body(finding(), None, record[:1], ended="max_attempts_exhausted")
    assert "No verified patch after 1 attempt(s): no attempt passed verification." in none
    assert "The last attempt: still there." in none
    capped = cmd.result_body(finding(), None, [], ended="token_cap")
    assert "token cap" in capped
