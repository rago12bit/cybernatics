"""`/fix` on a pull request (plan §50, Week 76, ADR-0059): the command, who may give it, and what
Bulwark says back. Pure functions; `core.fixagent.pr_fix` does the I/O.

1. Someone comments `/fix` on a pull request. Bulwark checks who they are and what the pull request
   is, then replies with a **preview**: the findings this pull request introduced that it would
   try to fix, and the most it may spend (a token cap, and its price when one is configured).
   Nothing has run and nothing is spent.
2. Someone allowed to (the same rules) replies `/fix confirm <code>`. Bulwark checks everything
   again -- including that the pull request has not moved since the preview -- and only then starts
   the verified-fix agent, which stops at the cap.
3. Each verified patch is posted as a comment for a person to apply. Bulwark writes nothing to the
   repository.

Who may: a GitHub owner, member or collaborator of the repository (GitHub's `author_association`)
*and* linked by an admin to an active Bulwark person whose role on this project is Member or higher.
Never for a pull request from a fork -- the lesson of GitHub's own `pull_request_target`: a fork's
code must not run with the base repository's credentials, and the agent runs that code's tests.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any

from core.ci.report import md

#: GitHub's word for someone with a hand in the repository. CONTRIBUTOR (a past merged PR),
#: FIRST_TIMER, NONE and the rest are not enough.
TRUSTED_ASSOCIATIONS = frozenset({"OWNER", "MEMBER", "COLLABORATOR"})
MIN_ROLE_RANK = 2  # core.identity.roles.RANK["member"]
MAX_FINDINGS = 5
FIXABLE = frozenset({"sast", "secrets", "iac"})
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I: read off a screen
_COMMAND = re.compile(r"^/fix(?:\s+(confirm|cancel)\s+([A-Za-z0-9]{6,12}))?\s*$")
MARKER = "<!-- bulwark-fix -->"
STEP_NAMES = {
    "rerun_rule": "The rule that flagged it, run again",
    "rerun_scanners": "Every scanner on the changed file, run again",
    "run_tests": "The project's tests",
}


@dataclass(frozen=True)
class Command:
    action: str  # "preview" | "confirm" | "cancel"
    code: str | None = None


def parse(body: str) -> Command | None:
    """The command on the comment's first line, or None. Only the first line counts, and it must be
    the whole line: a `/fix` quoted inside a sentence or a reply is not a command."""
    first = (body or "").lstrip().split("\n", 1)[0].strip()
    m = _COMMAND.match(first)
    if m is None:
        return None
    if m.group(1) is None:
        return Command("preview")
    return Command(m.group(1), m.group(2).upper())


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


@dataclass(frozen=True)
class Commenter:
    login: str
    association: str
    is_bot: bool


@dataclass(frozen=True)
class PullRequest:
    number: int
    state: str
    head_sha: str
    head_repo: str | None  # None: the fork it came from was deleted
    base_repo: str

    @property
    def from_fork(self) -> bool:
        return self.head_repo is None or self.head_repo.lower() != self.base_repo.lower()


def refusal(commenter: Commenter, pr: PullRequest | None, role_rank: int | None) -> str | None:
    """Why this person may not run /fix on this pull request, or None if they may. `role_rank` is
    the linked Bulwark person's rank on the project, None when the login is linked to no one."""
    if commenter.association.upper() not in TRUSTED_ASSOCIATIONS:
        return "only an owner, member or collaborator of this repository can use /fix"
    if role_rank is None:
        return (
            "your GitHub account is not linked to a Bulwark person in this organization; an admin "
            "can link it under People and access"
        )
    if role_rank < MIN_ROLE_RANK:
        return "/fix needs the Member role or higher on this project in Bulwark"
    if pr is None:
        return "Bulwark could not read this pull request from GitHub"
    if pr.from_fork:
        return "/fix never runs for a pull request from a fork"
    if pr.state != "open":
        return "this pull request is not open"
    return None


def fixable(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """The findings this pull request introduced that the agent can try, most severe first, at most
    MAX_FINDINGS; and how many more were left out."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    new = [
        f
        for f in findings
        if (f.get("issue") or {}).get("state") == "new"  # new in this pull request (plan §36)
        and f.get("taxonomy", {}).get("category") in FIXABLE
        and (f.get("location") or {}).get("path")
    ]
    new.sort(
        key=lambda f: (
            order.get(str(f.get("scoring", {}).get("normalized_severity", "INFO")).upper(), 5),
            -(f.get("scoring", {}).get("risk_score") or 0),
        )
    )
    return new[:MAX_FINDINGS], max(0, len(new) - MAX_FINDINGS)


@dataclass(frozen=True)
class Estimate:
    findings: int
    tokens_per_finding: int
    usd_per_1k: float | None
    budget_left: int | None  # the organization's monthly LLM tokens left, None when unlimited

    @property
    def cap(self) -> int:
        return self.findings * self.tokens_per_finding

    @property
    def usd(self) -> float | None:
        return None if self.usd_per_1k is None else round(self.cap / 1000 * self.usd_per_1k, 2)

    @property
    def over_budget(self) -> bool:
        return self.budget_left is not None and self.cap > self.budget_left


def _where(f: dict[str, Any]) -> str:
    loc = f.get("location") or {}
    return f"{md(loc.get('path', '?'), 120)}:{int(loc.get('start_line') or 0)}"


def preview_body(code: str, findings: list[dict[str, Any]], left_out: int, est: Estimate) -> str:
    lines = [MARKER, "### Bulwark /fix: preview", ""]
    lines.append(
        f"The verified-fix agent would try {len(findings)} finding(s) this pull request introduced:"
    )
    lines.append("")
    for f in findings:
        sev = str(f.get("scoring", {}).get("normalized_severity", "INFO")).lower()
        lines.append(f"- **{md(sev, 10)}** {md(f.get('title', ''), 120)} ({_where(f)})")
    if left_out:
        lines.append(f"- and {left_out} more, not included (at most {MAX_FINDINGS} per request)")
    lines.append("")
    price = f" (about ${est.usd:,.2f})" if est.usd is not None else ""
    lines.append(
        f"**Cost:** at most {est.cap:,} model tokens{price}: {est.tokens_per_finding:,} per finding. "
        "The agent stops at that cap."
    )
    if est.budget_left is not None:
        lines.append(f"This organization has {est.budget_left:,} tokens left this month.")
    lines.append("")
    if est.over_budget:
        lines.append("**This is more than the budget left, so it cannot run.**")
    else:
        lines.append(
            f"Nothing has run and nothing is spent. A member can start it by replying "
            f"`/fix confirm {code}` within 24 hours. Each verified patch is posted here for a person "
            "to apply; Bulwark does not push to this branch."
        )
    return "\n".join(lines)


def refused_body(reason: str) -> str:
    return "\n".join([MARKER, f"Bulwark /fix: {md(reason, 300)}."])


def started_body(n: int, est: Estimate, by: str) -> str:
    return "\n".join(
        [MARKER, f"Bulwark /fix: started for {n} finding(s), at most {est.cap:,} tokens, confirmed "
         f"by @{md(by, 60).replace('@​', '')}. Each result is posted here when it is verified."]
    )  # fmt: skip


def fence(text: str) -> str:
    """A fenced block the text inside cannot close: longer than any backtick run in it."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}diff\n{text}\n{ticks}"


ENDED = {
    "token_cap": "it reached the token cap from the preview",
    "org_budget": "the organization's monthly AI token budget is used up",
    "overall_timeout": "it ran out of time",
    "per_attempt_timeout": "an attempt ran out of time",
    "max_attempts_exhausted": "no attempt passed verification",
}


def result_body(
    finding: dict[str, Any],
    patch: dict[str, Any] | None,
    record: list[dict[str, Any]],
    *,
    ended: str | None = None,
) -> str:
    """One finding's outcome. The explanation is the model's and the patch is derived from the
    pull request's code: both are shown as text, never as markup. `ended`: the workflow's reason
    for stopping, when it stopped without a patch."""
    title = md(finding.get("title", ""), 120)
    lines = [MARKER, f"### Bulwark /fix: {title} ({_where(finding)})", ""]
    if patch is None:
        last = record[-1] if record else {}
        stopped = ENDED.get(ended or "", "no attempt passed verification")
        lines.append(f"No verified patch after {len(record)} attempt(s): {stopped}.")
        if last.get("feedback"):
            lines.append(f"The last attempt: {md(str(last['feedback']).rstrip('. '), 300)}.")
        return "\n".join(lines)
    lines.append("A patch that passed verification:")
    for step in record[-1].get("steps", []) if record else []:
        mark = "passed" if step.get("passed") else "failed"
        lines.append(
            f"- {STEP_NAMES.get(step.get('name', ''), md(step.get('name', ''), 40))}: {mark}"
        )
    lines += ["", fence(str(patch.get("patch", ""))[:50_000].rstrip("\n")), ""]
    lines.append("<details><summary>The agent's explanation (written by a model)</summary>")
    lines += ["", md(patch.get("explanation", ""), 2000), "", "</details>"]
    lines.append("")
    lines.append("Review it before applying. Bulwark has not changed this branch.")
    return "\n".join(lines)
