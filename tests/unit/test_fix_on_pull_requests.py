"""`/fix` on a pull request (plan §50, Week 76): the comment flow against a real schema (SQLite)
with GitHub replaced at the HTTP layer; the agent's activities with the model replaced; and the
workflow's pull request mode on Temporal's own test server.

What is not here: a real GitHub App delivering a real comment, and a real model. See
docs/v2-week76-verification.md for what was run live instead.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from core.fixagent import pr_fix
from core.fixagent import workflow as wf
from core.fixagent.limits import WorkflowLimits
from core.fixagent.workflow import VerifiedFixInput, VerifiedFixWorkflow
from core.identity import users as people
from core.llm.budget import current_period
from core.models import Category, Finding, Location, Taxonomy
from core.models.finding import Evidence, Scoring, Severity
from core.persistence import repo
from core.persistence.models import (
    AuditEntry,
    FindingRow,
    GithubInstallation,
    LlmUsage,
    Organization,
    PrFixRequest,
    RoleOverride,
    VerifiedFixRun,
)

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

REPO = "acme/widgets"
SHA = "a" * 40
NEWER = "b" * 40


# ---- a pull request Bulwark scanned, and the people around it ----------------------------------


def finding(fid: str, sev: Severity = Severity.HIGH, category: Category = Category.SAST) -> Finding:
    return Finding(
        fid, f"Finding {fid}", "d", Location("app/users.py", 2, 2, "x"),
        Taxonomy(category, cwe=("CWE-89",)),
        scoring=Scoring(normalized_severity=sev, risk_score=50),
        evidence=Evidence(reported_by=["semgrep"]), fingerprint=f"fp-{fid}",
    )  # fmt: skip


class World:
    def __init__(self, sessions: sessionmaker[Session]) -> None:
        self.sessions = sessions
        with sessions() as s:
            org = Organization(name="acme")
            s.add(org)
            s.flush()
            self.org = org.id
            s.add(GithubInstallation(id="42", account_login="acme", org_id=org.id))
            s.commit()
            scan = repo.create_scan(
                s, source_type="git", source_ref="https://github.com/acme/widgets.git",
                source_label=f"{REPO}#7", asset_label="https://github.com/acme/widgets.git",
                tools=["semgrep"], org_id=org.id, ref="refs/pull/7/head", github_repo=REPO,
                github_pr_number=7, github_installation_id="42", github_head_sha=SHA,
            )  # fmt: skip
            scan.status = "completed"
            self.scan, self.asset = scan.id, scan.asset_id
            new = [finding("new1"), finding("new2", Severity.CRITICAL)]
            for f, state in [*((f, "new") for f in new), (finding("old"), "open"),
                             (finding("dep", category=Category.SCA), "new")]:  # fmt: skip
                s.add(FindingRow(
                    scan_id=scan.id, finding_id=f.id, fingerprint=f.fingerprint,
                    category=f.taxonomy.category.value, severity="HIGH", severity_rank=3,
                    risk_score=50, path=f.location.path, start_line=2, tools=["semgrep"],
                    data=f.to_dict(), issue_id=None, issue_state=state,
                ))  # fmt: skip
            self.ana = self.person(s, "ana@acme.test", "member", "ana-gh")
            self.vic = self.person(s, "vic@acme.test", "viewer", "vic-gh")
            s.commit()
        self.gh = FakeGitHub()
        self.started: list[tuple[str, str, str]] = []

    def person(self, s: Session, email: str, role: str, login: str) -> str:
        u = people.create(s, self.org, "test", email=email, role=role)
        u.github_login = login
        return u.id

    async def starter(
        self, s: Session, req: PrFixRequest, doc: dict[str, Any], workflow_id: str, run_id: str
    ) -> None:
        self.started.append((req.id, doc["id"], run_id))

    def comment(self, body: str, login: str = "ana-gh", association: str = "MEMBER",
                **kw: Any) -> str:  # fmt: skip
        payload = comment_payload(body, login, association, **kw)
        event = pr_fix.parse_comment_event(payload)
        assert event is not None
        with self.sessions() as s:
            return asyncio.run(pr_fix.handle_comment(
                s, event, self.org, pr_fix.GitHub(lambda: "inst-token", self.gh),
                starter=self.starter, usd_per_1k=0.015, now=kw.get("now"),
            ))  # fmt: skip

    def requests(self) -> list[PrFixRequest]:
        with self.sessions() as s:
            return list(s.scalars(select(PrFixRequest).order_by(PrFixRequest.created_at)))


def comment_payload(body: str, login: str = "ana-gh", association: str = "MEMBER",
                    **kw: Any) -> dict[str, Any]:  # fmt: skip
    return {
        "action": kw.get("action", "created"),
        "installation": {"id": 42},
        "repository": {"full_name": REPO},
        "issue": {"number": 7, **({} if kw.get("on_issue") else {"pull_request": {"url": "x"}})},
        "comment": {"body": body, "author_association": association,
                    "user": {"login": login, "type": kw.get("type", "User")}},
    }  # fmt: skip


class FakeGitHub:
    """GitHub's REST API for one pull request: read it, and take comments."""

    def __init__(self) -> None:
        self.head, self.head_repo, self.state = SHA, REPO, "open"
        self.calls: list[tuple[str, str]] = []
        self.comments: list[str] = []

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> Any:
        assert headers["Authorization"] == "Bearer inst-token"
        self.calls.append((method, url))
        if method == "GET" and url.endswith(f"/repos/{REPO}/pulls/7"):
            head_repo = {"full_name": self.head_repo} if self.head_repo else None
            return 200, {"number": 7, "state": self.state,
                         "head": {"sha": self.head, "repo": head_repo},
                         "base": {"repo": {"full_name": REPO}}}  # fmt: skip
        if method == "POST" and url.endswith(f"/repos/{REPO}/issues/7/comments"):
            self.comments.append(json.loads(body or b"{}")["body"])
            return 201, {"id": len(self.comments)}
        return 404, None

    @property
    def last(self) -> str:
        return self.comments[-1]

    def code(self) -> str:
        line = next(x for x in self.last.splitlines() if "/fix confirm" in x)
        return line.split("/fix confirm ", 1)[1].split("`", 1)[0]


@pytest.fixture
def world(sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch) -> World:
    monkeypatch.setenv("BULWARK_FIX_TOKENS_PER_FINDING", "50000")
    monkeypatch.setenv("BULWARK_LLM_MAX_TOKENS_PER_ORG_MONTH", "1000000")
    monkeypatch.setenv("BULWARK_FIXAGENT_MAX_CONCURRENT_PER_ORG", "3")
    return World(sessions)


# ---- the comment flow ---------------------------------------------------------------------------


def test_preview_then_confirm_starts_one_run_per_new_finding(world: World) -> None:
    assert world.comment("/fix") == "previewed"
    preview = world.gh.last
    assert "Finding new2" in preview and "Finding new1" in preview
    assert "Finding old" not in preview  # already on the branch: not this pull request's
    assert "Finding dep" not in preview  # a dependency: not a code patch
    assert "at most 100,000 model tokens (about $1.50)" in preview
    assert "1,000,000 tokens left this month" in preview
    [req] = world.requests()
    assert req.status == "previewed" and req.head_sha == SHA and req.token_cap == 100_000
    assert req.finding_ids == ["new2", "new1"]  # critical first
    assert world.started == []  # nothing runs on a preview

    assert world.comment(f"/fix confirm {world.gh.code()}") == "started"
    assert sorted(f for _, f, _ in world.started) == ["new1", "new2"]
    assert "started for 2 finding(s), at most 100,000 tokens, confirmed by @ana-gh" in world.gh.last
    with world.sessions() as s:
        runs = list(s.scalars(select(VerifiedFixRun)))
        assert {r.finding_id for r in runs} == {"new1", "new2"}
        assert all(r.issue_id is None and r.pr_fix_request_id == req.id for r in runs)
        actions = [a.action for a in s.scalars(select(AuditEntry))]
        assert "pr_fix.previewed" in actions and "pr_fix.started" in actions
    [req] = world.requests()
    assert req.status == "started" and req.confirmed_by == world.ana


def test_a_code_works_once(world: World) -> None:
    world.comment("/fix")
    code = world.gh.code()
    assert world.comment(f"/fix confirm {code}") == "started"
    assert world.comment(f"/fix confirm {code}") == "refused"
    assert "no open /fix preview with that code" in world.gh.last
    assert len(world.started) == 2


def test_a_confirm_after_new_commits_is_refused(world: World) -> None:
    world.comment("/fix")
    code = world.gh.code()
    world.gh.head = NEWER  # someone pushed after the preview
    assert world.comment(f"/fix confirm {code}") == "refused"
    assert "new commits since the preview" in world.gh.last
    assert world.started == [] and world.requests()[0].status == "cancelled"


def test_a_preview_needs_a_scan_of_the_commit_the_pull_request_is_at(world: World) -> None:
    world.gh.head = NEWER  # the scan of NEWER has not finished
    assert world.comment("/fix") == "refused"
    assert "no finished scan of this pull request's latest commit" in world.gh.last
    assert world.requests() == []


def test_an_expired_preview_cannot_be_confirmed(world: World) -> None:
    world.comment("/fix")
    later = datetime.now(timezone.utc) + timedelta(hours=25)
    assert world.comment(f"/fix confirm {world.gh.code()}", now=later) == "refused"
    assert "expired" in world.gh.last and world.started == []


def test_cancel(world: World) -> None:
    world.comment("/fix")
    code = world.gh.code()
    assert world.comment(f"/fix cancel {code}") == "cancelled"
    assert world.comment(f"/fix confirm {code}") == "refused"
    assert world.started == []


def test_a_new_preview_replaces_the_old_one(world: World) -> None:
    world.comment("/fix")
    first = world.gh.code()
    world.comment("/fix")
    second = world.gh.code()
    assert second != first
    assert world.comment(f"/fix confirm {first}") == "refused"
    assert world.comment(f"/fix confirm {second}") == "started"


@pytest.mark.parametrize(
    ("login", "association", "words"),
    [
        ("vic-gh", "MEMBER", "Member role"),  # a viewer in Bulwark
        ("stranger", "MEMBER", "not linked"),
        ("ana-gh", "CONTRIBUTOR", "owner, member or collaborator"),
        ("ana-gh", "NONE", "owner, member or collaborator"),
    ],
)
def test_who_may_not(world: World, login: str, association: str, words: str) -> None:
    assert world.comment("/fix", login, association) == "refused"
    assert words in world.gh.last
    assert ("GET", f"https://api.github.com/repos/{REPO}/pulls/7") not in world.gh.calls
    assert world.requests() == []


def test_the_same_rules_hold_for_the_confirm(world: World) -> None:
    world.comment("/fix")
    code = world.gh.code()
    assert world.comment(f"/fix confirm {code}", "vic-gh") == "refused"
    assert world.comment(f"/fix confirm {code}", "ana-gh", "CONTRIBUTOR") == "refused"
    assert world.started == [] and world.requests()[0].status == "previewed"


def test_a_project_role_counts_and_a_login_matches_without_case(world: World) -> None:
    with world.sessions() as s:
        s.add(RoleOverride(org_id=world.org, user_id=world.vic, target_type="project",
                           target_id=world.asset, role="member", created_by="test"))  # fmt: skip
        s.commit()
    assert world.comment("/fix", "VIC-GH") == "previewed"


def test_a_turned_off_person_is_not_linked(world: World) -> None:
    with world.sessions() as s:
        people.disable(s, world.org, "test", world.ana, reason="left")
    assert world.comment("/fix") == "refused" and "not linked" in world.gh.last


def test_never_for_a_fork_or_a_closed_pull_request(world: World) -> None:
    world.gh.head_repo = "eve/widgets"
    assert world.comment("/fix") == "refused" and "fork" in world.gh.last
    world.gh.head_repo = None  # the fork was deleted
    assert world.comment("/fix") == "refused" and "fork" in world.gh.last
    world.gh.head_repo, world.gh.state = REPO, "closed"
    assert world.comment("/fix") == "refused" and "not open" in world.gh.last


def test_a_fork_that_became_one_after_the_preview_is_refused_on_confirm(world: World) -> None:
    world.comment("/fix")
    code = world.gh.code()
    world.gh.head_repo = "eve/widgets"
    assert world.comment(f"/fix confirm {code}") == "refused" and world.started == []


def test_over_the_budget_it_cannot_run(world: World) -> None:
    with world.sessions() as s:
        s.add(LlmUsage(org_id=world.org, period=current_period(), tokens=950_000))
        s.commit()
    assert world.comment("/fix") == "over_budget"
    assert "cannot run" in world.gh.last and "/fix confirm" not in world.gh.last
    assert world.requests()[0].status == "refused"


def test_the_budget_is_checked_again_on_confirm(world: World) -> None:
    world.comment("/fix")
    code = world.gh.code()
    with world.sessions() as s:
        s.add(LlmUsage(org_id=world.org, period=current_period(), tokens=990_000))
        s.commit()
    assert world.comment(f"/fix confirm {code}") == "refused"
    assert "only 10,000 are left" in world.gh.last and world.started == []


def test_the_concurrency_limit_holds(world: World, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BULWARK_FIXAGENT_MAX_CONCURRENT_PER_ORG", "1")
    world.comment("/fix")
    assert world.comment(f"/fix confirm {world.gh.code()}") == "refused"
    assert "at most 1" in world.gh.last


def test_temporal_down_spends_nothing_and_says_so(world: World) -> None:
    async def down(*_: Any) -> None:
        raise ConnectionError("temporal is not running")

    world.starter = down  # type: ignore[method-assign]
    world.comment("/fix")
    assert world.comment(f"/fix confirm {world.gh.code()}") == "refused"
    assert "could not be started" in world.gh.last
    with world.sessions() as s:
        assert {r.status for r in s.scalars(select(VerifiedFixRun))} == {"failed"}


def test_a_pull_request_bulwark_never_scanned_gets_no_answer(world: World) -> None:
    with world.sessions() as s:
        event = pr_fix.parse_comment_event(comment_payload("/fix"))
        assert event is not None
        other = pr_fix.CommentEvent("42", "acme/other", 7, event.commenter, event.command)
        out = asyncio.run(pr_fix.handle_comment(s, other, world.org,
                                                pr_fix.GitHub(lambda: "inst-token", world.gh)))  # fmt: skip
    assert out == "ignored" and world.gh.calls == []


def test_another_organizations_person_with_that_login_is_not_linked(world: World) -> None:
    with world.sessions() as s:
        other = Organization(name="other")
        s.add(other)
        s.flush()
        u = people.create(s, other.id, "test", email="x@other.test", role="admin")
        u.github_login = "eve-gh"
        s.commit()
    assert world.comment("/fix", "eve-gh", "OWNER") == "refused"
    assert "not linked" in world.gh.last


@pytest.mark.parametrize(
    ("payload_kw", "body"),
    [
        ({"type": "Bot"}, "/fix"),
        ({"action": "edited"}, "/fix"),  # an old comment edited into a command
        ({"on_issue": True}, "/fix"),  # an issue, not a pull request
        ({}, "please run /fix"),
    ],
)
def test_what_is_not_a_fix_comment(payload_kw: dict[str, Any], body: str) -> None:
    login = "bulwark[bot]" if payload_kw.get("type") == "Bot" else "ana-gh"
    assert pr_fix.parse_comment_event(comment_payload(body, login, **payload_kw)) is None
    assert pr_fix.parse_comment_event(comment_payload("/fix", "renovate[bot]")) is None
    assert pr_fix.parse_comment_event({"action": "created", "issue": []}) is None


# ---- linking a GitHub login (admins only, through the People API) ------------------------------


def test_linking_a_login(world: World) -> None:
    with world.sessions() as s:
        u = people.update_user(s, world.org, "test", world.vic, {"github_login": "@Vic-Two"})
        assert u.github_login == "Vic-Two" and people.view(u)["github_login"] == "Vic-Two"
        for bad in ("-vic", "vic-", "v--x", "a" * 40, "vic two", "vic/../x"):
            with pytest.raises(people.UserError, match="GitHub username"):
                people.update_user(s, world.org, "test", world.vic, {"github_login": bad})
        with pytest.raises(people.UserError, match="already linked to ana@acme.test") as exc:
            people.update_user(s, world.org, "test", world.vic, {"github_login": "ANA-gh"})
        assert exc.value.status == 409
        u = people.update_user(s, world.org, "test", world.vic, {"github_login": ""})
        assert u.github_login is None
        updates = [a for a in s.scalars(select(AuditEntry)) if a.action == "user.updated"]
        assert len(updates) == 2  # linked, unlinked (the log keeps a digest of each change)


# ---- the webhook, with GitHub's own signature ---------------------------------------------------


def test_the_webhook_answers_a_signed_comment(
    world: World, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api.deps import AppState
    from api.main import create_app
    from core.config import Settings
    from tests.unit.test_github_webhook import SECRET, FakeSubscriber, sign

    settings = Settings(
        database_url="sqlite://", redis_url="", s3_endpoint=None, s3_access_key="",
        s3_secret_key="", s3_bucket="b", api_token="t" * 32, workdir=tmp_path,
        upload_dir=tmp_path / "up", max_upload_bytes=1000, github_webhook_secret=SECRET,
        github_app_id="1", github_app_private_key="unused: the token is faked below",
    )  # fmt: skip
    monkeypatch.setattr("core.github_app.installation_token", lambda *a, **k: "inst-token")
    monkeypatch.setattr(pr_fix, "http_transport", world.gh)
    client = TestClient(create_app(AppState(settings, world.sessions, lambda *a: None,
                                            FakeSubscriber())))  # fmt: skip

    def post(payload: dict[str, Any], secret: str = SECRET) -> Any:
        body = json.dumps(payload).encode()
        return client.post("/integrations/github/webhook", content=body, headers={
            "X-GitHub-Event": "issue_comment", "X-Hub-Signature-256": sign(body, secret)})  # fmt: skip

    assert post(comment_payload("/fix"), "wrong").status_code == 401
    assert world.gh.comments == []
    r = post(comment_payload("/fix"))
    assert r.status_code == 200 and r.json() == {"status": "previewed"}
    assert "Bulwark /fix: preview" in world.gh.last
    unknown = {**comment_payload("/fix"), "installation": {"id": 999}}
    assert post(unknown).json() == {"status": "ignored"}  # never creates an organization
    with world.sessions() as s:
        assert s.get(GithubInstallation, "999") is None
    assert post(comment_payload("thanks!")).json() == {"status": "ignored"}

    # Taken off the installation allow-list: a known installation's comments get no answer.
    listed = Settings(**{**settings.__dict__, "github_app_allowed_accounts": frozenset({"other"})})
    client = TestClient(create_app(AppState(listed, world.sessions, lambda *a: None,
                                            FakeSubscriber())))  # fmt: skip
    seen = len(world.gh.comments)
    assert post(comment_payload("/fix")).json() == {"status": "refused"}
    assert len(world.gh.comments) == seen


def test_a_pull_request_scan_records_the_head_commit() -> None:
    from core.github_app import parse_pull_request_event

    base = {"action": "synchronize", "installation": {"id": 1},
            "repository": {"owner": {"login": "a"}, "full_name": "a/b",
                           "clone_url": "https://github.com/a/b.git"}}  # fmt: skip
    ev = parse_pull_request_event({**base, "pull_request": {"number": 3, "head": {"sha": SHA}}})
    assert ev is not None and ev.head_sha == SHA
    odd = parse_pull_request_event({**base, "pull_request": {"number": 3, "head": {"sha": "x; y"}}})
    assert odd is not None and odd.head_sha is None


# ---- the activities: budget, cap, and the result comment ----------------------------------------


class Usage:
    input_tokens, output_tokens = 1000, 500


def message(*blocks: Any) -> Any:
    return SimpleNamespace(content=list(blocks), stop_reason="tool_use", usage=Usage())


def tool(name: str, **inp: Any) -> Any:
    return SimpleNamespace(type="tool_use", id=f"t-{uuid.uuid4().hex[:6]}", name=name, input=inp)


PATCH = "--- a/app/users.py\n+++ b/app/users.py\n@@ -1 +1 @@\n-x\n+y\n"


@pytest.fixture
def agent(sessions: sessionmaker[Session], monkeypatch: pytest.MonkeyPatch) -> Any:
    """run_one_attempt_activity with the clone, the model and the scanners replaced."""
    replies: list[Any] = []
    calls: list[int] = []

    class FakeClient:
        def __init__(self, cfg: Any) -> None:
            pass

        def complete_with_tools(self, system: str, messages: Any, tools: Any) -> Any:
            calls.append(1)
            return replies.pop(0)

    def clone(url: str, dest: Path, **kw: Any) -> Path:
        (dest / "app").mkdir(parents=True, exist_ok=True)
        (dest / "app" / "users.py").write_text("x\n")
        return dest

    passed = SimpleNamespace(name="rerun_rule", passed=True, detail="")
    verified: dict[str, Any] = {}

    def record(step: str) -> Any:
        def run(*args: Any, **kw: Any) -> Any:
            verified[step] = kw
            return passed

        return run

    monkeypatch.setenv("BULWARK_LLM_ENABLED", "1")
    monkeypatch.setenv("BULWARK_LLM_API_KEY", "test-key-not-real")
    monkeypatch.setenv("BULWARK_LLM_MAX_TOKENS_PER_ORG_MONTH", "1000000")
    monkeypatch.setattr("core.persistence.db.get_session_factory", lambda: sessions)
    monkeypatch.setattr("core.gitfetch.clone_repo", clone)
    monkeypatch.setattr("core.llm.client.AnthropicClient", FakeClient)
    monkeypatch.setattr("core.fixagent.verify.apply_patch", lambda root, patch: None)
    monkeypatch.setattr("core.fixagent.verify.rerun_rule", record("rule"))
    monkeypatch.setattr("core.fixagent.verify.rerun_scanners", record("scanners"))
    with sessions() as s:
        org = Organization(name="o")
        s.add(org)
        s.flush()
        run = VerifiedFixRun(org_id=org.id, issue_id="issue-1", workflow_id="wf-1",
                             verification_record=[])  # fmt: skip
        s.add(run)
        s.commit()
        org_id, run_id = org.id, run.id
    inp = VerifiedFixInput(
        run_db_id=run_id, workflow_id="wf-1", org_id=org_id, issue_id="",
        finding=Finding("f1", "SQLi", "d", Location("app/users.py", 1, 1, "x"),
                        Taxonomy(Category.SAST)).to_dict(),
        clone_url="https://github.com/acme/widgets.git", ref="refs/pull/7/head",
        originating_tool="semgrep", baseline_fingerprints=[], repo_full_name=REPO,
        installation_id="42", run_tests=None, limits=WorkflowLimits().__dict__,
        token_cap=50_000, pr_fix_request_id="req-1", pr_number=7,
    )  # fmt: skip
    return SimpleNamespace(inp=inp, replies=replies, calls=calls, sessions=sessions, org=org_id,
                           verified=verified)  # fmt: skip


def used(agent: Any) -> int:
    with agent.sessions() as s:
        row = s.get(LlmUsage, (agent.org, current_period()))
        return row.tokens if row else 0


def test_an_attempt_charges_the_organizations_budget(agent: Any) -> None:
    agent.replies += [message(tool("read_file", path="app/users.py")),
                      message(tool("propose_patch", explanation="e", patch=PATCH,
                                   confidence="high"))]  # fmt: skip
    out = asyncio.run(wf.run_one_attempt_activity(agent.inp, None, 1, 50_000))
    assert out["passed"] and out["tokens"] == 3000
    assert used(agent) == 3000  # before Week 76 the fix agent spent without counting


def test_verification_gets_the_file_before_the_patch_and_the_known_findings(agent: Any) -> None:
    agent.inp.baseline_findings = [{"path": "app/users.py", "fingerprint": "fp", "category": "sast",
                                    "rule_ids": ["B608"], "start_line": 1, "end_line": 1}]  # fmt: skip
    agent.replies += [
        message(tool("propose_patch", explanation="e", patch=PATCH, confidence="high"))
    ]
    assert asyncio.run(wf.run_one_attempt_activity(agent.inp, None, 1, 50_000))["passed"]
    rule, scanners = agent.verified["rule"], agent.verified["scanners"]
    assert rule["original"] == "x\n"  # the clone's text, read before the patch was applied
    assert scanners["originals"] == {"app/users.py": "x\n"}
    assert [k.rule_ids for k in rule["known"]] == [("B608",)] and scanners["known"] == rule["known"]


def test_the_baseline_carries_what_verification_needs(world: World) -> None:
    from core.fixagent.store import baseline_findings_for

    f = finding("ruled")
    f.evidence.rule_ids = {"bandit": ["B608"], "semgrep": ["python.sqli"]}
    f.location = Location("app/users.py", 4, 6, "x")
    with world.sessions() as s:
        s.add(
            FindingRow(
                scan_id=world.scan,
                finding_id="ruled",
                fingerprint="fp-ruled",
                category="sast",
                severity="HIGH",
                severity_rank=3,
                risk_score=1,
                path="app/users.py",
                start_line=4,
                tools=["bandit"],
                data=f.to_dict(),
            )
        )
        s.commit()
        rows = {r["fingerprint"]: r for r in baseline_findings_for(s, world.scan, "app/users.py")}
    assert {"fp-new1", "fp-new2", "fp-old", "fp-ruled"} <= set(rows)
    assert rows["fp-ruled"] == {"path": "app/users.py", "fingerprint": "fp-ruled",
                                "category": "sast", "rule_ids": ["B608", "python.sqli"],
                                "start_line": 4, "end_line": 6}  # fmt: skip


def test_the_cap_stops_the_attempt_before_the_next_model_call(agent: Any) -> None:
    agent.replies += [message(tool("read_file", path="app/users.py")) for _ in range(5)]
    out = asyncio.run(wf.run_one_attempt_activity(agent.inp, None, 1, 1500))
    assert not out["passed"] and "token cap" in out["feedback"]
    assert len(agent.calls) == 1 and out["tokens"] == 1500 and used(agent) == 1500


def test_no_attempt_once_the_monthly_budget_is_used(
    agent: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BULWARK_LLM_MAX_TOKENS_PER_ORG_MONTH", "100")
    with agent.sessions() as s:
        s.add(LlmUsage(org_id=agent.org, period=current_period(), tokens=100))
        s.commit()
    out = asyncio.run(wf.run_one_attempt_activity(agent.inp, None, 1, 50_000))
    assert out["stop"] == "org_budget" and agent.calls == []
    with agent.sessions() as s:
        run = s.get(VerifiedFixRun, agent.inp.run_db_id)
        assert run is not None and "budget reached" in run.verification_record[-1]["feedback"]


def test_the_result_is_posted_on_the_pull_request(
    agent: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    gh = FakeGitHub()
    monkeypatch.setattr("core.github_app.installation_token", lambda *a, **k: "inst-token")
    monkeypatch.setattr(wf, "github_transport", gh)
    with agent.sessions() as s:
        run = s.get(VerifiedFixRun, agent.inp.run_db_id)
        assert run is not None
        run.latest_patch = {"patch": PATCH, "explanation": "parameterize it"}
        run.verification_record = [
            {"attempt": 1, "steps": [{"name": "rerun_rule", "passed": True}]}
        ]
        s.commit()
    asyncio.run(wf.post_pr_result_activity(agent.inp, "verified", None))
    assert "A patch that passed verification" in gh.last and "+y" in gh.last
    asyncio.run(wf.post_pr_result_activity(agent.inp, "inconclusive", "token_cap"))
    assert "token cap" in gh.last and "+y" not in gh.last


# ---- the workflow's pull request mode, on Temporal's test server --------------------------------


def _pr_input(**kw: Any) -> VerifiedFixInput:
    base: dict[str, Any] = dict(
        run_db_id="run1", workflow_id="wf-x", org_id="org1", issue_id="", finding={},
        clone_url="https://example.com/x.git", ref="refs/pull/7/head", originating_tool="semgrep",
        baseline_fingerprints=[], repo_full_name=REPO, installation_id="42", run_tests=None,
        limits=WorkflowLimits(per_attempt_timeout_s=5, overall_timeout_s=60, max_attempts=3).__dict__,
        token_cap=10_000, pr_fix_request_id="req-1", pr_number=7,
    )  # fmt: skip
    base.update(kw)
    return VerifiedFixInput(**base)


def run_pr_workflow(
    attempt: Any, inp: VerifiedFixInput, post_fails: bool = False
) -> dict[str, Any]:
    seen: dict[str, Any] = {"posted": [], "finished": [], "awaiting": 0, "opened": 0}

    @activity.defn(name="set_awaiting_approval_activity")
    async def awaiting(run_db_id: str, patch: dict[str, Any], org_id: str | None = None) -> None:
        seen["awaiting"] += 1

    @activity.defn(name="open_pr_activity")
    async def open_pr(inp: VerifiedFixInput, patch: dict[str, Any]) -> str:
        seen["opened"] += 1
        return "x"

    @activity.defn(name="post_pr_result_activity")
    async def post(inp: VerifiedFixInput, status: str, ended: str | None) -> None:
        if post_fails:
            raise RuntimeError("GitHub is down")
        seen["posted"].append((status, ended))

    @activity.defn(name="finish_run_activity")
    async def finish(run_db_id: str, status: str, ended: str | None, pr_url: str | None,
                     org_id: str | None = None) -> None:  # fmt: skip
        seen["finished"].append((status, ended, org_id))

    async def scenario() -> str:
        env = await WorkflowEnvironment.start_time_skipping()
        queue = f"q-{uuid.uuid4().hex[:6]}"
        async with env, Worker(env.client, task_queue=queue, workflows=[VerifiedFixWorkflow],
                               activities=[attempt, awaiting, open_pr, post, finish]):  # fmt: skip
            return await env.client.execute_workflow(
                VerifiedFixWorkflow.run, inp, id=f"wf-{uuid.uuid4()}", task_queue=queue
            )

    seen["result"] = asyncio.run(scenario())
    return seen


def test_a_pull_request_run_posts_its_patch_and_needs_no_approval() -> None:
    @activity.defn(name="run_one_attempt_activity")
    async def ok(inp: VerifiedFixInput, feedback: str | None, attempt: int,
                 left: int | None = None) -> dict[str, Any]:  # fmt: skip
        return {"passed": True, "patch": {"patch": "p"}, "feedback": None, "tokens": 4000}

    seen = run_pr_workflow(ok, _pr_input())
    assert seen["result"] == "verified"
    assert seen["posted"] == [("verified", None)]
    assert seen["finished"] == [("verified", None, "org1")]
    assert seen["awaiting"] == 0 and seen["opened"] == 0  # nothing written to the repository


def test_the_cap_holds_across_attempts() -> None:
    budgets: list[int | None] = []

    @activity.defn(name="run_one_attempt_activity")
    async def costly(inp: VerifiedFixInput, feedback: str | None, attempt: int,
                     left: int | None = None) -> dict[str, Any]:  # fmt: skip
        budgets.append(left)
        return {"passed": False, "patch": None, "feedback": "nope", "tokens": 6000}

    seen = run_pr_workflow(costly, _pr_input())
    assert budgets == [10_000, 4_000]  # the second attempt may spend only what is left
    assert seen["result"] == "inconclusive"
    assert seen["posted"] == [("inconclusive", "token_cap")]


def test_a_used_up_budget_ends_the_run_without_more_attempts() -> None:
    tries: list[int] = []

    @activity.defn(name="run_one_attempt_activity")
    async def broke(inp: VerifiedFixInput, feedback: str | None, attempt: int,
                    left: int | None = None) -> dict[str, Any]:  # fmt: skip
        tries.append(attempt)
        return {"passed": False, "patch": None, "feedback": "budget", "tokens": 0,
                "stop": "org_budget"}  # fmt: skip

    seen = run_pr_workflow(broke, _pr_input())
    assert tries == [1] and seen["result"] == "failed"
    assert seen["finished"] == [("failed", "org_budget", "org1")]


def test_when_github_cannot_take_the_comment_the_run_says_so() -> None:
    @activity.defn(name="run_one_attempt_activity")
    async def ok(inp: VerifiedFixInput, feedback: str | None, attempt: int,
                 left: int | None = None) -> dict[str, Any]:  # fmt: skip
        return {"passed": True, "patch": {"patch": "p"}, "feedback": None, "tokens": 1}

    seen = run_pr_workflow(ok, _pr_input(), post_fails=True)
    assert seen["finished"] == [("verified", "comment_not_posted", "org1")]
