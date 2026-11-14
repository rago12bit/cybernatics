import pytest

from core.gitfetch import GitUrlError, validate_git_url
from core.netsafety import is_public_ip as _is_public


def resolves_to(*ips: str):  # type: ignore[no-untyped-def]
    return lambda host: list(ips)


PUBLIC = resolves_to("140.82.112.3")


def test_valid_urls_accepted() -> None:
    for url in (
        "https://github.com/OWASP/NodeGoat",
        "https://github.com/OWASP/NodeGoat.git",
        "https://gitlab.com/group/sub/project",
        "https://bitbucket.org/team/repo/",
    ):
        assert validate_git_url(url, PUBLIC).ip == "140.82.112.3"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",  # not https
        "git://github.com/a/b",
        "ssh://git@github.com/a/b",
        "git@github.com:a/b.git",
        "file:///etc/passwd",
        "https://user:pw@github.com/a/b",  # credentials
        "https://github.com@evil.com/a/b",  # userinfo host confusion
        "https://evil.com/a/b",  # not allowlisted
        "https://github.com.evil.com/a/b",  # suffix trick
        "https://169.254.169.254/latest/meta-data",
        "https://github.com:8443/a/b",  # port
        "https://github.com/a/b?x=1",  # query
        "https://github.com/a/b#frag",
        "https://github.com/a",  # missing repo
        "https://github.com/a/../../etc",  # traversal
        "https://github.com/a/b c",
        "",
    ],
)
def test_bad_urls_rejected(url: str) -> None:
    with pytest.raises(GitUrlError):
        validate_git_url(url, PUBLIC)


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.5", "172.16.0.1", "192.168.1.1",  # RFC 1918
        "127.0.0.1", "::1",  # loopback
        "169.254.169.254", "fe80::1",  # link-local / cloud metadata
        "100.64.0.1",  # CGNAT
        "0.0.0.0", "224.0.0.1",  # unspecified / multicast
        "::ffff:169.254.169.254", "::ffff:10.0.0.1",  # IPv4-mapped bypass
        "2002:a9fe:a9fe::1",  # 6to4 embedding 169.254.169.254
        "64:ff9b::a00:1",  # NAT64
        "fc00::1",  # unique local
    ],
)  # fmt: skip
def test_private_and_special_addresses_blocked(ip: str) -> None:
    assert not _is_public(ip)
    with pytest.raises(GitUrlError, match="non-public"):
        validate_git_url("https://github.com/a/b", resolves_to(ip))


def test_one_bad_record_poisons_the_answer() -> None:
    """DNS returning a public AND a private address must be rejected (rebinding-style answer)."""
    with pytest.raises(GitUrlError):
        validate_git_url("https://github.com/a/b", resolves_to("140.82.112.3", "10.0.0.1"))


def test_public_addresses_allowed() -> None:
    assert _is_public("140.82.112.3") and _is_public("2606:50c0:8000::154")


def test_dns_failure_is_a_clean_rejection() -> None:
    def boom(host: str) -> list[str]:
        raise OSError("nxdomain")

    with pytest.raises(GitUrlError, match="could not resolve"):
        validate_git_url("https://github.com/a/b", boom)
    with pytest.raises(GitUrlError, match="did not resolve"):
        validate_git_url("https://github.com/a/b", resolves_to())


# ---- clone_repo: exercised with a fake `git` process (no network) -------------------------
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

from core.gitfetch import clone_repo  # noqa: E402
from core.ingest import IngestError, Limits  # noqa: E402


class FakeGit:
    """Stands in for subprocess.Popen: optionally writes files into the clone dir."""

    instances: list["FakeGit"] = []

    def __init__(self, argv: list[str], **kw: Any) -> None:
        self.argv, self.env = argv, kw["env"]
        self.dest = Path(argv[-1])
        kw["stderr"].write(FakeGit.err)  # git writes its errors to the file it is given
        self._polls = 0
        self.killed = False
        FakeGit.instances.append(self)
        self.dest.mkdir()
        (self.dest / ".git").mkdir()
        (self.dest / "a.py").write_bytes(b"x" * FakeGit.payload)

    err = b""
    payload = 10
    code = 0
    hang = False

    def poll(self) -> int | None:
        self._polls += 1
        return None if (FakeGit.hang or self._polls < 3) and not self.killed else FakeGit.code

    @property
    def returncode(self) -> int:
        return -9 if self.killed else FakeGit.code

    def kill(self) -> None:
        self.killed = True

    def wait(self) -> int:
        return self.returncode


@pytest.fixture
def fake_git(monkeypatch: pytest.MonkeyPatch) -> type[FakeGit]:
    FakeGit.instances, FakeGit.err, FakeGit.payload, FakeGit.code, FakeGit.hang = (
        [],
        b"",
        10,
        0,
        False,
    )
    monkeypatch.setattr("core.gitfetch.subprocess.Popen", FakeGit)
    monkeypatch.setattr("core.gitfetch.time.sleep", lambda s: None)
    return FakeGit


def test_clone_uses_every_hardening_flag_and_pins_the_validated_ip(
    fake_git: type[FakeGit], tmp_path: Path
) -> None:
    out = clone_repo("https://github.com/a/b", tmp_path / "c", resolver=PUBLIC)
    argv = fake_git.instances[0].argv
    joined = " ".join(argv)
    for expected in (
        "protocol.allow=never",
        "protocol.https.allow=always",
        "http.followRedirects=false",
        "http.curloptResolve=github.com:443:140.82.112.3",  # DNS pinned: no rebinding window
        "core.symlinks=false",
        "core.hooksPath=/dev/null",
        "credential.helper=",
        "--depth=1",
        "--no-recurse-submodules",
    ):
        assert expected in joined, expected
    assert argv[-3:-1] == ["--", "https://github.com/a/b"]  # `--` stops option injection
    env = fake_git.instances[0].env
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "GITHUB_TOKEN" not in env and "AWS_SECRET_ACCESS_KEY" not in env  # minimal env
    assert (out / "a.py").exists() and not (out / ".git").exists()  # .git stripped


def test_clone_never_runs_when_the_url_is_unsafe(fake_git: type[FakeGit], tmp_path: Path) -> None:
    with pytest.raises(GitUrlError):
        clone_repo("https://github.com/a/b", tmp_path / "c", resolver=resolves_to("10.0.0.1"))
    assert fake_git.instances == []


def test_clone_size_watchdog_kills_and_cleans_up(fake_git: type[FakeGit], tmp_path: Path) -> None:
    fake_git.payload = 5_000
    with pytest.raises(IngestError, match="max size"):
        clone_repo("https://github.com/a/b", tmp_path / "c", Limits(max_uncompressed_bytes=1000),
                   resolver=PUBLIC)  # fmt: skip
    assert fake_git.instances[0].killed and not (tmp_path / "c").exists()


def test_clone_timeout_kills_and_cleans_up(fake_git: type[FakeGit], tmp_path: Path) -> None:
    fake_git.hang = True
    with pytest.raises(IngestError, match="timed out"):
        clone_repo("https://github.com/a/b", tmp_path / "c", timeout=-1, resolver=PUBLIC)
    assert fake_git.instances[0].killed and not (tmp_path / "c").exists()


def test_clone_failure_reports_stderr_and_cleans_up(
    fake_git: type[FakeGit], tmp_path: Path
) -> None:
    fake_git.code, fake_git.err = 128, b"fatal: repository not found"
    with pytest.raises(IngestError, match="repository not found"):
        clone_repo("https://github.com/a/b", tmp_path / "c", resolver=PUBLIC)
    assert not (tmp_path / "c").exists()


def test_clone_failure_leads_with_a_plain_word_summary(
    fake_git: type[FakeGit], tmp_path: Path
) -> None:
    """Plan §30.3: an error says what happened and what to do next, not just a raw git message."""
    fake_git.code, fake_git.err = 128, b"fatal: repository 'https://github.com/a/b/' not found"
    with pytest.raises(IngestError) as exc:
        clone_repo("https://github.com/a/b", tmp_path / "c", resolver=PUBLIC)
    assert str(exc.value).startswith("Couldn't find this repository.")
    assert "not found" in str(exc.value)  # the raw detail stays attached, not hidden


def test_clone_failure_recognizes_a_private_repository(
    fake_git: type[FakeGit], tmp_path: Path
) -> None:
    fake_git.code, fake_git.err = (
        128,
        b"fatal: could not read Username for 'https://github.com': terminal prompts disabled",
    )
    with pytest.raises(IngestError) as exc:
        clone_repo("https://github.com/a/b", tmp_path / "c", resolver=PUBLIC)
    assert "can only scan public repositories" in str(exc.value)


# ---- clone_repo(ref=...): the GitHub App's PR-head path (Week 30, ADR-0017) ----------------


class FakeGitSteps:
    """Stands in for subprocess.Popen across the ref path's 4 separate git invocations (init,
    remote add, fetch, checkout). Only the `checkout` step materializes files, matching what git
    itself does -- `init`/`remote add`/`fetch` don't populate a working tree."""

    instances: list["FakeGitSteps"] = []
    dest: Path
    payload = 10
    code = 0
    err = b""

    def __init__(self, argv: list[str], **kw: Any) -> None:
        self.argv, self.env = argv, kw["env"]
        kw["stderr"].write(FakeGitSteps.err)
        self._polls = 0
        self.killed = False
        FakeGitSteps.instances.append(self)
        if "checkout" in argv:
            (FakeGitSteps.dest / ".git").mkdir(exist_ok=True)
            (FakeGitSteps.dest / "a.py").write_bytes(b"x" * FakeGitSteps.payload)

    def poll(self) -> int | None:
        self._polls += 1
        return None if self._polls < 2 and not self.killed else FakeGitSteps.code

    @property
    def returncode(self) -> int:
        return -9 if self.killed else FakeGitSteps.code

    def kill(self) -> None:
        self.killed = True

    def wait(self) -> int:
        return self.returncode


@pytest.fixture
def fake_git_steps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> type[FakeGitSteps]:
    FakeGitSteps.instances, FakeGitSteps.err, FakeGitSteps.payload, FakeGitSteps.code = (
        [],
        b"",
        10,
        0,
    )
    FakeGitSteps.dest = tmp_path / "c"
    monkeypatch.setattr("core.gitfetch.subprocess.Popen", FakeGitSteps)
    monkeypatch.setattr("core.gitfetch.time.sleep", lambda s: None)
    return FakeGitSteps


def test_ref_must_be_a_pull_request_head_or_merge_ref(
    fake_git_steps: type[FakeGitSteps], tmp_path: Path
) -> None:
    for bad in ("main", "refs/heads/main", "refs/pull/1/head; rm -rf /", "--upload-pack=evil"):
        with pytest.raises(GitUrlError, match="unsupported ref"):
            clone_repo("https://github.com/a/b", tmp_path / "c", resolver=PUBLIC, ref=bad)
    assert fake_git_steps.instances == []  # never even shelled out


def test_ref_clone_runs_init_remote_fetch_checkout_with_every_hardening_flag(
    fake_git_steps: type[FakeGitSteps], tmp_path: Path
) -> None:
    out = clone_repo(
        "https://github.com/a/b", tmp_path / "c", resolver=PUBLIC, ref="refs/pull/42/head"
    )
    steps = [" ".join(i.argv) for i in fake_git_steps.instances]
    assert len(steps) == 4
    assert "init" in steps[0] and "remote" in steps[1] and "add" in steps[1]
    assert "fetch" in steps[2] and "refs/pull/42/head" in steps[2] and "--depth=1" in steps[2]
    assert "checkout" in steps[3] and "FETCH_HEAD" in steps[3]
    for s in steps:
        assert "http.curloptResolve=github.com:443:140.82.112.3" in s  # SSRF pin, every step
        assert "credential.helper=" in s
    assert (out / "a.py").exists() and not (out / ".git").exists()


def test_ref_clone_failure_midway_cleans_up(
    fake_git_steps: type[FakeGitSteps], tmp_path: Path
) -> None:
    fake_git_steps.code, fake_git_steps.err = 128, b"fatal: couldn't find remote ref"
    with pytest.raises(IngestError, match="couldn't find remote ref"):
        clone_repo(
            "https://github.com/a/b", tmp_path / "c", resolver=PUBLIC, ref="refs/pull/1/head"
        )
    assert not (tmp_path / "c").exists()
