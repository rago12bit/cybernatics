import pytest

from core.gitfetch import GitUrlError, _is_public, validate_git_url


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
import io  # noqa: E402
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
        self.stderr = io.BytesIO(FakeGit.err)
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
