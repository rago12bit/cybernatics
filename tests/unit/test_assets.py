from __future__ import annotations

from core.assets import asset_key


def test_git_urls_that_are_the_same_repo_get_the_same_key() -> None:
    variants = [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "https://github.com/owner/repo/",
        "https://GitHub.com/owner/repo",
    ]
    keys = {asset_key("git", u) for u in variants}
    assert len(keys) == 1


def test_git_urls_are_case_sensitive_on_the_path() -> None:
    # only the host is case-normalized; GitHub paths are case-sensitive
    assert asset_key("git", "https://github.com/Owner/Repo") != asset_key(
        "git", "https://github.com/owner/repo"
    )


def test_different_repos_get_different_keys() -> None:
    assert asset_key("git", "https://github.com/a/b") != asset_key("git", "https://github.com/a/c")


def test_archive_identity_is_the_label_as_given() -> None:
    assert asset_key("archive", "my-project.zip") == asset_key("archive", "my-project.zip")
    assert asset_key("archive", "my-project.zip") != asset_key("archive", "other.zip")


def test_archive_label_is_stripped_but_not_otherwise_normalized() -> None:
    assert asset_key("archive", "  my-project.zip  ") == "my-project.zip"
    # unlike git URLs, case is preserved: a filename's case is meaningful on most filesystems
    assert asset_key("archive", "MyProject.zip") != asset_key("archive", "myproject.zip")


def test_web_identity_is_the_host_regardless_of_scheme_path_or_case() -> None:
    variants = [
        "example.com",
        "https://example.com",
        "https://example.com/",
        "https://Example.com",
        "http://example.com/some/path",
    ]
    keys = {asset_key("web", v) for v in variants}
    assert keys == {"example.com"}


def test_web_identity_differs_by_host() -> None:
    assert asset_key("web", "example.com") != asset_key("web", "example.org")
    assert asset_key("web", "sub.example.com") != asset_key("web", "example.com")
