"""core/cache.py: the content-addressed result cache (plan §20.1)."""

from __future__ import annotations

from pathlib import Path

from core.cache import CacheKey, ResultCache, hash_file, hash_files
from core.models import Category, Finding, Location, Taxonomy


def fake_finding(path: str) -> Finding:
    return Finding(
        id=f"f:{path}",
        title="t",
        description="d",
        location=Location(path, 1, 1),
        taxonomy=Taxonomy(Category.SAST),
    )


def test_cache_round_trips_findings(tmp_path: Path) -> None:
    cache = ResultCache(tmp_path)
    key = CacheKey("bandit", "1.7.10", "default", "abc123")
    assert cache.get(key) is None
    assert cache.misses == 1
    findings = [fake_finding("a.py"), fake_finding("b.py")]
    cache.set(key, findings)
    got = cache.get(key)
    assert got is not None
    assert [f.id for f in got] == [f.id for f in findings]
    assert cache.hits == 1


def test_cache_key_digest_is_sensitive_to_every_component() -> None:
    base = CacheKey("bandit", "1.7.10", "default", "abc123")
    variants = [
        CacheKey("semgrep", "1.7.10", "default", "abc123"),
        CacheKey("bandit", "1.7.11", "default", "abc123"),
        CacheKey("bandit", "1.7.10", "other", "abc123"),
        CacheKey("bandit", "1.7.10", "default", "xyz789"),
    ]
    digests = {base.digest(), *[v.digest() for v in variants]}
    assert len(digests) == 5  # every variant is a distinct entry -- no accidental collisions


def test_an_empty_finding_list_is_a_real_cacheable_result(tmp_path: Path) -> None:
    """A file with zero findings from a tool is a valid, valuable thing to cache -- most files
    have none -- and must round-trip as an empty list, not be mistaken for "never scanned"."""
    cache = ResultCache(tmp_path)
    key = CacheKey("bandit", "1.7.10", "default", "abc123")
    cache.set(key, [])
    assert cache.get(key) == []


def test_corrupt_entry_is_a_miss_not_a_crash(tmp_path: Path) -> None:
    cache = ResultCache(tmp_path)
    key = CacheKey("bandit", "1.7.10", "default", "abc123")
    path = cache._path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not json", encoding="utf-8")
    assert cache.get(key) is None
    assert cache.misses == 1


def test_unwritable_cache_dir_does_not_raise(tmp_path: Path) -> None:
    cache = ResultCache(tmp_path / "no" / "such" / "writable" / "place")
    cache.root.parent.mkdir(parents=True)
    cache.root.parent.chmod(0o500)  # read+execute only: mkdir inside it must fail
    try:
        cache.set(CacheKey("bandit", "1", "default", "x"), [fake_finding("a.py")])  # no raise
    finally:
        cache.root.parent.chmod(0o700)


def test_hash_file_is_content_not_path_dependent(tmp_path: Path) -> None:
    a, b = tmp_path / "a.py", tmp_path / "sub" / "b.py"
    b.parent.mkdir()
    a.write_text("x = 1\n")
    b.write_text("x = 1\n")
    assert hash_file(a) == hash_file(b)
    b.write_text("x = 2\n")
    assert hash_file(a) != hash_file(b)


def test_hash_files_is_order_independent(tmp_path: Path) -> None:
    a, b = tmp_path / "a.lock", tmp_path / "b.lock"
    a.write_text("1")
    b.write_text("2")
    assert hash_files([a, b]) == hash_files([b, a])
    before = hash_files([a, b])
    b.write_text("3")
    assert hash_files([a, b]) != before  # a content change is a different combined hash
    assert hash_files([a, b]) != hash_files([a])  # dropping a file changes it too
