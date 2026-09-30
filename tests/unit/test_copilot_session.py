"""core.copilot.session.CheckoutCache (Week 44 task 3): clone-once-per-conversation, TTL eviction,
and the per-key lock that stops two concurrent first-messages for the SAME new conversation from
both cloning (and leaking the loser's tempdir)."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from core.codeintel.models import CodeGraph
from core.copilot.session import CheckoutCache


class _FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def fake_clone(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str | None]]:
    calls: list[tuple[str, str | None]] = []

    def _clone(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        calls.append((source_ref, ref))
        return dest  # dest already exists (tempfile.mkdtemp), nothing more to do for a fake clone

    monkeypatch.setattr("core.copilot.session.clone_repo", _clone)
    monkeypatch.setattr("core.copilot.session.analyze", lambda root: CodeGraph())
    return calls


def test_first_call_clones_second_call_for_the_same_conversation_reuses(
    fake_clone: list[tuple[str, str | None]],
) -> None:
    cache = CheckoutCache()
    path1, _ = cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    path2, _ = cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    assert path1 == path2
    assert len(fake_clone) == 1


def test_different_conversations_clone_separately(
    fake_clone: list[tuple[str, str | None]],
) -> None:
    cache = CheckoutCache()
    path1, _ = cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    path2, _ = cache.get_or_clone("conv-2", "https://example.com/x.git", None)
    assert path1 != path2
    assert len(fake_clone) == 2


def test_an_expired_entry_is_evicted_and_recloned(
    fake_clone: list[tuple[str, str | None]],
) -> None:
    clock = _FakeClock()
    cache = CheckoutCache(ttl_seconds=100, clock=clock)
    path1, _ = cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    assert path1.exists()
    clock.advance(200)  # past the 100s TTL
    path2, _ = cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    assert not path1.exists()  # the old checkout's temp dir is actually removed
    assert path2 != path1
    assert len(fake_clone) == 2


def test_reusing_within_the_ttl_does_not_reclone(
    fake_clone: list[tuple[str, str | None]],
) -> None:
    clock = _FakeClock()
    cache = CheckoutCache(ttl_seconds=100, clock=clock)
    cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    clock.advance(50)  # well inside the TTL
    cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    assert len(fake_clone) == 1


def test_evict_removes_the_checkout_directory(fake_clone: list[tuple[str, str | None]]) -> None:
    cache = CheckoutCache()
    path, _ = cache.get_or_clone("conv-1", "https://example.com/x.git", None)
    assert path.exists()
    cache.evict("conv-1")
    assert not path.exists()
    assert cache.size() == 0


def test_evicting_an_unknown_conversation_is_a_no_op(
    fake_clone: list[tuple[str, str | None]],
) -> None:
    cache = CheckoutCache()
    cache.evict("no-such-conversation")  # must not raise


def test_concurrent_first_messages_for_the_same_new_conversation_clone_only_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The race this cache exists to prevent: two threads both miss the cache for a brand-new
    conversation id at the same time. Without the per-key lock, both would clone and one
    checkout would be silently leaked (never tracked, never cleaned up)."""
    calls: list[str] = []
    lock = threading.Lock()

    def _slow_clone(source_ref: str, dest: Path, ref: str | None = None) -> Path:
        with lock:
            calls.append(source_ref)
        time.sleep(0.05)  # widen the race window
        return dest

    monkeypatch.setattr("core.copilot.session.clone_repo", _slow_clone)
    monkeypatch.setattr("core.copilot.session.analyze", lambda root: CodeGraph())
    cache = CheckoutCache()
    results: list[Path] = []

    def _worker() -> None:
        path, _ = cache.get_or_clone("conv-shared", "https://example.com/x.git", None)
        results.append(path)

    threads = [threading.Thread(target=_worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 1
    assert len(set(results)) == 1  # every thread got the same checkout path
