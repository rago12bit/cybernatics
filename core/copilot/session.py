"""Per-conversation checkout + code-graph caching for the security copilot (Week 44 task 3): clone
and analyze once when a conversation starts, reuse for every later message in it, rather than
re-cloning per message -- a chat panel answering several questions in a row should not pay a full
clone+analyze cost each time.

Process-local only (an in-memory dict): a multi-worker deployment needs sticky routing per
conversation, or a shared cache, to get this benefit across every worker -- a disclosed limitation,
not a correctness bug (a cache miss just re-clones, same as a cold start, so answers are still
correct even when the cache doesn't help).

The checkout is a snapshot as of the conversation's first message: a scan that finishes mid-chat does
not change what later messages in that same conversation see. A new conversation always sees the
asset's current latest scan.
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from core.codeintel import analyze
from core.codeintel.models import CodeGraph
from core.gitfetch import clone_repo

DEFAULT_TTL_SECONDS = 1800  # 30 minutes idle


@dataclass
class _CachedCheckout:
    path: Path
    graph: CodeGraph
    last_used: float


class CheckoutCache:
    """One process's worth of cached checkouts, keyed by conversation id."""

    def __init__(
        self, ttl_seconds: float = DEFAULT_TTL_SECONDS, clock: object = time.monotonic
    ) -> None:
        self._ttl = ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: dict[str, _CachedCheckout] = {}
        self._clone_locks: dict[str, threading.Lock] = {}

    def _evict_expired(self) -> None:
        now = self._clock()  # type: ignore[operator]
        expired = [cid for cid, e in self._entries.items() if now - e.last_used > self._ttl]
        for cid in expired:
            entry = self._entries.pop(cid)
            shutil.rmtree(entry.path, ignore_errors=True)

    def get_or_clone(
        self, conversation_id: str, source_ref: str, ref: str | None
    ) -> tuple[Path, CodeGraph]:
        with self._lock:
            self._evict_expired()
            entry = self._entries.get(conversation_id)
            if entry is not None:
                entry.last_used = self._clock()  # type: ignore[operator]
                return entry.path, entry.graph
            conv_lock = self._clone_locks.setdefault(conversation_id, threading.Lock())

        # One lock per conversation id: two concurrent first-messages for the SAME conversation
        # serialize here (so only one clone happens, not two with the loser's tempdir leaked);
        # different conversations use different locks and still clone in parallel.
        with conv_lock:
            with self._lock:
                entry = self._entries.get(conversation_id)
                if entry is not None:
                    entry.last_used = self._clock()  # type: ignore[operator]
                    return entry.path, entry.graph
            checkout = Path(tempfile.mkdtemp(prefix="bulwark-copilot-"))
            try:
                clone_repo(source_ref, checkout, ref=ref)
                graph = analyze(checkout)
            except Exception:
                shutil.rmtree(checkout, ignore_errors=True)
                raise
            with self._lock:
                self._entries[conversation_id] = _CachedCheckout(checkout, graph, self._clock())  # type: ignore[operator]
                self._clone_locks.pop(conversation_id, None)
            return checkout, graph

    def evict(self, conversation_id: str) -> None:
        """Explicitly drop one conversation's checkout (e.g. the conversation was deleted)."""
        with self._lock:
            entry = self._entries.pop(conversation_id, None)
        if entry is not None:
            shutil.rmtree(entry.path, ignore_errors=True)

    def size(self) -> int:
        return len(self._entries)


_default_cache: CheckoutCache | None = None


def default_cache() -> CheckoutCache:
    global _default_cache
    if _default_cache is None:
        _default_cache = CheckoutCache()
    return _default_cache
