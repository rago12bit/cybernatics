"""Spend guard for model calls: a sliding-window limit per minute and per day.

The API has one shared token, so anyone holding it could otherwise run up the provider bill by clicking
"generate" on every finding. Only real model calls count; cache hits are free. In-memory and per process:
enough for a single API instance, and it fails safe (a restart resets the counters, not the cache).
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections import deque


class LimitExceeded(Exception):
    def __init__(self, retry_after: int, window: str) -> None:
        super().__init__(f"AI suggestion limit reached ({window}); try again in {retry_after}s")
        self.retry_after = retry_after
        self.window = window


class UsageLimiter:
    def __init__(
        self, per_minute: int = 10, per_day: int = 200, clock: object = time.monotonic
    ) -> None:
        self.per_minute, self.per_day = per_minute, per_day
        self._clock = clock  # injectable for tests
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> UsageLimiter:
        return cls(
            int(os.environ.get("BULWARK_LLM_MAX_PER_MINUTE", "10")),
            int(os.environ.get("BULWARK_LLM_MAX_PER_DAY", "200")),
        )

    def acquire(self) -> None:
        """Record one call, or raise LimitExceeded. Call this immediately before the model call."""
        now = self._clock()  # type: ignore[operator]
        with self._lock:
            while self._calls and now - self._calls[0] > 86_400:
                self._calls.popleft()
            day = len(self._calls)
            minute = [t for t in self._calls if now - t <= 60]
            if day >= self.per_day:
                raise LimitExceeded(max(1, math.ceil(86_400 - (now - self._calls[0]))), "per day")
            if len(minute) >= self.per_minute:
                raise LimitExceeded(max(1, math.ceil(60 - (now - minute[0]))), "per minute")
            self._calls.append(now)
