"""Scan progress events. Workers publish; the API's WebSocket endpoint relays to clients."""

from __future__ import annotations

import json
from typing import Any, Protocol

import redis


def channel(scan_id: str) -> str:
    return f"bulwark:scan:{scan_id}"


class EventPublisher(Protocol):
    def publish(self, scan_id: str, event: dict[str, Any]) -> None: ...


class RedisPublisher:
    def __init__(self, url: str) -> None:
        self._r: Any = redis.Redis.from_url(url)

    def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        try:
            self._r.publish(channel(scan_id), json.dumps(event))
        except redis.RedisError:
            pass  # progress is best-effort; the database is the source of truth


class MemoryPublisher:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        self.events.append((scan_id, event))
