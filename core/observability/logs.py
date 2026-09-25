"""Structured JSON logging with a scan_id on every line that belongs to a scan.

The id travels in a context variable, so it follows the work into helper threads (use `in_context`) without
each call site passing it around. When a trace is active its trace_id and span_id are added too, which lets a
log line be found from a trace and the other way round. Secrets that reach a log message are scrubbed with the
same detector the LLM layer uses; newlines cannot forge a second log line because the output is JSON.
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, TypeVar

from core.llm.scrub import scrub_secrets

T = TypeVar("T")

scan_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "bulwark_scan_id", default=None
)
tool_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("bulwark_tool", default=None)

MAX_FIELD = 8000
# Attributes every LogRecord has: anything else came from `extra=` and is logged as its own field.
_STANDARD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {
    "message",
    "asctime",
    "taskName",
}
_OWN = {
    "scan_id",
    "tool",
    "trace_id",
    "span_id",
    "color_message",
}  # color_message: uvicorn's ANSI copy


@contextmanager
def bind_scan(scan_id: str) -> Iterator[None]:
    token = scan_id_var.set(scan_id)
    try:
        yield
    finally:
        scan_id_var.reset(token)


@contextmanager
def bind_tool(tool: str) -> Iterator[None]:
    token = tool_var.set(tool)
    try:
        yield
    finally:
        tool_var.reset(token)


def in_context(fn: Callable[..., T]) -> Callable[..., T]:
    """Wrap `fn` so it runs with the CURRENT context (scan id, active span) even in another thread."""
    ctx = contextvars.copy_context()

    def run(*args: Any, **kwargs: Any) -> T:
        return ctx.copy().run(fn, *args, **kwargs)

    return run


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        from core.observability.tracing import current_ids

        record.scan_id = scan_id_var.get()
        record.tool = tool_var.get()
        record.trace_id, record.span_id = current_ids()
        return True


def _clean(text: str) -> str:
    scrubbed, _ = scrub_secrets(text)
    return scrubbed[:MAX_FIELD]


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - a bad format string must not lose the line
            message = str(record.msg)
        out: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": _clean(message),
        }
        for key in ("scan_id", "tool", "trace_id", "span_id"):
            value = getattr(record, key, None)
            if value:
                out[key] = value
        for key, value in vars(record).items():
            if key not in _STANDARD and key not in _OWN and not key.startswith("_"):
                out[key] = (
                    value
                    if isinstance(value, (int, float, bool, type(None)))
                    else _clean(str(value))
                )
        if record.exc_info:
            out["exception"] = _clean(self.formatException(record.exc_info))
        return json.dumps(out, ensure_ascii=False, default=str)


def configure_logging(fmt: str | None = None, level: str | None = None) -> None:
    """Install the root handler. `fmt` is "json" or "text"; the default comes from BULWARK_LOG_FORMAT."""
    import os

    fmt = (fmt or os.environ.get("BULWARK_LOG_FORMAT") or "json").lower()
    lvl = (level or os.environ.get("BULWARK_LOG_LEVEL") or "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(ContextFilter())
    if fmt == "text":
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(scan_id)s] %(message)s")
        )
    else:
        handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(getattr(logging, lvl, logging.INFO))
