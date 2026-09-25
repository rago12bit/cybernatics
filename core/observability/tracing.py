"""OpenTelemetry spans across the scan pipeline, optional and never in the way.

Without the SDK installed, or without OTEL_EXPORTER_OTLP_ENDPOINT set, `span()` does nothing and costs almost
nothing. A tracing failure (bad endpoint, exporter error) must never fail a scan, so setup swallows and logs it.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

log = logging.getLogger(__name__)

try:  # the API package alone is tiny and gives no-op spans
    from opentelemetry import trace as _trace
    from opentelemetry.trace import Status, StatusCode

    _HAVE_API = True
except ImportError:  # pragma: no cover - exercised only where the package is absent
    _HAVE_API = False

_configured = False


def setup_tracing(service_name: str) -> bool:
    """Export spans over OTLP/HTTP if an endpoint is configured. Returns True when tracing is live."""
    global _configured
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint or _configured or not _HAVE_API:
        return _configured
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        _trace.set_tracer_provider(provider)
        _configured = True
        log.info("tracing enabled", extra={"otlp_endpoint": endpoint})
    except Exception:  # noqa: BLE001
        log.warning("tracing could not be set up; continuing without it", exc_info=True)
    return _configured


def shutdown_tracing() -> None:
    if _configured and _HAVE_API:
        provider = _trace.get_tracer_provider()
        flush = getattr(provider, "force_flush", None)
        if flush:
            flush(5000)


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """A span named `name`; an exception marks it as an error and still propagates."""
    if not _HAVE_API:
        yield None
        return
    tracer = _trace.get_tracer("bulwark")
    with tracer.start_as_current_span(name) as sp:
        for k, v in attributes.items():
            if v is not None:
                sp.set_attribute(k, v if isinstance(v, (str, bool, int, float)) else str(v))
        try:
            yield sp
        except Exception as exc:
            sp.set_status(Status(StatusCode.ERROR, str(exc)[:200]))
            raise


def set_attributes(sp: Any, **attributes: Any) -> None:
    if sp is not None:
        for k, v in attributes.items():
            if v is not None:
                sp.set_attribute(k, v if isinstance(v, (str, bool, int, float)) else str(v))


def mark_error(sp: Any, message: str) -> None:
    """Flag a span failed without raising (a tool that timed out is an outcome, not an exception)."""
    if sp is not None and _HAVE_API:
        sp.set_status(Status(StatusCode.ERROR, message[:200]))


def current_ids() -> tuple[str | None, str | None]:
    """(trace_id, span_id) of the active span as hex, for log correlation."""
    if not _HAVE_API:
        return None, None
    ctx = _trace.get_current_span().get_span_context()
    if not ctx.is_valid:
        return None, None
    return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
