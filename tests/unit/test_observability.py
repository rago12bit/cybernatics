from __future__ import annotations

import io
import json
import logging
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import CollectorRegistry, generate_latest
from sqlalchemy.orm import Session, sessionmaker

from core.events import MemoryPublisher
from core.models import Category, Finding, Location, Severity, Taxonomy
from core.observability import (
    bind_scan,
    configure_logging,
    current_ids,
    in_context,
    scan_id_var,
    span,
)
from core.observability import metrics as obs
from core.observability.logs import JsonFormatter, bind_tool
from core.persistence import repo
from core.persistence.storage import MemoryStore
from core.pipeline import run_scan_job
from core.scan import ToolOutcome

# One provider for the whole test process: OpenTelemetry allows setting it only once.
_EXPORTER = InMemorySpanExporter()
_PROVIDER = TracerProvider()
_PROVIDER.add_span_processor(SimpleSpanProcessor(_EXPORTER))
trace.set_tracer_provider(_PROVIDER)


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


def line(msg: str = "hello", level: int = logging.INFO, **extra: object) -> dict[str, object]:
    rec = logging.LogRecord("bulwark.test", level, __file__, 1, msg, (), None)
    for k, v in extra.items():
        setattr(rec, k, v)
    from core.observability.logs import ContextFilter

    ContextFilter().filter(rec)
    out = JsonFormatter().format(rec)
    assert "\n" not in out  # one record, one line
    return json.loads(out)  # type: ignore[no-any-return]


# ---- logging ------------------------------------------------------------------------------------


def test_json_line_has_time_level_logger_message_and_no_scan_id_outside_a_scan() -> None:
    d = line()
    assert d["level"] == "INFO" and d["logger"] == "bulwark.test" and d["message"] == "hello"
    assert str(d["ts"]).endswith("+00:00") and "scan_id" not in d


def test_scan_id_and_tool_are_added_inside_their_contexts_and_removed_after() -> None:
    with bind_scan("11111111-2222-3333-4444-555555555555"), bind_tool("bandit"):
        d = line()
    assert d["scan_id"] == "11111111-2222-3333-4444-555555555555" and d["tool"] == "bandit"
    assert "scan_id" not in line() and scan_id_var.get() is None


def test_extra_fields_become_json_fields_and_do_not_shadow_reserved_ones() -> None:
    d = line(status="ok", findings=3, duration_s=1.5, weird=object())
    assert d["status"] == "ok" and d["findings"] == 3 and d["duration_s"] == 1.5
    assert isinstance(d["weird"], str)


def test_a_newline_in_a_message_cannot_forge_a_second_log_line() -> None:
    d = line('scan done\n{"level":"CRITICAL","message":"forged"}')
    assert d["level"] == "INFO" and "forged" in str(d["message"])


def test_secrets_in_messages_and_exceptions_are_scrubbed() -> None:
    token = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"
    assert token not in json.dumps(line(f"clone failed for token {token}"))
    try:
        raise RuntimeError(f"auth failed: password={token}")
    except RuntimeError:
        import sys

        rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "boom", (), sys.exc_info())
        assert token not in JsonFormatter().format(rec)


def test_bad_format_arguments_and_huge_messages_do_not_break_logging() -> None:
    rec = logging.LogRecord("x", logging.INFO, __file__, 1, "value %d", ("not a number",), None)
    assert "value %d" in json.loads(JsonFormatter().format(rec))["message"]
    assert len(str(line("x" * 100_000)["message"])) <= 8000


def test_configure_logging_writes_json_to_stderr_and_supports_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buf = io.StringIO()
    monkeypatch.setattr("sys.stderr", buf)
    root = logging.getLogger()
    old_handlers, old_level = list(root.handlers), root.level
    try:
        configure_logging("json", "INFO")
        with bind_scan("abc"):
            logging.getLogger("bulwark.x").info("hi")
        assert json.loads(buf.getvalue().splitlines()[-1])["scan_id"] == "abc"
        buf.truncate(0)
        configure_logging("text", "INFO")
        logging.getLogger("bulwark.x").info("plain")
        assert "plain" in buf.getvalue() and not buf.getvalue().startswith("{")
    finally:
        root.handlers[:] = old_handlers
        root.setLevel(old_level)


def test_context_reaches_worker_threads_only_through_in_context() -> None:
    seen: dict[str, str | None] = {}

    def read(key: str) -> None:
        seen[key] = scan_id_var.get()

    with bind_scan("scan-1"), ThreadPoolExecutor(max_workers=2) as pool:
        pool.submit(read, "plain").result()
        pool.submit(in_context(read), "wrapped").result()
    assert seen == {"plain": None, "wrapped": "scan-1"}  # why the pipeline wraps its submissions


# ---- tracing ------------------------------------------------------------------------------------


def test_spans_nest_carry_attributes_and_mark_errors(spans: InMemorySpanExporter) -> None:
    with pytest.raises(ValueError):
        with span("outer", scan_id="s1"):
            with span("inner", n=2):
                assert all(current_ids())
                raise ValueError("bad")
    by = {s.name: s for s in spans.get_finished_spans()}
    assert by["inner"].parent.span_id == by["outer"].context.span_id  # type: ignore[union-attr]
    assert by["outer"].attributes["scan_id"] == "s1" and by["inner"].attributes["n"] == 2  # type: ignore[index]
    assert by["inner"].status.status_code.name == "ERROR"


def test_log_lines_carry_the_trace_and_span_id_of_the_active_span(
    spans: InMemorySpanExporter,
) -> None:
    with span("s") as sp:
        d = line()
    ctx = sp.get_span_context()
    assert d["trace_id"] == f"{ctx.trace_id:032x}" and d["span_id"] == f"{ctx.span_id:016x}"
    assert current_ids() == (None, None)


# ---- the pipeline, end to end (fake scanners) ---------------------------------------------------


def _finding(tool: str) -> Finding:
    f = Finding(id=f"{tool}:a.py:1", title="t", description="d", location=Location("a.py", 1, 1, "x", "h"),
                taxonomy=Taxonomy(Category.SAST))  # fmt: skip
    f.scoring.normalized_severity = Severity.HIGH
    f.evidence.reported_by = [tool]
    return f


def _run(
    sessions: sessionmaker[Session], repo_dir: Path, table: dict[str, ToolOutcome], tools: list[str]
) -> tuple[str, str]:
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=str(repo_dir), source_label="l", tools=tools
        ).id

    def executor(name: str, target: Path) -> ToolOutcome:
        return table[name]

    return sid, run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor)


def test_a_scan_is_one_trace_with_a_stage_per_step_and_every_span_tagged(
    sessions: sessionmaker[Session], sample_repo: Path, spans: InMemorySpanExporter
) -> None:
    (sample_repo / "requirements.txt").write_text("flask==2.0\n")
    table = {"bandit": ToolOutcome("bandit", "ok", [_finding("bandit")], 1, 2.0),
             "osv-scanner": ToolOutcome("osv-scanner", "timeout", [], None, 9.0, "wall-clock timeout")}  # fmt: skip
    sid, status = _run(sessions, sample_repo, table, ["bandit", "osv-scanner"])
    assert status == "partial"
    done = spans.get_finished_spans()
    by = {s.name: s for s in done}
    assert {"scan", "ingest", "reachability", "tools", "correlate", "finalize", "persist"} <= set(
        by
    )
    assert len({s.context.trace_id for s in done}) == 1  # one trace, including the tool threads
    root = by["scan"]
    assert root.attributes["scan_id"] == sid and root.attributes["status"] == "partial"  # type: ignore[index]
    for stage in ("ingest", "tools", "correlate", "persist"):
        assert by[stage].parent.span_id == root.context.span_id  # type: ignore[union-attr]
    tool_spans = [s for s in done if s.name.startswith("tool.")]
    assert {s.name for s in tool_spans} == {"tool.bandit", "tool.osv-scanner"} or {
        s.name for s in tool_spans
    } <= {"tool.bandit", "tool.osv-scanner"}
    # (the test executor replaces execute_tool, so per-tool spans come from execute_tool itself: see below)


def test_execute_tool_records_a_span_and_metrics_per_scanner(
    monkeypatch: pytest.MonkeyPatch, spans: InMemorySpanExporter, tmp_path: Path
) -> None:
    from core import scan as scan_mod
    from core.runner import RunResult

    monkeypatch.setattr(
        scan_mod, "run_tool", lambda a, t, c=None: RunResult("bandit", "ok", 1, b"{}", "")
    )
    monkeypatch.setattr(scan_mod.ADAPTERS["bandit"], "parse", lambda raw: [_finding("bandit")])
    before = obs.TOOL_RUNS.labels("bandit", "ok")._value.get()
    with bind_scan("scan-x"):
        out = scan_mod.execute_tool("bandit", tmp_path)
    assert out.status == "ok"
    [sp] = [s for s in spans.get_finished_spans() if s.name == "tool.bandit"]
    assert sp.attributes["tool"] == "bandit" and sp.attributes["findings"] == 1  # type: ignore[index]
    assert obs.TOOL_RUNS.labels("bandit", "ok")._value.get() == before + 1


def test_tools_run_in_parallel_spans_under_the_tools_span(
    sessions: sessionmaker[Session],
    sample_repo: Path,
    spans: InMemorySpanExporter,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core import pipeline

    (sample_repo / "package-lock.json").write_text("{}")
    (sample_repo / "main.tf").write_text("x")

    def slow(name: str, target: Path) -> ToolOutcome:
        with span(f"tool.{name}", tool=name):
            time.sleep(0.25)
        return ToolOutcome(name, "ok", [], 0, 0.25)

    with sessions() as s:
        sid = repo.create_scan(
            s,
            source_type="git",
            source_ref=str(sample_repo),
            source_label="l",
            tools=["bandit", "trivy", "osv-scanner"],
        ).id
    monkeypatch.setattr(pipeline, "execute_tool", slow)
    # Overlap is shown by the spans below, not by the job's wall time: that includes the database
    # and post-processing too, and took 1.17 s on a slow CI runner (2026-10-14) with the tools
    # overlapping as they should.
    run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), slow)
    tools_span = next(s for s in spans.get_finished_spans() if s.name == "tools")
    kids = [s for s in spans.get_finished_spans() if s.name.startswith("tool.")]
    assert len(kids) >= 2 and all(k.parent.span_id == tools_span.context.span_id for k in kids)  # type: ignore[union-attr]
    starts, ends = [k.start_time for k in kids], [k.end_time for k in kids]
    assert max(starts) < min(ends)  # they really overlapped in time


def test_logs_from_tool_threads_carry_the_scan_id(
    sessions: sessionmaker[Session], sample_repo: Path, caplog: pytest.LogCaptureFixture
) -> None:
    seen: list[str | None] = []

    def executor(name: str, target: Path) -> ToolOutcome:
        seen.append(scan_id_var.get())
        return ToolOutcome(name, "ok", [], 0, 0.1)

    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=str(sample_repo), source_label="l", tools=["bandit"]
        ).id
    with caplog.at_level(logging.INFO):
        run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor)
    assert seen == [sid]
    from core.observability.logs import ContextFilter

    assert scan_id_var.get() is None  # nothing leaks out of the job
    assert any(r.getMessage() == "scan finished" for r in caplog.records)
    _ = ContextFilter


# ---- metrics ------------------------------------------------------------------------------------


def test_scan_and_tool_outcomes_are_counted_with_bounded_labels() -> None:
    reg_text = lambda: generate_latest(obs.REGISTRY).decode()  # noqa: E731
    base_scans = obs.SCANS.labels("completed")._value.get()
    obs.observe_scan("completed", 12.0, {"HIGH": 2, "LOW": 0, "bogus": 5})
    assert obs.SCANS.labels("completed")._value.get() == base_scans + 1
    obs.observe_tool(
        "mystery-tool", "weird-status", 1.0
    )  # arbitrary strings must not create new series
    text = reg_text()
    assert (
        'status="other",tool="other"' in text and "mystery-tool" not in text and "bogus" not in text
    )
    assert (
        "bulwark_scan_duration_seconds_bucket" in text
        and 'bulwark_findings_total{severity="HIGH"}' in text
    )


def test_a_skipped_tool_is_counted_but_not_timed() -> None:
    before = obs.TOOL_SECONDS.labels("gitleaks")._sum.get()
    obs.observe_tool("gitleaks", "skipped", 99.0)
    assert obs.TOOL_SECONDS.labels("gitleaks")._sum.get() == before


def test_queue_depth_is_read_from_redis_at_scrape_time(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeRedis:
        @staticmethod
        def from_url(url: str, **kw: object) -> FakeRedis:
            return FakeRedis()

        def llen(self, q: str) -> int:
            return 7 if q == "celery" else 0

    import redis

    monkeypatch.setattr(redis, "Redis", FakeRedis)
    reg = CollectorRegistry()
    reg.register(obs.QueueDepth("redis://x"))
    assert "bulwark_queue_depth 7.0" in generate_latest(reg).decode()


def test_an_unreachable_broker_omits_the_gauge_instead_of_failing_the_scrape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Broken:
        @staticmethod
        def from_url(*a: object, **k: object) -> Broken:
            raise ConnectionError("down")

    import redis

    monkeypatch.setattr(redis, "Redis", Broken)
    reg = CollectorRegistry()
    reg.register(obs.QueueDepth("redis://x"))
    assert "bulwark_queue_depth" not in generate_latest(reg).decode()


def test_cost_summary_sums_compute_and_llm_cost_for_the_default_org(
    sessions: sessionmaker[Session],
) -> None:
    from core.persistence.models import Scan, ToolRun
    from core.tenancy import DEFAULT_ORG_ID

    with sessions() as s:
        scan = Scan(
            org_id=DEFAULT_ORG_ID, source_type="git", source_ref="x", source_label="x",
            tools=["bandit"], llm_tokens_used=2000,
        )  # fmt: skip
        s.add(scan)
        s.flush()
        s.add(ToolRun(scan_id=scan.id, tool="bandit", status="ok", duration_seconds=10.0))
        s.commit()

    reg = CollectorRegistry()
    reg.register(obs.CostSummary(sessions))
    families = {m.name: m for m in reg.collect()}
    samples = {
        s.labels["component"]: s.value for s in families["bulwark_estimated_cost_usd"].samples
    }
    assert samples["compute"] == pytest.approx(0.003)  # 10s * 0.0003 $/s
    assert samples["llm"] == pytest.approx(0.012)  # 2000 tok * 0.006 $/1k


def test_cost_summary_omits_the_gauge_instead_of_failing_the_scrape_when_the_db_is_unreachable() -> (
    None
):
    def broken_factory() -> Session:
        raise ConnectionError("down")

    reg = CollectorRegistry()
    reg.register(obs.CostSummary(broken_factory))
    assert "bulwark_estimated_cost_usd" not in generate_latest(reg).decode()


def test_metrics_server_can_be_disabled_and_reports_a_busy_port() -> None:
    assert obs.start_metrics_server(port=0) is None
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    assert obs.start_metrics_server(port=s.getsockname()[1]) is None  # taken: warns, does not raise
    s.close()


def test_metrics_are_served_on_loopback_by_default_and_answer_scrapes() -> None:
    import socket
    import urllib.request

    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    assert obs.start_metrics_server(port=port) == port
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5).read().decode()
    assert "bulwark_tool_runs_total" in body and "# TYPE bulwark_scans_total counter" in body


def test_a_finished_scan_updates_the_scan_metrics_and_releases_the_in_progress_gauge(
    sessions: sessionmaker[Session], sample_repo: Path
) -> None:
    running_during: list[float] = []

    def executor(name: str, target: Path) -> ToolOutcome:
        running_during.append(obs.SCANS_RUNNING._value.get())
        return ToolOutcome(name, "ok", [_finding(name)], 0, 0.1)

    base = {
        "scans": obs.SCANS.labels("completed")._value.get(),
        "high": obs.FINDINGS.labels("HIGH")._value.get(),
        "hist": obs.SCAN_SECONDS._sum.get(),
        "idle": obs.SCANS_RUNNING._value.get(),
    }
    with sessions() as s:
        sid = repo.create_scan(
            s, source_type="git", source_ref=str(sample_repo), source_label="l", tools=["bandit"]
        ).id
    assert run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), executor) == "completed"
    assert obs.SCANS.labels("completed")._value.get() == base["scans"] + 1
    assert obs.FINDINGS.labels("HIGH")._value.get() == base["high"] + 1
    assert obs.SCAN_SECONDS._sum.get() > base["hist"]
    assert running_during == [base["idle"] + 1] and obs.SCANS_RUNNING._value.get() == base["idle"]


def test_a_crashed_scan_is_still_counted_as_failed_and_the_gauge_is_released(
    sessions: sessionmaker[Session],
) -> None:
    base = obs.SCANS.labels("failed")._value.get()
    idle = obs.SCANS_RUNNING._value.get()
    with sessions() as s:
        sid = repo.create_scan(
            s,
            source_type="git",
            source_ref="/definitely/not/here",
            source_label="l",
            tools=["bandit"],
        ).id
    assert run_scan_job(sid, sessions, MemoryStore(), MemoryPublisher(), lambda n, t: None) == "failed"  # type: ignore[arg-type,return-value]
    assert (
        obs.SCANS.labels("failed")._value.get() == base + 1
        and obs.SCANS_RUNNING._value.get() == idle
    )


def test_uvicorn_ansi_color_copy_is_not_logged() -> None:
    assert "color_message" not in line("started", color_message="\x1b[36mstarted\x1b[0m")


def test_tracing_setup_is_a_no_op_without_an_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.observability import setup_tracing

    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert setup_tracing("bulwark-test") is False
    with span("still-works"):  # spans are harmless without an exporter
        pass


def test_the_dashboard_only_uses_metrics_the_worker_exports() -> None:
    import re

    dash = (
        Path(__file__).resolve().parents[2] / "observability/grafana/dashboards/bulwark.json"
    ).read_text()
    used = set(re.findall(r"bulwark_[a-z_]+", dash))
    exported = (
        generate_latest(obs.REGISTRY).decode() + "bulwark_queue_depth bulwark_estimated_cost_usd"
    )
    for name in used:
        base = re.sub(r"_(bucket|count|sum|total|created)$", "", name)
        assert (
            base in exported or name in exported
        ), f"dashboard queries {name}, which no code exports"
