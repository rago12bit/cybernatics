"""Bulwark CLI: `bulwark scan <path> --tools bandit --format json`."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import typer

from core.ingest import IngestError
from core.scan import ADAPTERS, scan
from core.source import materialize

app = typer.Typer(help="Bulwark: unified security scanning.", no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Bulwark: unified security scanning."""


@app.command("scan")
def scan_cmd(
    source: str = typer.Argument(..., help="Directory, .zip/.tar.gz archive, or public Git URL."),
    tools: str = typer.Option(",".join(ADAPTERS), help="Comma-separated tool names."),
    fmt: str = typer.Option("json", "--format", help="json (default), sarif, html or pdf."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write here instead of stdout."
    ),
    distributed: bool = typer.Option(False, "--distributed", help="Run tools on Celery workers."),
) -> None:
    if fmt not in ("json", "sarif", "html", "pdf"):
        raise typer.BadParameter("use json, sarif, html or pdf", param_hint="--format")
    if fmt == "pdf" and output is None:
        raise typer.BadParameter("pdf is binary: pass --output report.pdf", param_hint="--output")
    names = [t.strip() for t in tools.split(",") if t.strip()]
    try:
        with materialize(source) as workspace:
            if distributed:
                from core.tasks import celery_executor

                result = scan(workspace, names, celery_executor)
            else:
                result = scan(workspace, names)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--tools") from exc
    except IngestError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    if fmt == "json":
        text = json.dumps(
            {
                "tool_status": result.tool_status,
                "stats": {
                    "raw_findings": result.stats.raw,
                    "unique_findings": result.stats.unique,
                    "dedup_rate": round(result.stats.dedup_rate, 3),
                },
                "findings": [f.to_dict() for f in result.findings],
            },
            indent=2,
        )
        data = text.encode()
    else:
        from core.export import ReportData, render

        counts = Counter(f.scoring.normalized_severity.value for f in result.findings)
        failed = any(t.get("status") not in ("ok", "skipped") for t in result.tool_status.values())
        report = ReportData(
            scan_id="local",
            source_label=source if "://" in source else Path(source).name or source,
            status="partial" if failed else "completed",
            finished_at=None,
            tool_status={
                k: {**v, "findings": v.get("findings", 0)} for k, v in result.tool_status.items()
            },
            raw_findings=result.stats.raw,
            unique_findings=result.stats.unique,
            dedup_rate=result.stats.dedup_rate,
            severity_counts=dict(counts),
            findings=[f.to_dict() for f in result.findings],
        )
        data = render(fmt, report)
    if output:
        output.write_bytes(data)
        typer.echo(f"wrote {output} ({len(data)} bytes)", err=True)
    else:
        typer.echo(data.decode())


kb_app = typer.Typer(help="Remediation knowledge base: CWE + OWASP cheat-sheet corpus in pgvector.")
app.add_typer(kb_app, name="kb")


@kb_app.command("load")
def kb_load() -> None:
    """(Re)build the search index from the committed corpus. Idempotent; takes about a second."""
    from core.persistence.db import get_session_factory
    from core.rag.corpus_io import read_corpus
    from core.rag.store import load_corpus

    with get_session_factory()() as s:
        info = load_corpus(s, read_corpus())
    typer.echo(json.dumps(info))


@kb_app.command("stats")
def kb_stats() -> None:
    from core.persistence.db import get_session_factory
    from core.rag.store import KnowledgeBase

    with get_session_factory()() as s:
        typer.echo(json.dumps(KnowledgeBase(s).stats(), indent=2))


@kb_app.command("search")
def kb_search(
    query: str = typer.Argument(..., help="What to look for, in plain words."),
    k: int = typer.Option(5, "-k", help="How many results."),
    kind: str | None = typer.Option(None, help="cwe or cheatsheet."),
) -> None:
    """Semantic search over the corpus (for checking what a finding would be given)."""
    from core.persistence.db import get_session_factory
    from core.rag.store import KnowledgeBase

    with get_session_factory()() as s:
        for h in KnowledgeBase(s).search(query, k, kind=kind):
            typer.echo(
                f"{h.score:.3f}  {h.chunk.title} | {h.chunk.section[:70]}\n        {h.chunk.url}"
            )


@app.command("update-feeds")
def update_feeds_cmd() -> None:
    """Download the EPSS and CISA KEV feeds behind risk scores (the worker also does this daily)."""
    from core.risk import update_feeds

    meta = update_feeds()
    for name, detail in (("epss", meta.get("epss")), ("kev", meta.get("kev"))):
        err = meta["errors"].get(name)
        typer.echo(f"{name}: {'FAILED ' + err if err else detail}")
    if meta["errors"]:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
