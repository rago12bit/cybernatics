"""Bulwark CLI: `bulwark scan <path> --tools bandit --format json`."""

from __future__ import annotations

import json

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
    fmt: str = typer.Option("json", "--format", help="Output format: json."),
    distributed: bool = typer.Option(False, "--distributed", help="Run tools on Celery workers."),
) -> None:
    if fmt != "json":
        raise typer.BadParameter("only 'json' is supported so far", param_hint="--format")
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
    typer.echo(
        json.dumps(
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
    )


if __name__ == "__main__":
    app()
