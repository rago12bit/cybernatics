"""Bulwark CLI: `bulwark scan <path> --tools bandit --format json`."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from core.scan import ADAPTERS, scan

app = typer.Typer(help="Bulwark: unified security scanning.", no_args_is_help=True)


@app.callback()
def _root() -> None:
    """Bulwark: unified security scanning."""


@app.command("scan")
def scan_cmd(
    path: Path = typer.Argument(..., exists=True, file_okay=False, resolve_path=True),
    tools: str = typer.Option(",".join(ADAPTERS), help="Comma-separated tool names."),
    fmt: str = typer.Option("json", "--format", help="Output format: json."),
) -> None:
    if fmt != "json":
        raise typer.BadParameter("only 'json' is supported so far", param_hint="--format")
    try:
        result = scan(path, [t.strip() for t in tools.split(",") if t.strip()])
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--tools") from exc
    typer.echo(
        json.dumps(
            {
                "tool_status": result.tool_status,
                "findings": [f.to_dict() for f in result.findings],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    app()
