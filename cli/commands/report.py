"""``xsf report`` — generate a report from a saved JSON scan file."""
from __future__ import annotations

import json as _json
from pathlib import Path
from typing import Optional

import typer

from cli.console import CONSOLE
from modules.base import ModuleResult


def report(
    input_file: Path = typer.Argument(..., help="JSON scan output file to render."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file (html/json formats)."),
    fmt: str = typer.Option("console", "--format", "-f", help="Output format: console | html | json | csv", show_default=True),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Include payload and evidence details."),
) -> None:
    """Generate a report from a previously saved JSON scan file.

    \b
    Examples:
      xsf report scan.json
      xsf report scan.json --format html -o report.html
      xsf report scan.json --verbose
    """
    if not input_file.exists():
        CONSOLE.print(f"[error]File not found: {input_file}[/error]")
        raise typer.Exit(1)

    try:
        data = _json.loads(input_file.read_text(encoding="utf-8"))
    except _json.JSONDecodeError as exc:
        CONSOLE.print(f"[error]Invalid JSON: {exc}[/error]")
        raise typer.Exit(1)

    result = ModuleResult(
        module_name=data.get("module", "unknown"),
        target=data.get("target", ""),
        findings=data.get("findings", []),
        errors=data.get("errors", []),
        metadata=data.get("metadata", {}),
    )

    fmt_lower = fmt.lower()

    if fmt_lower == "html":
        from reports.html_reporter import HTMLReporter
        dest = output or Path(input_file.stem + "_report.html")
        HTMLReporter(str(dest)).report(result)
        CONSOLE.print(f"\n[success]HTML report saved → {dest}[/success]")

    elif fmt_lower == "json":
        from reports.json_reporter import JSONReporter
        JSONReporter(str(output) if output else None).report(result)

    elif fmt_lower == "csv":
        from reports.csv_reporter import CSVReporter
        dest = output or Path(input_file.stem + "_report.csv")
        CSVReporter(str(dest)).report(result)
        CONSOLE.print(f"\n[success]CSV report saved → {dest}[/success]")

    else:
        from reports.console import ConsoleReporter
        ConsoleReporter(verbose=verbose).report(result)
