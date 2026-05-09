"""
XSS Framework — Command-line interface.

Entry point for the ``xsf`` command.  Five top-level commands:

  xsf scan      — Scan a URL for reflected XSS
  xsf crawl     — Crawl a site and discover injectable endpoints
  xsf payloads  — Manage payload sets (list / show / export)
  xsf report    — Render a saved JSON scan as console, HTML, or JSON
  xsf config    — Manage configuration files (init / show / validate)
"""
from __future__ import annotations

import typer

from cli.commands.config_cmd import app as _config_app
from cli.commands.crawl import crawl
from cli.commands.payloads import app as _payloads_app
from cli.commands.report import report
from cli.commands.scan import scan

app = typer.Typer(
    name="xsf",
    help=(
        "[bold red]XSS Framework[/bold red] — Professional Reflected XSS Testing\n\n"
        "Run [bold]xsf COMMAND --help[/bold] for detailed help on any command."
    ),
    invoke_without_command=True,
    rich_markup_mode="rich",
    no_args_is_help=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=False,
)

# Sub-apps (grouped commands)
app.add_typer(
    _payloads_app,
    name="payloads",
    help="Payload management — list, inspect, and export payload sets.",
)
app.add_typer(
    _config_app,
    name="config",
    help="Configuration management — init, display, and validate config files.",
)

# Single commands
app.command(
    "scan",
    help="Scan a URL for Reflected XSS vulnerabilities.",
    context_settings={"help_option_names": ["-h", "--help"]},
)(scan)

app.command(
    "crawl",
    help="Crawl a site and discover endpoints, forms, and injectable parameters.",
    context_settings={"help_option_names": ["-h", "--help"]},
)(crawl)

app.command(
    "report",
    help="Generate a report from a previously saved JSON scan file.",
    context_settings={"help_option_names": ["-h", "--help"]},
)(report)


@app.callback(invoke_without_command=True)
def _callback(ctx: typer.Context) -> None:
    """XSS Framework — Professional Reflected XSS Testing."""
    if ctx.invoked_subcommand is None:
        from cli.console import BANNER, CONSOLE
        CONSOLE.print(BANNER)
        typer.echo(ctx.get_help())
        raise typer.Exit(0)


def main() -> None:
    """Package entry point registered as ``xsf`` in pyproject.toml."""
    app()


if __name__ == "__main__":
    main()
